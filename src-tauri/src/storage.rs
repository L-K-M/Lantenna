use crate::models::{FingerbankResult, ScanResult};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const FINGERBANK_CACHE_TTL_DAYS: i64 = 90;
const MAX_FINGERBANK_CACHE_ENTRIES: usize = 5000;
const MAX_OUI_VENDOR_CACHE_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct StoredData {
    latest_scan: Option<ScanResult>,
    // Files written by older versions also hold a `fingerprint_cache` of whole
    // fingerprints. Serde ignores it, and the next save drops it: reusing
    // whole fingerprints froze heuristics that should follow the latest scan.
    fingerbank_cache: HashMap<String, FingerbankResult>,
    oui_vendor_cache: HashMap<String, String>,
}

pub struct Storage {
    file_path: Option<PathBuf>,
    data: Mutex<StoredData>,
}

impl Storage {
    pub fn new() -> Result<Self> {
        let app_support = dirs::data_dir()
            .context("Failed to get platform data directory")?
            .join("Lantenna");

        fs::create_dir_all(&app_support)
            .context("Failed to create application support directory")?;

        let file_path = app_support.join("scan_results.json");
        let mut data = load_stored_data(&file_path);
        prune_stored_data(&mut data);

        Ok(Self {
            file_path: Some(file_path),
            data: Mutex::new(data),
        })
    }

    pub fn in_memory() -> Self {
        Self {
            file_path: None,
            data: Mutex::new(StoredData::default()),
        }
    }

    fn lock_data(&self) -> MutexGuard<'_, StoredData> {
        self.data.lock().unwrap_or_else(|poisoned| {
            log::warn!("Storage lock poisoned; continuing with inner value");
            poisoned.into_inner()
        })
    }

    fn save(&self) -> Result<()> {
        let Some(file_path) = &self.file_path else {
            return Ok(());
        };

        let mut data = self.lock_data();
        prune_stored_data(&mut data);
        let json = serde_json::to_string_pretty(&*data).context("Failed to serialize scan data")?;

        let temp_path = file_path.with_extension("json.tmp");
        fs::write(&temp_path, json).context("Failed to write temp scan file")?;
        fs::rename(&temp_path, file_path).context("Failed to rename temp scan file")?;

        Ok(())
    }

    pub fn get_latest_scan(&self) -> Result<Option<ScanResult>> {
        let data = self.lock_data();
        Ok(data.latest_scan.clone())
    }

    pub fn save_scan_result(&self, result: ScanResult) -> Result<()> {
        let mut data = self.lock_data();
        data.latest_scan = Some(result);
        drop(data);
        self.save()
    }

    /// Returns the cached Fingerbank answer for a MAC address, if any.
    pub fn get_cached_fingerbank(&self, mac: &str) -> Result<Option<FingerbankResult>> {
        let data = self.lock_data();
        Ok(data.fingerbank_cache.get(mac).cloned())
    }

    pub fn cache_fingerbank_results(&self, entries: Vec<(String, FingerbankResult)>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut data = self.lock_data();
        for (mac, result) in entries {
            data.fingerbank_cache.insert(mac, result);
        }
        prune_fingerbank_cache(&mut data.fingerbank_cache);
        drop(data);

        self.save()
    }

    pub fn get_cached_vendor(&self, oui: &str) -> Result<Option<String>> {
        let data = self.lock_data();
        Ok(data.oui_vendor_cache.get(oui).cloned())
    }

    pub fn cache_vendors(&self, entries: Vec<(String, String)>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut data = self.lock_data();
        for (oui, vendor) in entries {
            data.oui_vendor_cache.insert(oui, vendor);
        }
        prune_oui_vendor_cache(&mut data.oui_vendor_cache);
        drop(data);
        self.save()
    }
}

fn load_stored_data(file_path: &PathBuf) -> StoredData {
    if !file_path.exists() {
        return StoredData::default();
    }

    let contents = match fs::read_to_string(file_path) {
        Ok(contents) => contents,
        Err(error) => {
            log::warn!("Failed to read persisted scan data: {}", error);
            return StoredData::default();
        }
    };

    match serde_json::from_str(&contents) {
        Ok(data) => data,
        Err(error) => {
            log::warn!("Failed to parse persisted scan data: {}", error);

            if let Err(backup_error) = quarantine_corrupt_scan_file(file_path) {
                log::warn!("Failed to quarantine corrupt scan data: {}", backup_error);
            }

            StoredData::default()
        }
    }
}

fn quarantine_corrupt_scan_file(file_path: &PathBuf) -> Result<()> {
    let file_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("scan_results.json");
    let backup_name = format!("{}.corrupt-{}", file_name, Utc::now().timestamp());
    let backup_path = file_path.with_file_name(backup_name);

    match fs::rename(file_path, &backup_path) {
        Ok(_) => Ok(()),
        Err(rename_error) => {
            fs::copy(file_path, &backup_path).with_context(|| {
                format!(
                    "Failed to copy corrupt file after rename error: {}",
                    rename_error
                )
            })?;
            fs::remove_file(file_path).context("Failed to remove corrupt scan file")?;
            Ok(())
        }
    }
}

fn prune_stored_data(data: &mut StoredData) {
    prune_fingerbank_cache(&mut data.fingerbank_cache);
    prune_oui_vendor_cache(&mut data.oui_vendor_cache);
}

fn prune_fingerbank_cache(cache: &mut HashMap<String, FingerbankResult>) {
    let cutoff = Utc::now() - ChronoDuration::days(FINGERBANK_CACHE_TTL_DAYS);

    cache.retain(|_, result| {
        parse_fetched_at(result)
            .map(|timestamp| timestamp >= cutoff)
            .unwrap_or(true)
    });

    if cache.len() <= MAX_FINGERBANK_CACHE_ENTRIES {
        return;
    }

    let mut ranked_keys = cache
        .iter()
        .map(|(key, result)| {
            let rank = parse_fetched_at(result)
                .map(|timestamp| timestamp.timestamp())
                .unwrap_or(0);
            (key.clone(), rank)
        })
        .collect::<Vec<(String, i64)>>();

    ranked_keys.sort_by_key(|(_, rank)| std::cmp::Reverse(*rank));

    let keep = ranked_keys
        .into_iter()
        .take(MAX_FINGERBANK_CACHE_ENTRIES)
        .map(|(key, _)| key)
        .collect::<HashSet<String>>();

    cache.retain(|key, _| keep.contains(key));
}

fn parse_fetched_at(result: &FingerbankResult) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&result.fetched_at)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn prune_oui_vendor_cache(cache: &mut HashMap<String, String>) {
    if cache.len() <= MAX_OUI_VENDOR_CACHE_ENTRIES {
        return;
    }

    let overflow = cache.len().saturating_sub(MAX_OUI_VENDOR_CACHE_ENTRIES);
    let mut keys = cache.keys().cloned().collect::<Vec<String>>();
    keys.sort();

    for key in keys.into_iter().take(overflow) {
        cache.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerbank_result_at(timestamp: DateTime<Utc>) -> FingerbankResult {
        FingerbankResult {
            vendor: None,
            model: None,
            device_type: None,
            os_guess: None,
            confidence: None,
            fetched_at: timestamp.to_rfc3339(),
        }
    }

    #[test]
    fn fingerbank_prune_removes_old_entries() {
        let now = Utc::now();
        let stale = now - ChronoDuration::days(FINGERBANK_CACHE_TTL_DAYS + 2);

        let mut cache = HashMap::new();
        cache.insert("old".to_string(), fingerbank_result_at(stale));
        cache.insert("fresh".to_string(), fingerbank_result_at(now));

        prune_fingerbank_cache(&mut cache);

        assert!(!cache.contains_key("old"));
        assert!(cache.contains_key("fresh"));
    }

    #[test]
    fn stored_data_from_older_versions_still_loads() {
        let legacy = r#"{"latest_scan":null,"fingerprint_cache":{"mac:AA":{}},"oui_vendor_cache":{"AA:BB:CC":"Acme"}}"#;

        let data: StoredData = serde_json::from_str(legacy).expect("legacy file parses");

        assert!(data.fingerbank_cache.is_empty());
        assert_eq!(
            data.oui_vendor_cache.get("AA:BB:CC").map(String::as_str),
            Some("Acme")
        );
    }

    #[test]
    fn oui_cache_prune_enforces_max_entries() {
        let mut cache = HashMap::new();
        for index in 0..(MAX_OUI_VENDOR_CACHE_ENTRIES + 10) {
            cache.insert(format!("{:06X}", index), format!("vendor-{}", index));
        }

        prune_oui_vendor_cache(&mut cache);

        assert_eq!(cache.len(), MAX_OUI_VENDOR_CACHE_ENTRIES);
    }
}
