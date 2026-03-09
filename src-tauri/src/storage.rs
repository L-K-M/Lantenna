use crate::models::ScanResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredData {
    latest_scan: Option<ScanResult>,
}

pub struct Storage {
    file_path: PathBuf,
    data: Mutex<StoredData>,
}

impl Storage {
    pub fn new() -> Result<Self> {
        let app_support = dirs::home_dir()
            .context("Failed to get home directory")?
            .join("Library")
            .join("Application Support")
            .join("Lantenna");

        fs::create_dir_all(&app_support).context("Failed to create application support directory")?;

        let file_path = app_support.join("scan_results.json");

        let data = if file_path.exists() {
            let contents = fs::read_to_string(&file_path).context("Failed to read scan_results.json")?;
            serde_json::from_str(&contents).context("Failed to parse scan_results.json")?
        } else {
            StoredData::default()
        };

        Ok(Self {
            file_path,
            data: Mutex::new(data),
        })
    }

    fn save(&self) -> Result<()> {
        let data = self.data.lock().unwrap();
        let json = serde_json::to_string_pretty(&*data).context("Failed to serialize scan data")?;

        let temp_path = self.file_path.with_extension("json.tmp");
        fs::write(&temp_path, json).context("Failed to write temp scan file")?;
        fs::rename(&temp_path, &self.file_path).context("Failed to rename temp scan file")?;

        Ok(())
    }

    pub fn get_latest_scan(&self) -> Result<Option<ScanResult>> {
        let data = self.data.lock().unwrap();
        Ok(data.latest_scan.clone())
    }

    pub fn save_scan_result(&self, result: ScanResult) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.latest_scan = Some(result);
        drop(data);
        self.save()
    }
}
