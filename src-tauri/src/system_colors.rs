use crate::models::SystemColors;

#[cfg(target_os = "macos")]
type Rgb = (u8, u8, u8);

#[cfg(target_os = "macos")]
const DEFAULT_ACCENT: Rgb = (0, 122, 255);

#[cfg(target_os = "macos")]
pub fn get_system_colors() -> SystemColors {
    let accent_rgb = read_global_default("AppleAccentColor")
        .as_deref()
        .and_then(parse_accent_index)
        .and_then(accent_rgb_from_index)
        .unwrap_or(DEFAULT_ACCENT);

    let highlight_rgb = read_global_default("AppleHighlightColor")
        .as_deref()
        .and_then(parse_highlight_rgb)
        .unwrap_or_else(|| derive_highlight_from_accent(accent_rgb));

    SystemColors {
        accent_color: Some(rgb_to_hex(accent_rgb)),
        accent_text_color: Some(contrast_text_color(accent_rgb)),
        highlight_color: Some(rgb_to_hex(highlight_rgb)),
        highlight_text_color: Some(contrast_text_color(highlight_rgb)),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn get_system_colors() -> SystemColors {
    SystemColors {
        accent_color: None,
        accent_text_color: None,
        highlight_color: None,
        highlight_text_color: None,
    }
}

#[cfg(target_os = "macos")]
fn read_global_default(key: &str) -> Option<String> {
    let output = std::process::Command::new("defaults")
        .args(["read", "-g", key])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn parse_accent_index(raw: &str) -> Option<i32> {
    raw.trim().parse::<i32>().ok()
}

#[cfg(target_os = "macos")]
fn accent_rgb_from_index(index: i32) -> Option<Rgb> {
    match index {
        -1 => Some((138, 138, 143)),
        0 => Some((255, 59, 48)),
        1 => Some((255, 149, 0)),
        2 => Some((255, 204, 0)),
        3 => Some((52, 199, 89)),
        4 => Some((0, 122, 255)),
        5 => Some((175, 82, 222)),
        6 => Some((255, 45, 85)),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn parse_highlight_rgb(raw: &str) -> Option<Rgb> {
    let channels = raw
        .split_whitespace()
        .filter_map(|token| token.parse::<f32>().ok())
        .take(3)
        .collect::<Vec<_>>();

    if channels.len() != 3 {
        return None;
    }

    Some((
        float_channel_to_u8(channels[0]),
        float_channel_to_u8(channels[1]),
        float_channel_to_u8(channels[2]),
    ))
}

#[cfg(target_os = "macos")]
fn float_channel_to_u8(value: f32) -> u8 {
    let scaled = if value <= 1.0 { value * 255.0 } else { value };
    scaled.clamp(0.0, 255.0).round() as u8
}

#[cfg(target_os = "macos")]
fn derive_highlight_from_accent(accent: Rgb) -> Rgb {
    blend_rgb(accent, (255, 255, 255), 0.62)
}

#[cfg(target_os = "macos")]
fn blend_rgb(base: Rgb, overlay: Rgb, amount: f32) -> Rgb {
    let clamped_amount = amount.clamp(0.0, 1.0);
    let inverse_amount = 1.0 - clamped_amount;

    (
        ((base.0 as f32 * inverse_amount) + (overlay.0 as f32 * clamped_amount)).round() as u8,
        ((base.1 as f32 * inverse_amount) + (overlay.1 as f32 * clamped_amount)).round() as u8,
        ((base.2 as f32 * inverse_amount) + (overlay.2 as f32 * clamped_amount)).round() as u8,
    )
}

#[cfg(target_os = "macos")]
fn rgb_to_hex((r, g, b): Rgb) -> String {
    format!("#{r:02X}{g:02X}{b:02X}")
}

#[cfg(target_os = "macos")]
fn contrast_text_color(rgb: Rgb) -> String {
    if relative_luminance(rgb) > 0.53 {
        "#000000".to_string()
    } else {
        "#FFFFFF".to_string()
    }
}

#[cfg(target_os = "macos")]
fn relative_luminance((r, g, b): Rgb) -> f32 {
    0.2126 * srgb_to_linear(r) + 0.7152 * srgb_to_linear(g) + 0.0722 * srgb_to_linear(b)
}

#[cfg(target_os = "macos")]
fn srgb_to_linear(channel: u8) -> f32 {
    let value = channel as f32 / 255.0;
    if value <= 0.04045 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}
