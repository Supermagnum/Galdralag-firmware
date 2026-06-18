//! Local GTK-only preferences (default encrypt profile, etc.).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_PROFILE: &str = "standard";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GtkConfig {
    pub default_encrypt_profile: String,
}

impl Default for GtkConfig {
    fn default() -> Self {
        Self {
            default_encrypt_profile: DEFAULT_PROFILE.to_string(),
        }
    }
}

impl GtkConfig {
    pub fn config_path() -> Option<PathBuf> {
        let mut p = dirs::config_dir()?;
        p.push("galdra");
        p.push("gtk.toml");
        Some(p)
    }

    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let Some(path) = Self::config_path() else {
            return Err("no config directory".to_string());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let s = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, s).map_err(|e| e.to_string())
    }
}
