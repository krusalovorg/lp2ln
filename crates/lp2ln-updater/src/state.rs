use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Persisted slot: both `active.json` and `last-known-good.json` use this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotState {
    pub build_id: String,
    /// Absolute path to the lp2lnd binary for this slot.
    pub binary_path: PathBuf,
    pub installed_at: u64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<()> {
    // ponytail: write-rename is atomic on same filesystem; crash mid-write
    // leaves a .tmp that is harmless on next startup.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)
        .with_context(|| format!("write tmp {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

pub struct StateStore {
    active_path: PathBuf,
    lkg_path: PathBuf,
}

impl StateStore {
    pub fn new(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        Ok(Self {
            active_path: state_dir.join("active.json"),
            lkg_path: state_dir.join("last-known-good.json"),
        })
    }

    pub fn load_active(&self) -> Result<Option<SlotState>> {
        self.load_slot(&self.active_path)
    }

    pub fn load_lkg(&self) -> Result<Option<SlotState>> {
        self.load_slot(&self.lkg_path)
    }

    fn load_slot(&self, path: &Path) -> Result<Option<SlotState>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let s = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn commit_active(&self, build_id: &str, binary_path: PathBuf) -> Result<()> {
        let slot = SlotState {
            build_id: build_id.to_string(),
            binary_path,
            installed_at: unix_now(),
        };
        write_atomic(&self.active_path, &serde_json::to_vec(&slot)?)
    }

    /// Copy active → LKG. Call after the child reports healthy for the first time.
    pub fn promote_active_to_lkg(&self) -> Result<()> {
        match self.load_active()? {
            Some(slot) => write_atomic(&self.lkg_path, &serde_json::to_vec(&slot)?),
            None => Ok(()),
        }
    }
}
