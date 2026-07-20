//! Filesystem layout operations: staging promotion and binary path resolution.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub struct Layout {
    pub base: PathBuf,
}

impl Layout {
    pub fn new(base: &Path) -> Self {
        Self { base: base.to_owned() }
    }

    pub fn staging_dir(&self, build_id: &str) -> PathBuf {
        self.base.join("staging").join(build_id)
    }

    pub fn versions_dir(&self, build_id: &str) -> PathBuf {
        self.base.join("versions").join(build_id)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.base.join("state")
    }

    pub fn binary_name() -> &'static str {
        if cfg!(windows) { "lp2lnd.exe" } else { "lp2lnd" }
    }

    pub fn binary_in(&self, build_id: &str) -> PathBuf {
        self.versions_dir(build_id).join(Self::binary_name())
    }

    /// Atomically promote `staging/<build_id>` → `versions/<build_id>`.
    ///
    /// Both directories must be on the same filesystem (same `base`).
    /// If `versions/<build_id>` already exists it is left in place and
    /// the staging dir is removed — idempotent after a crash mid-commit.
    pub fn promote_staging(&self, build_id: &str) -> Result<PathBuf> {
        let src = self.staging_dir(build_id);
        let dst = self.versions_dir(build_id);

        if dst.exists() {
            // Already promoted (crash recovery path).
            std::fs::remove_dir_all(&src).ok();
            return Ok(self.binary_in(build_id));
        }

        std::fs::create_dir_all(dst.parent().unwrap())
            .context("creating versions dir")?;

        // ponytail: rename is atomic on same filesystem; crash between rename
        // and state write leaves staging gone and versions present → handled above.
        std::fs::rename(&src, &dst)
            .with_context(|| format!("rename {} -> {}", src.display(), dst.display()))?;

        let bin = self.binary_in(build_id);
        if !bin.exists() {
            anyhow::bail!("binary missing after promotion: {}", bin.display());
        }

        // Ensure executable bit on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bin)?.permissions();
            perms.set_mode(perms.mode() | 0o111);
            std::fs::set_permissions(&bin, perms)?;
        }

        Ok(bin)
    }
}
