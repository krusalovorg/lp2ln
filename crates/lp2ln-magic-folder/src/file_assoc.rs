//! Register `.lp2ln` file type icon (and open→hydrate) for the current user.
//!
//! - Windows: extract embedded `lp2ln.ico` → LocalAppData + HKCU Classes (no admin).
//! - Linux: XDG MIME + hicolor icons + `.desktop` (user-local, no root).
//! Idempotent — safe to call every start.

use std::path::Path;

/// Ensure the file manager shows the LP2LN icon for `*.lp2ln` and opens them via this exe.
/// `options_path` is the magic-folder JSON passed as `-o` on open/hydrate.
pub fn ensure_lp2ln_association(options_path: &Path) {
    #[cfg(windows)]
    if let Err(e) = windows::apply(options_path) {
        eprintln!("warning: cannot register .lp2ln file association: {e}");
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = linux::apply(options_path) {
        eprintln!("warning: cannot register .lp2ln file association: {e}");
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    let _ = options_path;
}

#[cfg(windows)]
mod windows {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;

    const ICON_BYTES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln.ico"));

    const PROGID: &str = "lp2ln.file";
    const EXT: &str = ".lp2ln";
    const FRIENDLY: &str = "LP2LN Placeholder";

    const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as isize;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    const KEY_WRITE: u32 = KEY_SET_VALUE | KEY_CREATE_SUB_KEY;
    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const REG_SZ: u32 = 1;
    const ERROR_SUCCESS: u32 = 0;

    const SHCNE_ASSOCCHANGED: i32 = 0x0800_0000;
    const SHCNF_IDLIST: u32 = 0x0000;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegCreateKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            reserved: u32,
            lp_class: *const u16,
            dw_options: u32,
            sam_desired: u32,
            lp_security_attributes: *const std::ffi::c_void,
            phk_result: *mut isize,
            lpdw_disposition: *mut u32,
        ) -> u32;
        fn RegSetValueExW(
            h_key: isize,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> u32;
        fn RegCloseKey(h_key: isize) -> u32;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHChangeNotify(
            w_event_id: i32,
            u_flags: u32,
            dw_item1: *const std::ffi::c_void,
            dw_item2: *const std::ffi::c_void,
        );
    }

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn set_sz(root_path: &str, value_name: Option<&str>, data: &str) -> anyhow::Result<()> {
        let sub = wide(root_path);
        let mut hkey: isize = 0;
        let mut disp: u32 = 0;
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                ptr::null(),
                &mut hkey,
                &mut disp,
            )
        };
        if rc != ERROR_SUCCESS {
            anyhow::bail!("RegCreateKeyExW({root_path}) failed: {rc}");
        }

        let name_wide = value_name.map(wide);
        let name_ptr = name_wide
            .as_ref()
            .map(|v| v.as_ptr())
            .unwrap_or(ptr::null());

        let data_wide = wide(data);
        let bytes = unsafe {
            std::slice::from_raw_parts(data_wide.as_ptr() as *const u8, data_wide.len() * 2)
        };

        let rc = unsafe {
            RegSetValueExW(
                hkey,
                name_ptr,
                0,
                REG_SZ,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        unsafe { RegCloseKey(hkey) };
        if rc != ERROR_SUCCESS {
            anyhow::bail!("RegSetValueExW({root_path}) failed: {rc}");
        }
        Ok(())
    }

    fn icon_install_path() -> anyhow::Result<PathBuf> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA not set"))?;
        let dir = base.join("lp2ln-magic-folder");
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join("lp2ln-file.ico"))
    }

    pub fn apply(options_path: &Path) -> anyhow::Result<()> {
        let exe = std::env::current_exe()?;
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        let opts =
            std::fs::canonicalize(options_path).unwrap_or_else(|_| options_path.to_path_buf());

        let icon = icon_install_path()?;
        let need_icon = match std::fs::read(&icon) {
            Ok(existing) => existing != ICON_BYTES,
            Err(_) => true,
        };
        if need_icon {
            std::fs::write(&icon, ICON_BYTES)?;
        }

        let exe_s = strip_unc(&exe);
        let opts_s = strip_unc(&opts);
        let icon_s = strip_unc(&icon);

        set_sz(&format!(r"Software\Classes\{EXT}"), None, PROGID)?;
        set_sz(
            &format!(r"Software\Classes\{EXT}"),
            Some("Content Type"),
            "application/x-lp2ln",
        )?;
        set_sz(&format!(r"Software\Classes\{PROGID}"), None, FRIENDLY)?;
        set_sz(
            &format!(r"Software\Classes\{PROGID}\DefaultIcon"),
            None,
            &format!("{icon_s},0"),
        )?;
        set_sz(
            &format!(r"Software\Classes\{PROGID}\shell\open\command"),
            None,
            &format!("\"{exe_s}\" -o \"{opts_s}\" \"%1\""),
        )?;

        unsafe {
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, ptr::null(), ptr::null());
        }
        Ok(())
    }

    fn strip_unc(path: &Path) -> String {
        let s = path.to_string_lossy();
        s.strip_prefix(r"\\?\")
            .unwrap_or(&s)
            .to_string()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const MIME_TYPE: &str = "application/x-lp2ln";
    const DESKTOP_ID: &str = "lp2ln-magic-folder.desktop";

    const ICON_16: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln-16.png"));
    const ICON_32: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln-32.png"));
    const ICON_48: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln-48.png"));
    const ICON_128: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln-128.png"));
    const ICON_256: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln-256.png"));

    const MIME_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-lp2ln">
    <comment>LP2LN Placeholder</comment>
    <glob pattern="*.lp2ln"/>
    <icon name="application-x-lp2ln"/>
  </mime-type>
</mime-info>
"#;

    fn xdg_data_home() -> PathBuf {
        if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(p);
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(".local/share")
    }

    fn write_if_changed(path: &Path, data: &[u8]) -> anyhow::Result<bool> {
        if let Ok(existing) = std::fs::read(path) {
            if existing == data {
                return Ok(false);
            }
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)?;
        Ok(true)
    }

    pub fn apply(options_path: &Path) -> anyhow::Result<()> {
        let exe = std::env::current_exe()?;
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        let opts =
            std::fs::canonicalize(options_path).unwrap_or_else(|_| options_path.to_path_buf());

        let data = xdg_data_home();

        // MIME package
        write_if_changed(
            &data.join("mime/packages/lp2ln-file.xml"),
            MIME_XML.as_bytes(),
        )?;

        // hicolor mimetype icons
        for (size, bytes) in [
            (16, ICON_16),
            (32, ICON_32),
            (48, ICON_48),
            (128, ICON_128),
            (256, ICON_256),
        ] {
            let path = data.join(format!(
                "icons/hicolor/{size}x{size}/mimetypes/application-x-lp2ln.png"
            ));
            write_if_changed(&path, bytes)?;
            // Also as app icon for the .desktop Icon= field
            let app = data.join(format!("icons/hicolor/{size}x{size}/apps/lp2ln-magic-folder.png"));
            write_if_changed(&app, bytes)?;
        }

        let desktop = format!(
            "\
[Desktop Entry]\n\
Type=Application\n\
Name=LP2LN Magic Folder\n\
Comment=Hydrate LP2LN placeholders\n\
Exec=\"{}\" -o \"{}\" %f\n\
Icon=lp2ln-magic-folder\n\
MimeType={MIME_TYPE};\n\
NoDisplay=true\n\
Terminal=false\n\
Categories=Utility;\n\
",
            exe.display(),
            opts.display()
        );
        write_if_changed(&data.join(format!("applications/{DESKTOP_ID}")), desktop.as_bytes())?;

        // Refresh caches when tools exist (best-effort).
        let mime_dir = data.join("mime");
        let _ = Command::new("update-mime-database")
            .arg(&mime_dir)
            .status();
        let apps = data.join("applications");
        let _ = Command::new("update-desktop-database")
            .arg(&apps)
            .status();
        let icons = data.join("icons/hicolor");
        let _ = Command::new("gtk-update-icon-cache")
            .args(["-f", "-t"])
            .arg(&icons)
            .status();

        // Prefer our handler for this MIME (user default).
        let _ = Command::new("xdg-mime")
            .args(["default", DESKTOP_ID, MIME_TYPE])
            .status();

        Ok(())
    }
}
