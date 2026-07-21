//! Apply a custom file-manager icon to the magic folder root.
//!
//! - Windows: embedded `lp2ln-folder.ico` + `desktop.ini` + ReadOnly dir attr.
//! - Linux: embedded PNG + `.directory` (Freedesktop) + best-effort `gio` metadata.
//! Idempotent — safe to call every start.

use std::path::Path;

/// Icon filename written into the magic folder (also listed in `is_ignored`).
#[cfg(windows)]
pub const ICON_FILE_NAME: &str = "lp2ln-magic-folder.ico";
#[cfg(not(windows))]
pub const ICON_FILE_NAME: &str = "lp2ln-magic-folder.png";

pub const DESKTOP_INI_NAME: &str = "desktop.ini";
pub const DIRECTORY_FILE_NAME: &str = ".directory";

/// Ensure the magic folder shows the LP2LN icon in the file manager.
/// Best-effort: failures are logged to stderr and never abort the daemon.
pub fn ensure_folder_icon(root: &Path) {
    #[cfg(windows)]
    if let Err(e) = windows::apply(root) {
        eprintln!("warning: cannot set folder icon on {}: {e}", root.display());
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = linux::apply(root) {
        eprintln!("warning: cannot set folder icon on {}: {e}", root.display());
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    let _ = root;
}

#[cfg(windows)]
mod windows {
    use super::{DESKTOP_INI_NAME, ICON_FILE_NAME};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const ICON_BYTES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/lp2ln-folder.ico"));

    const DESKTOP_INI: &str = "\
[.ShellClassInfo]\r\n\
ConfirmFileOp=0\r\n\
IconResource=lp2ln-magic-folder.ico,0\r\n\
InfoTip=LP2LN Magic Folder\r\n\
";

    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

    const SHCNE_ATTRIBUTES: i32 = 0x0000_0800;
    const SHCNE_UPDATEITEM: i32 = 0x0000_2000;
    const SHCNF_PATHW: u32 = 0x0005;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
        fn SetFileAttributesW(lp_file_name: *const u16, dw_file_attributes: u32) -> i32;
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

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn get_attrs(path: &Path) -> Option<u32> {
        let w = to_wide(path);
        let a = unsafe { GetFileAttributesW(w.as_ptr()) };
        if a == INVALID_FILE_ATTRIBUTES {
            None
        } else {
            Some(a)
        }
    }

    fn set_attrs(path: &Path, attrs: u32) -> std::io::Result<()> {
        let w = to_wide(path);
        let ok = unsafe { SetFileAttributesW(w.as_ptr(), attrs) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn write_bytes(path: &Path, data: &[u8], final_attrs: u32) -> std::io::Result<()> {
        if let Some(a) = get_attrs(path) {
            let clear = a & !(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            let _ = set_attrs(path, if clear == 0 { FILE_ATTRIBUTE_NORMAL } else { clear });
        }
        std::fs::write(path, data)?;
        set_attrs(path, final_attrs)
    }

    fn notify_shell(path: &Path) {
        let w = to_wide(path);
        unsafe {
            SHChangeNotify(
                SHCNE_ATTRIBUTES,
                SHCNF_PATHW,
                w.as_ptr() as *const std::ffi::c_void,
                std::ptr::null(),
            );
            SHChangeNotify(
                SHCNE_UPDATEITEM,
                SHCNF_PATHW,
                w.as_ptr() as *const std::ffi::c_void,
                std::ptr::null(),
            );
        }
    }

    pub fn apply(root: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(root)?;

        if let Some(a) = get_attrs(root) {
            let clear = a & !FILE_ATTRIBUTE_READONLY;
            let _ = set_attrs(root, if clear == 0 { FILE_ATTRIBUTE_NORMAL } else { clear });
        }

        let icon_path = root.join(ICON_FILE_NAME);
        let need_icon = match std::fs::read(&icon_path) {
            Ok(existing) => existing != ICON_BYTES,
            Err(_) => true,
        };
        if need_icon {
            write_bytes(
                &icon_path,
                ICON_BYTES,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            )?;
        } else {
            let _ = set_attrs(
                &icon_path,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            );
        }

        let ini_path = root.join(DESKTOP_INI_NAME);
        let need_ini = match std::fs::read_to_string(&ini_path) {
            Ok(existing) => existing != DESKTOP_INI,
            Err(_) => true,
        };
        if need_ini {
            write_bytes(
                &ini_path,
                DESKTOP_INI.as_bytes(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            )?;
        } else {
            let _ = set_attrs(
                &ini_path,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            );
        }

        let folder_attrs = (get_attrs(root).unwrap_or(0) | FILE_ATTRIBUTE_READONLY)
            & !FILE_ATTRIBUTE_NORMAL;
        set_attrs(root, folder_attrs)?;
        notify_shell(root);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{DIRECTORY_FILE_NAME, ICON_FILE_NAME};
    use std::path::Path;
    use std::process::Command;

    const ICON_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../assets/lp2ln-folder-256.png"
    ));

    pub fn apply(root: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(root)?;

        let icon_path = root.join(ICON_FILE_NAME);
        let need_icon = match std::fs::read(&icon_path) {
            Ok(existing) => existing != ICON_BYTES,
            Err(_) => true,
        };
        if need_icon {
            std::fs::write(&icon_path, ICON_BYTES)?;
        }

        // Prefer absolute path in Icon= so relocating the folder still works
        // until the next daemon start rewrites .directory.
        let icon_abs = std::fs::canonicalize(&icon_path).unwrap_or(icon_path);
        let directory = format!(
            "\
[Desktop Entry]\n\
Type=Directory\n\
Icon={}\n\
Name=LP2LN Magic Folder\n\
Comment=LP2LN encrypted sync folder\n\
",
            icon_abs.display()
        );

        let dir_file = root.join(DIRECTORY_FILE_NAME);
        let need_dir = match std::fs::read_to_string(&dir_file) {
            Ok(existing) => existing != directory,
            Err(_) => true,
        };
        if need_dir {
            std::fs::write(&dir_file, directory)?;
        }

        // GNOME/Nautilus often ignores .directory; set gvfs metadata when gio exists.
        let uri = format!("file://{}", root.display());
        let icon_uri = format!("file://{}", icon_abs.display());
        let _ = Command::new("gio")
            .args(["set", &uri, "metadata::custom-icon", &icon_uri])
            .status();

        Ok(())
    }
}
