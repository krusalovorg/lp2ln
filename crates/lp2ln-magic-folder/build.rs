//! Embed `assets/lp2ln.ico` as the Windows PE application icon.
//!
//! Only runs when targeting Windows. Uses `winresource` (rc.exe / windres).

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let icon = std::path::Path::new(&manifest_dir).join("../../assets/lp2ln.ico");
    println!("cargo:rerun-if-changed={}", icon.display());

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }
    if !icon.is_file() {
        println!("cargo:warning=app icon missing at {}", icon.display());
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon(icon.to_str().expect("icon path utf-8"));
    if let Err(e) = res.compile() {
        // Don't hard-fail the whole crate if the host lacks a resource compiler.
        println!("cargo:warning=failed to embed Windows app icon: {e}");
    }
}
