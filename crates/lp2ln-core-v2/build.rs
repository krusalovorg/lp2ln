use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let native_dir = PathBuf::from(&manifest_dir).join("native");

    // Build scripts run on the host, so `#[cfg(target_os)]` here describes the
    // host, not the build target. Cross-compiling (e.g. to Android) must read
    // CARGO_CFG_TARGET_OS instead, otherwise it links host-only capture libs.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "windows" => {
            let packet_lib = native_dir.join("Packet.lib");
            if !packet_lib.exists() {
                panic!("Packet.lib not found at: {}", packet_lib.display());
            }
            println!("cargo:rustc-link-search=native={}", native_dir.display());
            println!("cargo:rustc-link-lib=static=Packet");
            println!("cargo:rerun-if-changed={}", packet_lib.display());
        }
        "linux" | "macos" => println!("cargo:rustc-link-lib=dylib=pcap"),
        // android/ios have no packet-capture backend to link
        _ => {}
    }
}
