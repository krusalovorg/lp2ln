use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let native_dir = PathBuf::from(&manifest_dir).join("native");

    #[cfg(target_os = "windows")]
    {
        let packet_lib = native_dir.join("Packet.lib");
        if !packet_lib.exists() {
            panic!("Packet.lib not found at: {}", packet_lib.display());
        }
        println!("cargo:rustc-link-search=native={}", native_dir.display());
        println!("cargo:rustc-link-lib=static=Packet");
        println!("cargo:rerun-if-changed={}", packet_lib.display());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        println!("cargo:rustc-link-lib=dylib=pcap");
    }
}
