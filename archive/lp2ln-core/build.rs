use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from("native");
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=Packet");
    println!("cargo:rerun-if-changed=native/Packet.lib");
}
