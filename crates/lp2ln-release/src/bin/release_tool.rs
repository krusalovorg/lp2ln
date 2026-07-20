//! lp2ln-release-tool — create and sign release packages.
//!
//! Usage:
//!   lp2ln-release-tool generate-key
//!   lp2ln-release-tool package --key <hex> --binary <path> --build-id <id>
//!                               --channel <ch> --os <os> --arch <arch>
//!                               --rollout <0-100> --output <dir>
//!                               [--min-protocol <n>] [--max-protocol <n>]
//!                               [--expires-in-days <n>]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use lp2ln_release::{
    ReleaseSigningKey, ReleaseVerifyKey,
    manifest::{ReleaseManifest, SignedManifest},
};
use sha2::{Digest, Sha256};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_file(path: &std::path::Path) -> Result<([u8; 32], u64)> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let hash: [u8; 32] = Sha256::digest(&data).into();
    Ok((hash, data.len() as u64))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("help");

    match sub {
        "generate-key" => {
            let key = ReleaseSigningKey::generate();
            println!("secret_key_hex = {}", key.to_hex());
            println!("verify_key_hex = {}", key.verify_key().to_hex());
        }
        "package" => {
            let get = |flag: &str| -> Result<String> {
                args.windows(2)
                    .find(|w| w[0] == flag)
                    .map(|w| w[1].clone())
                    .with_context(|| format!("missing {flag}"))
            };
            let get_opt = |flag: &str| -> Option<String> {
                args.windows(2)
                    .find(|w| w[0] == flag)
                    .map(|w| w[1].clone())
            };

            let key_hex = get("--key")?;
            let binary_path = PathBuf::from(get("--binary")?);
            let build_id = get("--build-id")?;
            let channel = get("--channel")?;
            let target_os = get("--os")?;
            let target_arch = get("--arch")?;
            let rollout: u8 = get("--rollout")?.parse().context("--rollout must be 0-100")?;
            let out_dir = PathBuf::from(get("--output")?);

            let min_proto: u16 = get_opt("--min-protocol")
                .map(|s| s.parse().unwrap_or(1))
                .unwrap_or(1);
            let max_proto: u16 = get_opt("--max-protocol")
                .map(|s| s.parse().unwrap_or(1))
                .unwrap_or(1);
            let expires_days: u64 = get_opt("--expires-in-days")
                .map(|s| s.parse().unwrap_or(30))
                .unwrap_or(30);

            if rollout > 100 {
                bail!("--rollout must be 0-100");
            }

            let signing_key = ReleaseSigningKey::from_hex(&key_hex)
                .context("invalid --key")?;
            let verify_key_hex = signing_key.verify_key().to_hex();

            let (package_hash, package_size) = hash_file(&binary_path)?;
            let now = unix_now();

            let manifest = ReleaseManifest {
                format_version: 1,
                channel,
                build_id: build_id.clone(),
                version: build_id.clone(),
                target_os,
                target_arch,
                package_hash,
                package_size,
                min_protocol: min_proto,
                max_protocol: max_proto,
                required_features: vec![],
                rollout_percent: rollout,
                max_concurrent: 16,
                created_at: now,
                expires_at: now + expires_days * 86400,
                release_key_id: verify_key_hex,
            };

            let signed = SignedManifest::sign(manifest, &signing_key)
                .context("signing manifest")?;

            fs::create_dir_all(&out_dir)
                .with_context(|| format!("creating {}", out_dir.display()))?;

            // Verify we can round-trip before writing anything.
            let verify_key = ReleaseVerifyKey::from_hex(&signing_key.verify_key().to_hex())?;
            signed.verify(&verify_key).context("self-verify failed")?;

            let manifest_bytes = signed.encode().context("encoding manifest")?;
            let manifest_path = out_dir.join(format!("{build_id}.manifest"));
            fs::write(&manifest_path, &manifest_bytes)
                .with_context(|| format!("writing {}", manifest_path.display()))?;

            let binary_name = binary_path.file_name().unwrap_or_default();
            let out_binary = out_dir.join(binary_name);
            fs::copy(&binary_path, &out_binary)
                .with_context(|| format!("copying binary to {}", out_binary.display()))?;

            println!("Package written to {}", out_dir.display());
            println!("  manifest : {}", manifest_path.display());
            println!("  binary   : {}", out_binary.display());
            println!("  hash     : {}", hex::encode(signed.manifest.package_hash));
            println!("  size     : {} bytes", signed.manifest.package_size);
        }
        _ => {
            eprintln!(
                "Usage:\n  lp2ln-release-tool generate-key\n  lp2ln-release-tool package --key <hex> --binary <path> --build-id <id> --channel <ch> --os <os> --arch <arch> --rollout <0-100> --output <dir>"
            );
        }
    }

    Ok(())
}
