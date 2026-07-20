//! LP2LN release manifest types, signing, and verification (P5).
//!
//! Package source ≠ author: chunks may arrive from any node;
//! the manifest is trusted only when it carries a valid release-key signature.

pub mod key;
pub mod manifest;

pub use key::{ReleaseError, ReleaseSigningKey, ReleaseVerifyKey};
pub use manifest::{ReleaseManifest, SignedManifest, UPDATE_PROTOCOL_ID};
