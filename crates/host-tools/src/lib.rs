//! Host-side release engineering helpers: manifest hashing and signature verification stubs.
//!
//! **Security role:** supports **reproducible builds** and signed update bundles described in the
//! Baochip README (detached signatures, checksum manifests, offline verification).

use sha2::Digest;
use sha2::Sha256;

/// Returned by [`verify_update_bundle_stub`] until signature verification is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyUpdateBundleStubError;

impl core::fmt::Display for VerifyUpdateBundleStubError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("update bundle verification is not implemented")
    }
}

impl std::error::Error for VerifyUpdateBundleStubError {}

/// Compute SHA-256 digest for a firmware image slice (host tool path).
pub fn sha256_manifest_chunk(data: &[u8]) -> [u8; 32] {
    let h = Sha256::digest(data);
    h.into()
}

/// Stub: verify detached signature on an update bundle (minisign / GPG / Sigstore — TBD).
pub fn verify_update_bundle_stub(
    _image: &[u8],
    _sig: &[u8],
) -> Result<(), VerifyUpdateBundleStubError> {
    Err(VerifyUpdateBundleStubError)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod property_tests;
