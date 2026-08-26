//! OpenPGP detached signing and verification.

use std::io::Write;

use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp::KeyHandle;

use crate::GaldraError;

struct VerifyCertsHelper<'a> {
    certs: &'a [Cert],
}

impl<'a> VerificationHelper for VerifyCertsHelper<'a> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        if ids.is_empty() {
            return Ok(self.certs.to_vec());
        }
        let mut out = Vec::new();
        for c in self.certs {
            let matches = ids.iter().any(|id| {
                id.aliases(KeyHandle::from(c.fingerprint()))
                    || c.keys().any(|k| id.aliases(KeyHandle::from(k.key().keyid())))
            });
            if matches {
                out.push(c.clone());
            }
        }
        Ok(out)
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    r.map_err(|e| anyhow::anyhow!("{e:?}"))?;
                }
            }
        }
        Ok(())
    }
}

/// Create a detached OpenPGP signature over `payload`.
pub fn sign_openpgp_detached<S: sequoia_openpgp::crypto::Signer + Send + Sync>(
    signer: S,
    payload: &[u8],
) -> Result<Vec<u8>, GaldraError> {
    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let mut signer = Signer::new(message, signer)
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?
            .detached()
            .build()
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
        signer
            .write_all(payload)
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
        signer
            .finalize()
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    }
    Ok(sink)
}

/// Verify a detached OpenPGP signature over `payload` using keys from `trusted_certs`.
pub fn verify_openpgp_detached(
    policy: &dyn Policy,
    detached_signature: &[u8],
    payload: &[u8],
    trusted_certs: &[Cert],
) -> Result<(), GaldraError> {
    let helper = VerifyCertsHelper {
        certs: trusted_certs,
    };
    let mut v = DetachedVerifierBuilder::from_bytes(detached_signature)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?
        .with_policy(policy, None, helper)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    v.verify_bytes(payload)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::policy::StandardPolicy;

    #[test]
    fn detached_roundtrip() {
        let p = StandardPolicy::new();
        let (cert, _) = CertBuilder::new()
            .add_userid("signer@example.org")
            .add_signing_subkey()
            .generate()
            .unwrap();
        let pair = cert
            .keys()
            .secret()
            .with_policy(&p, None)
            .for_signing()
            .nth(0)
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();

        let data = b"manifest checksum input";
        let sig = sign_openpgp_detached(pair, data).unwrap();
        verify_openpgp_detached(&p, &sig, data, &[cert.clone()]).unwrap();
    }
}
