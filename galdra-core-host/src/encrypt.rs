//! Multi-recipient OpenPGP encryption and decryption using Sequoia.
//!
//! Private key material is never required on the host for encryption. Decryption accepts a
//! callback that performs session-key decapsulation (for example on a hardware token).

use std::io::Write;

use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::parse::stream::{
    DecryptorBuilder, DecryptionHelper, MessageLayer, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message, Recipient, Signer};
use sequoia_openpgp::types::{DataFormat, SymmetricAlgorithm};
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::KeyID;

use crate::GaldraError;

fn collect_recipients<'a>(
    policy: &'a dyn Policy,
    recipient_certs: &'a [Cert],
    hidden_recipients: bool,
    strict: bool,
) -> Result<Vec<Recipient<'a>>, GaldraError> {
    let mut recipients: Vec<Recipient<'a>> = Vec::new();
    for cert in recipient_certs {
        let mut found = false;
        for ka in cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            found = true;
            let r: Recipient<'a> = ka.into();
            let r = if hidden_recipients {
                r.set_keyid(KeyID::wildcard())
            } else {
                r
            };
            recipients.push(r);
        }
        if !found && strict {
            return Err(GaldraError::NoEncryptionSubkey(
                cert.fingerprint().to_string(),
            ));
        }
    }
    if recipients.is_empty() {
        return Err(GaldraError::OpenPgp(
            "no usable encryption subkeys for any recipient".to_string(),
        ));
    }
    Ok(recipients)
}

fn write_literal_payload(
    message: Message<'_>,
    plaintext: &[u8],
    literal_filename: Option<&str>,
) -> Result<(), GaldraError> {
    let mut lit = LiteralWriter::new(message).format(DataFormat::Binary);
    if let Some(name) = literal_filename {
        lit = lit
            .filename(name)
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    }
    let mut lit = lit.build().map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    lit.write_all(plaintext)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    lit.finalize()
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    Ok(())
}

/// Encrypt plaintext to one or more OpenPGP certificates.
///
/// When `hidden_recipients` is true, each PKESK uses [`KeyID::wildcard`] so recipients cannot read
/// the full recipient list from the ciphertext.
///
/// With `strict`, any certificate that has no usable encryption subkey under `policy` causes an
/// error. Otherwise such certificates are skipped; if no recipients remain, [`GaldraError::OpenPgp`]
/// is returned.
pub fn encrypt_openpgp(
    policy: &dyn Policy,
    plaintext: &[u8],
    literal_filename: Option<&str>,
    recipient_certs: &[Cert],
    hidden_recipients: bool,
    strict: bool,
) -> Result<Vec<u8>, GaldraError> {
    let recipients = collect_recipients(policy, recipient_certs, hidden_recipients, strict)?;
    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor2::for_recipients(message, recipients)
            .build()
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
        write_literal_payload(message, plaintext, literal_filename)?;
    }
    Ok(sink)
}

/// Encrypt and sign (sign-then-encrypt) using a [`sequoia_openpgp::crypto::Signer`], typically a
/// [`sequoia_openpgp::crypto::KeyPair`] or a hardware-backed implementation.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_openpgp_signed<S: sequoia_openpgp::crypto::Signer + Send + Sync>(
    policy: &dyn Policy,
    plaintext: &[u8],
    literal_filename: Option<&str>,
    recipient_certs: &[Cert],
    hidden_recipients: bool,
    strict: bool,
    signer: S,
    intended_recipient: &Cert,
) -> Result<Vec<u8>, GaldraError> {
    let recipients = collect_recipients(policy, recipient_certs, hidden_recipients, strict)?;
    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor2::for_recipients(message, recipients)
            .build()
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
        let message = Signer::new(message, signer)
            .add_intended_recipient(intended_recipient)
            .build()
            .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
        write_literal_payload(message, plaintext, literal_filename)?;
    }
    Ok(sink)
}

/// Try to unwrap the session key using unencrypted secret subkeys on `cert` (tests and local keys).
pub fn try_decrypt_session_key_from_cert(
    policy: &dyn Policy,
    recipient_secret: &Cert,
    pkesk: &PKESK,
    sym_algo: Option<SymmetricAlgorithm>,
) -> Option<(SymmetricAlgorithm, SessionKey)> {
    for ka in recipient_secret
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .for_transport_encryption()
    {
        let mut kp = ka.key().clone().into_keypair().ok()?;
        if let Some(pair) = pkesk.decrypt(&mut kp, sym_algo) {
            return Some(pair);
        }
    }
    None
}

struct DecryptVerifyHelper<'a, F>
where
    F: FnMut(&PKESK, Option<SymmetricAlgorithm>) -> Option<(SymmetricAlgorithm, SessionKey)>,
{
    recipient: &'a Cert,
    try_decrypt: F,
    verification_certs: &'a [Cert],
}

impl<'a, F> VerificationHelper for DecryptVerifyHelper<'a, F>
where
    F: FnMut(&PKESK, Option<SymmetricAlgorithm>) -> Option<(SymmetricAlgorithm, SessionKey)>,
{
    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        if ids.is_empty() {
            return Ok(self.verification_certs.to_vec());
        }
        let mut out = Vec::new();
        for c in self.verification_certs {
            let matches = ids.iter().any(|id| {
                id.aliases(KeyHandle::from(c.fingerprint()))
                    || c.keys().any(|k| id.aliases(KeyHandle::from(k.keyid())))
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

impl<'a, F> DecryptionHelper for DecryptVerifyHelper<'a, F>
where
    F: FnMut(&PKESK, Option<SymmetricAlgorithm>) -> Option<(SymmetricAlgorithm, SessionKey)>,
{
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        if !skesks.is_empty() {
            return Err(anyhow::anyhow!(
                "password-encrypted messages are not supported"
            ));
        }
        for pkesk in pkesks {
            if let Some((algo, sk)) = (self.try_decrypt)(pkesk, sym_algo) {
                if decrypt(algo, &sk) {
                    return Ok(Some(self.recipient.fingerprint()));
                }
            }
        }
        Err(anyhow::anyhow!("could not decrypt OpenPGP session key"))
    }
}

/// Decrypt an OpenPGP message.
///
/// `try_decrypt_session_key` must unwrap the PKESK using the recipient's private key material (for
/// example by delegating to a token). `verification_certs` are used to verify embedded signatures.
pub fn decrypt_openpgp<F>(
    policy: &dyn Policy,
    ciphertext: &[u8],
    recipient_cert: &Cert,
    try_decrypt_session_key: F,
    verification_certs: &[Cert],
) -> Result<Vec<u8>, GaldraError>
where
    F: FnMut(&PKESK, Option<SymmetricAlgorithm>) -> Option<(SymmetricAlgorithm, SessionKey)>,
{
    let helper = DecryptVerifyHelper {
        recipient: recipient_cert,
        try_decrypt: try_decrypt_session_key,
        verification_certs,
    };
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?
        .with_policy(policy, None, helper)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    let mut plain = Vec::new();
    std::io::copy(&mut decryptor, &mut plain).map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::policy::StandardPolicy;

    #[test]
    fn roundtrip_two_recipients() {
        let p = StandardPolicy::new();
        let (alice, _) = CertBuilder::new()
            .add_userid("alice@example.org")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        let (bob, _) = CertBuilder::new()
            .add_userid("bob@example.org")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();

        let msg = b"field exercise payload";
        let ct = encrypt_openpgp(
            &p,
            msg,
            None,
            &[alice.clone(), bob.clone()],
            false,
            true,
        )
        .expect("encrypt");

        let plain = decrypt_openpgp(
            &p,
            &ct,
            &alice,
            |pkesk, sym| try_decrypt_session_key_from_cert(&p, &alice, pkesk, sym),
            &[],
        )
        .expect("decrypt alice");

        assert_eq!(plain, msg);

        let plain_b = decrypt_openpgp(
            &p,
            &ct,
            &bob,
            |pkesk, sym| try_decrypt_session_key_from_cert(&p, &bob, pkesk, sym),
            &[],
        )
        .expect("decrypt bob");
        assert_eq!(plain_b, msg);
    }

    #[test]
    fn hidden_recipients_roundtrip() {
        let p = StandardPolicy::new();
        let (alice, _) = CertBuilder::new()
            .add_userid("alice@example.org")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();

        let ct = encrypt_openpgp(&p, b"secret", None, &[alice.clone()], true, true).unwrap();

        let plain = decrypt_openpgp(
            &p,
            &ct,
            &alice,
            |pkesk, sym| try_decrypt_session_key_from_cert(&p, &alice, pkesk, sym),
            &[],
        )
        .unwrap();
        assert_eq!(plain, b"secret");
    }
}
