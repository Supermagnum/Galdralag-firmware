//! Known-answer tests for **workspace cryptographic dependencies** (no custom primitives).
//!
//! **TODO (developer):** When firmware calls these crates, prefer Baochip-1x **PKE / ComboHash /
//! AES** where policy mandates, and retain these tests as software cross-checks (see Baochip
//! [design README](https://github.com/Supermagnum/Baochip-1x-firmware)).

#[test]
fn hkdf_sha256_rfc5869_appendix_a() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = [0x0bu8; 22];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let mut okm = [0u8; 42];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    hk.expand(&info, &mut okm).unwrap();
    let exp = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();
    assert_eq!(okm.as_slice(), exp.as_slice());
}

#[test]
fn hkdf_sha512_expand_smoke() {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let mut okm = [0u8; 64];
    let hk = Hkdf::<Sha512>::new(Some(b"salt"), b"ikm");
    hk.expand(b"galdr-v1/info-label", &mut okm).unwrap();
    assert_ne!(okm, [0u8; 64]);
}

#[test]
fn chacha20poly1305_rfc8439_aead() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let key_bytes =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce_bytes = hex::decode("070000004041424344454647").unwrap();
    let key = Key::from_slice(key_bytes.as_slice());
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let mut ct = hex::decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
    ct.extend_from_slice(&hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap());
    let cipher = ChaCha20Poly1305::new(key);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .unwrap();
    let expected = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    assert_eq!(pt.as_slice(), expected.as_slice());
}

#[test]
fn x25519_rfc7748() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let alice =
        hex::decode("77076d0a7318a57d3c16c17251b26645df1496dff944d7fbfc15b887fe467530").unwrap();
    let bob =
        hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap();
    let a = StaticSecret::from(<[u8; 32]>::try_from(alice.as_slice()).unwrap());
    let b = StaticSecret::from(<[u8; 32]>::try_from(bob.as_slice()).unwrap());
    let bp = PublicKey::from(&b);
    let ap = PublicKey::from(&a);
    let sa = a.diffie_hellman(&bp);
    let sb = b.diffie_hellman(&ap);
    assert_eq!(sa.as_bytes(), sb.as_bytes());
}

#[test]
fn ed25519_rfc8032_sign_verify_smoke() {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let sk = SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let vk = sk.verifying_key();
    let sig = sk.sign(b"");
    assert!(vk.verify(b"", &sig).is_ok());
}

#[test]
fn hmac_sha256_rfc4231_case_1() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    )
    .unwrap();
    mac.update(b"Hi There");
    let expected =
        hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
    assert_eq!(mac.finalize().into_bytes().as_slice(), expected.as_slice());
}

#[test]
fn pbkdf2_hmac_sha1_rfc6070_count_1() {
    use pbkdf2::pbkdf2_hmac_array;
    use sha1::Sha1;
    let password = b"password";
    let salt = b"salt";
    let dk = pbkdf2_hmac_array::<Sha1, 20>(password, salt, 1u32);
    let expected = hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap();
    assert_eq!(dk.as_slice(), expected.as_slice());
}

#[test]
fn aes256_gcm_nist_one_block() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    let key = Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]);
    let nonce = Nonce::from_slice(&[0x01u8; 12]);
    let cipher = Aes256Gcm::new(key);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: b"plaintext",
                aad: b"",
            },
        )
        .unwrap();
    let pt = cipher
        .decrypt(nonce, Payload { msg: &ct, aad: b"" })
        .unwrap();
    assert_eq!(pt, b"plaintext");
}

#[test]
fn sha3_256_empty() {
    use sha3::{Digest, Sha3_256};
    let h = Sha3_256::digest([]);
    let exp =
        hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap();
    assert_eq!(h.as_slice(), exp.as_slice());
}

#[test]
fn blake2b512_known_vector() {
    use blake2::{Blake2b512, Digest};
    let mut h = Blake2b512::new();
    h.update(b"abc");
    let out = h.finalize();
    assert_eq!(
        hex::encode(out),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    );
}

#[test]
fn blake3_deterministic() {
    let a = blake3::hash(b"galdr");
    let b = blake3::hash(b"galdr");
    assert_eq!(a, b);
}
