//! One-shot host tool: emit `serpent_vectors.json` for vault KAT tests (RustCrypto `serpent` ECB).

use serde_json::json;
use serpent::cipher::array::Array;
use serpent::cipher::consts::U16;
use serpent::cipher::{BlockCipherEncrypt, KeyInit};
use serpent::Serpent;

fn ecb_encrypt(key: &[u8], pt: &[u8; 16]) -> Result<[u8; 16], serpent::cipher::InvalidLength> {
    let s = Serpent::new_from_slice(key)?;
    let bin: Array<u8, U16> = (*pt).into();
    let mut bout = Array::<u8, U16>::default();
    s.encrypt_block_b2b(&bin, &mut bout);
    let mut o = [0u8; 16];
    o.copy_from_slice(bout.as_slice());
    Ok(o)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for &bits in &[128u32, 192, 256] {
        let kl = (bits / 8) as usize;
        let key = vec![0u8; kl];
        let pt = [0u8; 16];
        let ct = ecb_encrypt(&key, &pt)?;
        out.push(json!({
            "key_bits": bits,
            "key": hex::encode(&key),
            "plaintext": hex::encode(pt),
            "ciphertext": hex::encode(ct),
        }));
        for i in 0..200 {
            let mut key = vec![0u8; kl];
            let bit = (i as usize) % (bits as usize);
            key[bit / 8] |= 1 << (bit % 8);
            let pt = [0u8; 16];
            let ct = ecb_encrypt(&key, &pt)?;
            out.push(json!({
                "key_bits": bits,
                "key": hex::encode(&key),
                "plaintext": hex::encode(pt),
                "ciphertext": hex::encode(ct),
            }));
        }
        for i in 0..200 {
            let key = vec![0u8; kl];
            let mut pt = [0u8; 16];
            let bit = (i as usize) % 128;
            pt[bit / 8] |= 1 << (bit % 8);
            let ct = ecb_encrypt(&key, &pt)?;
            out.push(json!({
                "key_bits": bits,
                "key": hex::encode(&key),
                "plaintext": hex::encode(pt),
                "ciphertext": hex::encode(ct),
            }));
        }
    }
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
