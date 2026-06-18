//! Development helper: `cargo run -p vault --example shamir_vector_dump`
//! prints share hex lines for embedding in `tests/data/shamir_vectors.json`.

use galdr_core::fake_hal::FakeTrng;
use vault::shamir::shamir_split;

fn main() {
    let secret = [0x11u8; 32];
    let mut trng = FakeTrng::from_seed(0x51);
    let shares = shamir_split(&secret, 2, 3, &mut trng).expect("split");
    println!("secret_hex = {}", hex::encode(secret));
    for s in shares {
        println!("index {} value_hex {}", s.index, hex::encode(s.value()));
    }
}
