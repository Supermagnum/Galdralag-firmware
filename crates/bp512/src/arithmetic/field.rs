//! Base field modulo p (RFC 5639 brainpoolP512r1) — Montgomery arithmetic via `primefield` / crypto-bigint.

use crate::U512;
use elliptic_curve::ff::PrimeField;
use elliptic_curve::subtle::{Choice, ConstantTimeEq, CtOption};

/// Modulus p (512-bit prime), lower-case hex without 0x prefix.
const MODULUS_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U512,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for brainpoolP512r1 field modulus"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U512,
    doc: "Element in the brainpoolP512r1 field modulo p"
}

primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U512
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U512};
    primefield::test_primefield!(FieldElement, U512);
}
