//! Scalar field modulo n (brainpoolP512r1 subgroup order).

use crate::{BrainpoolP512r1, ORDER, ORDER_HEX, U512};
use elliptic_curve::ff::PrimeField;
use elliptic_curve::scalar::{FromUintUnchecked, IsHigh};
use elliptic_curve::subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U512,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 7,
    doc: "Montgomery parameters for brainpoolP512r1 scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
    doc: "Element in the brainpoolP512r1 scalar field modulo n"
}

primefield::monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U512
}

primefield::monty_field_reduce! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
}

elliptic_curve::scalar_impls!(BrainpoolP512r1, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U512;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U512 = ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U512};
    primefield::test_primefield!(Scalar, U512);
}
