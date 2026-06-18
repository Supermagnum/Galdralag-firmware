//! Values listed in the CESS [**Cipher suite identifier lookup table**](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md#cipher-suite-identifier-lookup-table).
//!
//! **Sync:** When [ALGORITHM-REGISTRY.md](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md) gains or loses rows, update [`LISTED_SUITE_ID_RANGES`] to match (Version **0.2-draft**, classical **56**-cell product rows **`0x0001`–`0x0007`**, **`0x0008`–`0x000f`**, **`0x0010`–`0x0030`**, **`0x0200`–`0x0207`**, plus PQ rows, per upstream).
//!
//! **Private-use `suite_id`:** CESS allows deployment-specific IDs only with **out-of-band**
//! agreement. This crate **rejects** any ID not covered by [`LISTED_SUITE_ID_RANGES`]; add a
//! `(start, end)` pair locally if your deployment uses authorised private-use codes.

/// Inclusive `(low, high)` ranges of **`suite_id`** values that each have a row in the lookup table.
///
/// Gaps between ranges are **not** valid (for example **`0x0031`–`0x00FF`** excluding listed rows,
/// **`0x0103`–`0x010F`**, **`0x0113`–`0x011F`**, **`0x0123`–`0x01FF`**, **`0x0208`–`0x02FF`**, **`0x0300`–`0xFFFF`**
/// until allocated — see registry **Informative (registry maintenance)**).
pub const LISTED_SUITE_ID_RANGES: &[(u16, u16)] = &[
    (0x0001, 0x0007),
    (0x0008, 0x000f),
    (0x0010, 0x0030),
    (0x0100, 0x0102),
    (0x0110, 0x0112),
    (0x0120, 0x0122),
    (0x0200, 0x0207),
];

/// Returns `true` if `id` is a **listed** `suite_id` in the CESS algorithm registry lookup table.
///
/// **`0x0000`** is never listed (reserved). Values in gaps between [`LISTED_SUITE_ID_RANGES`] are **not** valid.
#[inline]
pub fn is_listed_suite_id(id: u16) -> bool {
    if id == 0 {
        return false;
    }
    LISTED_SUITE_ID_RANGES
        .iter()
        .any(|&(low, high)| id >= low && id <= high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_endpoints_are_listed() {
        for &(low, high) in LISTED_SUITE_ID_RANGES {
            assert!(is_listed_suite_id(low), "low={low:#06x}");
            assert!(is_listed_suite_id(high), "high={high:#06x}");
        }
    }

    #[test]
    fn documented_gaps_are_unlisted() {
        assert!(!is_listed_suite_id(0x0000));
        assert!(!is_listed_suite_id(0x0031));
        assert!(!is_listed_suite_id(0x0103));
        assert!(!is_listed_suite_id(0x0113));
        assert!(!is_listed_suite_id(0x0123));
        assert!(!is_listed_suite_id(0x0208));
        assert!(!is_listed_suite_id(0xffff));
    }

    #[test]
    fn newly_allocated_classical_rows_are_listed() {
        assert!(is_listed_suite_id(0x0008));
        assert!(is_listed_suite_id(0x0013));
        assert!(is_listed_suite_id(0x0030));
    }
}
