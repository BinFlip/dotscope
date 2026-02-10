//! Mathematical utility functions.

use crate::Result;

/// Converts a `usize` to `u32` for PE serialization, returning an error if the value
/// exceeds `u32::MAX`. All .NET metadata structures are bounded well below this limit.
///
/// # Errors
///
/// Returns an error if `value` exceeds `u32::MAX`.
pub fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| malformed_error!("PE serialization value {value} exceeds u32::MAX"))
}

/// Checks if a value is a power of two and returns the exponent.
///
/// Returns `Some(n)` if `value == 2^n`, `None` otherwise.
/// Only works for positive values.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::utils::is_power_of_two;
///
/// assert_eq!(is_power_of_two(1), Some(0));   // 2^0 = 1
/// assert_eq!(is_power_of_two(2), Some(1));   // 2^1 = 2
/// assert_eq!(is_power_of_two(8), Some(3));   // 2^3 = 8
/// assert_eq!(is_power_of_two(0), None);
/// assert_eq!(is_power_of_two(-8), None);
/// assert_eq!(is_power_of_two(6), None);
/// ```
#[must_use]
#[allow(clippy::cast_sign_loss)] // value > 0 verified above
#[allow(clippy::cast_possible_truncation)] // trailing_zeros <= 63 for u64
pub fn is_power_of_two(value: i64) -> Option<u8> {
    if value <= 0 {
        return None;
    }
    let value = value as u64;
    if value.is_power_of_two() {
        Some(value.trailing_zeros() as u8)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_power_of_two() {
        assert_eq!(is_power_of_two(1), Some(0));
        assert_eq!(is_power_of_two(2), Some(1));
        assert_eq!(is_power_of_two(4), Some(2));
        assert_eq!(is_power_of_two(8), Some(3));
        assert_eq!(is_power_of_two(16), Some(4));
        assert_eq!(is_power_of_two(32), Some(5));
        assert_eq!(is_power_of_two(64), Some(6));
        assert_eq!(is_power_of_two(128), Some(7));
        assert_eq!(is_power_of_two(256), Some(8));
        assert_eq!(is_power_of_two(1024), Some(10));
        assert_eq!(is_power_of_two(1 << 20), Some(20));
        assert_eq!(is_power_of_two(1 << 30), Some(30));
    }

    #[test]
    fn test_to_u32_valid() {
        assert_eq!(to_u32(0).unwrap(), 0);
        assert_eq!(to_u32(1).unwrap(), 1);
        assert_eq!(to_u32(u32::MAX as usize).unwrap(), u32::MAX);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_to_u32_overflow() {
        assert!(to_u32(u32::MAX as usize + 1).is_err());
        assert!(to_u32(usize::MAX).is_err());
    }

    #[test]
    fn test_is_power_of_two_non_powers() {
        assert_eq!(is_power_of_two(0), None);
        assert_eq!(is_power_of_two(-1), None);
        assert_eq!(is_power_of_two(-8), None);
        assert_eq!(is_power_of_two(3), None);
        assert_eq!(is_power_of_two(5), None);
        assert_eq!(is_power_of_two(6), None);
        assert_eq!(is_power_of_two(7), None);
        assert_eq!(is_power_of_two(9), None);
        assert_eq!(is_power_of_two(15), None);
        assert_eq!(is_power_of_two(17), None);
    }
}
