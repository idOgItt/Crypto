use twofish::crypto::utils::{rotate_left, rotate_right};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotate_left() {
        assert_eq!(rotate_left(0x12345678, 4), 0x23456781);
        assert_eq!(rotate_left(0x87654321, 8), 0x76543218);
        assert_eq!(rotate_left(0xFFFFFFFF, 16), 0xFFFFFFFF);
        assert_eq!(rotate_left(0x00000001, 1), 0x00000002);
        assert_eq!(rotate_left(0x80000000, 1), 0x00000001);
        assert_eq!(rotate_left(0x12345678, 32), 0x12345678);
    }

    #[test]
    fn test_rotate_right() {
        assert_eq!(rotate_right(0x12345678, 4), 0x81234567);
        assert_eq!(rotate_right(0x87654321, 8), 0x21876543);
        assert_eq!(rotate_right(0xFFFFFFFF, 16), 0xFFFFFFFF);
        assert_eq!(rotate_right(0x00000001, 1), 0x80000000);
        assert_eq!(rotate_right(0x00000002, 1), 0x00000001);
        assert_eq!(rotate_right(0x12345678, 32), 0x12345678);
    }

    #[test]
    fn test_rotate_identity() {
        let value = 0x12345678;
        assert_eq!(rotate_left(value, 0), value);
        assert_eq!(rotate_right(value, 0), value);
    }

    #[test]
    fn test_rotate_equivalence() {
        let value = 0xABCDEF01;
        let shift = 7;
        assert_eq!(rotate_left(value, shift), rotate_right(value, 32 - shift));
    }
}