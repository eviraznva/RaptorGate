//! Kodowanie i dekodowanie liczb w formacie varint dla IPC.
//!
//! Typ `VarInt` opakowuje `u32`, gdzie każdy bajt niesie 7 bitów danych,
//! a starszy bit sygnalizuje, czy kolejne bajty należą do tej samej liczby.

use crate::impl_varnum;

impl_varnum!(VarInt, u32, 5);

#[cfg(test)]
mod varint_tests {
    use super::VarInt;

    #[test]
    fn encode_zero_uses_one_byte() {
        let mut buf = [0u8; VarInt::MAX_LEN];

        let encoded = VarInt::new(0).encode_into(&mut buf);

        assert_eq!(encoded, &[0]);
    }

    #[test]
    fn encode_small_value_uses_one_byte() {
        let mut buf = [0u8; VarInt::MAX_LEN];

        let encoded = VarInt::new(127).encode_into(&mut buf);

        assert_eq!(encoded, &[0x7F]);
    }

    #[test]
    fn encode_boundary_value_uses_two_bytes() {
        let mut buf = [0u8; VarInt::MAX_LEN];

        let encoded = VarInt::new(128).encode_into(&mut buf);

        assert_eq!(encoded, &[0x80, 1]);
    }

    #[test]
    fn encoded_len_matches_output_size() {
        assert_eq!(VarInt::new(0).encoded_len(), 1);
        assert_eq!(VarInt::new(127).encoded_len(), 1);
        assert_eq!(VarInt::new(128).encoded_len(), 2);
        assert_eq!(VarInt::new(u32::MAX).encoded_len(), 5);
    }

    #[test]
    fn decode_round_trips_common_values() {
        let cases = [
            (0u32, &[0][..]),
            (1u32, &[1][..]),
            (127u32, &[0x7F][..]),
            (128u32, &[0x80, 1][..]),
            (300u32, &[0xAC, 2][..]),
            (u32::MAX, &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F][..]),
        ];

        for (value, expected) in cases {
            let mut buf = [0u8; VarInt::MAX_LEN];

            let encoded = VarInt::new(value).encode_into(&mut buf);

            assert_eq!(encoded, expected);
            assert_eq!(
                VarInt::decode(encoded),
                Some((VarInt::new(value), expected.len()))
            );
        }
    }

    #[test]
    fn decode_rejects_truncated_input() {
        assert_eq!(VarInt::decode(&[0x80]), None);
        assert_eq!(VarInt::decode(&[0x80, 0x80]), None);
    }

    #[test]
    fn decode_rejects_too_long_input_without_termination() {
        assert_eq!(VarInt::decode(&[0x80, 0x80, 0x80, 0x80, 0x80, 0]), None);
    }

    #[test]
    fn decode_cursor_advances_input() {
        let mut cursor = &[0xAC, 0x02, 0x05][..];

        let first = VarInt::decode_cursor(&mut cursor);
        let second = VarInt::decode_cursor(&mut cursor);

        assert_eq!(first, Some(VarInt::new(300)));
        assert_eq!(second, Some(VarInt::new(5)));
        assert!(cursor.is_empty());
    }
}
