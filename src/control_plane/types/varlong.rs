//! Kodowanie i dekodowanie liczb w formacie varlong dla IPC.
//!
//! Typ `VarLong` opakowuje `u64`, gdzie każdy bajt niesie 7 bitów danych,
//! a starszy bit sygnalizuje, czy kolejne bajty należą do tej samej liczby.

use crate::impl_varnum;

impl_varnum!(VarLong, u64, 10);

#[cfg(test)]
mod varlong_tests {
    use super::VarLong;

    #[test]
    fn encode_zero_uses_one_byte() {
        let mut buf = [0u8; VarLong::MAX_LEN];

        let encoded = VarLong::new(0).encode_into(&mut buf);

        assert_eq!(encoded, &[0]);
    }

    #[test]
    fn encode_small_value_uses_one_byte() {
        let mut buf = [0u8; VarLong::MAX_LEN];

        let encoded = VarLong::new(127).encode_into(&mut buf);

        assert_eq!(encoded, &[0x7F]);
    }

    #[test]
    fn encode_boundary_value_uses_two_bytes() {
        let mut buf = [0u8; VarLong::MAX_LEN];

        let encoded = VarLong::new(128).encode_into(&mut buf);

        assert_eq!(encoded, &[0x80, 0x01]);
    }

    #[test]
    fn encoded_len_matches_output_size() {
        assert_eq!(VarLong::new(0).encoded_len(), 1);
        assert_eq!(VarLong::new(127).encoded_len(), 1);
        assert_eq!(VarLong::new(128).encoded_len(), 2);
        assert_eq!(VarLong::new(u64::MAX).encoded_len(), 10);
    }

    #[test]
    fn decode_round_trips_common_values() {
        let cases = [
            (0u64, &[0][..]),
            (1u64, &[1][..]),
            (127u64, &[0x7F][..]),
            (128u64, &[0x80, 1][..]),
            (300u64, &[0xAC, 2][..]),
            (
                u64::MAX,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01][..],
            ),
        ];

        for (value, expected) in cases {
            let mut buf = [0u8; VarLong::MAX_LEN];

            let encoded = VarLong::new(value).encode_into(&mut buf);

            assert_eq!(encoded, expected);
            assert_eq!(
                VarLong::decode(encoded),
                Some((VarLong::new(value), expected.len()))
            );
        }
    }

    #[test]
    fn decode_rejects_truncated_input() {
        assert_eq!(VarLong::decode(&[0x80]), None);
        assert_eq!(VarLong::decode(&[0x80, 0x80]), None);
    }

    #[test]
    fn decode_rejects_too_long_input_without_termination() {
        assert_eq!(
            VarLong::decode(&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00
            ]),
            None
        );
    }

    #[test]
    fn decode_cursor_advances_input() {
        let mut cursor = &[0xAC, 0x02, 0x05][..];

        let first = VarLong::decode_cursor(&mut cursor);
        let second = VarLong::decode_cursor(&mut cursor);

        assert_eq!(first, Some(VarLong::new(300)));
        assert_eq!(second, Some(VarLong::new(5)));
        assert!(cursor.is_empty());
    }
}
