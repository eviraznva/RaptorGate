#[macro_export]
macro_rules! impl_varnum {
    ($name:ident, $primitive:ty, $max_len:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($primitive);

        impl $name {
            pub const MAX_LEN: usize = $max_len;

            pub const fn new(value: $primitive) -> Self {
                Self(value)
            }

            pub const fn get(self) -> $primitive {
                self.0
            }

            pub fn encode_into(self, buf: &mut [u8; Self::MAX_LEN]) -> &[u8] {
                let mut value = self.0;
                let mut i = 0;

                while value > 0x7F {
                    buf[i] = (value as u8 & 0x7F) | 0x80;
                    value >>= 7;
                    i += 1;
                }

                buf[i] = value as u8;
                
                tracing::trace!(
                    type_name = stringify!($name),
                    value = self.0 as u64,
                    encoded_len = i + 1,
                    "Encoded variable-length integer"
                );
                
                &buf[..=i]
            }

            pub fn encoded_len(self) -> usize {
                let mut value = self.0;
                let mut len = 1;

                while value > 0x7F {
                    value >>= 7;
                    len += 1;
                }

                len
            }

            pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
                let mut value: $primitive = 0;
                let mut shift: u32 = 0;

                for (i, &byte) in buf.iter().enumerate().take(Self::MAX_LEN) {
                    value |= ((byte & 0x7F) as $primitive) << shift;
                    shift += 7;

                    if byte & 0x80 == 0 {
                        tracing::trace!(
                            type_name = stringify!($name),
                            value = value as u64,
                            encoded_len = i + 1,
                            "Decoded variable-length integer"
                        );
                        
                        return Some((Self(value), i + 1));
                    }
                }

                None
            }

            pub fn decode_cursor(cursor: &mut &[u8]) -> Option<Self> {
                let (value, len) = Self::decode(cursor)?;
                *cursor = &cursor[len..];
                Some(value)
            }
        }

        impl From<$primitive> for $name {
            fn from(value: $primitive) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $primitive {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}
