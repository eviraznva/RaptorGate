use bitflags::bitflags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManipType {
    Source,
    Destination,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ManipMask: u8 {
      const SRC = 1 << 0;
      const DST = 1 << 1;
    }
}

impl ManipMask {
    pub fn from_type(t: ManipType) -> Self {
        match t {
            ManipType::Source      => ManipMask::SRC,
            ManipType::Destination => ManipMask::DST,
        }
    }

    pub fn contains_src(self) -> bool { self.contains(ManipMask::SRC) }
    pub fn contains_dst(self) -> bool { self.contains(ManipMask::DST) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_from_type_round_trip() {
        assert_eq!(ManipMask::from_type(ManipType::Source),      ManipMask::SRC);
        assert_eq!(ManipMask::from_type(ManipType::Destination), ManipMask::DST);
    }

    #[test]
    fn mask_can_combine_src_and_dst() {
        let combo = ManipMask::SRC | ManipMask::DST;
        
        assert!(combo.contains_src());
        assert!(combo.contains_dst());
    }
}