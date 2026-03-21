#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatStage {
    Prerouting,
    Postrouting,
}