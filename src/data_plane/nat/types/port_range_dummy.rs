#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRangeDummy {
    pub start: u16,
    pub end: u16,
}

impl PortRangeDummy {
    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}