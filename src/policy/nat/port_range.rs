#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> u16 {
        self.start
    }

    pub fn end(&self) -> u16 {
        self.end
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}