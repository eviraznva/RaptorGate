use super::noop::{NoopIcmpStage, NoopTcpStage, NoopUdpStage};
use super::stage::{L4Outcome, L4Stage};
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;

pub type TcpNoopPipeline = NoopTcpStage;
pub type UdpNoopPipeline = NoopUdpStage;
pub type IcmpNoopPipeline = NoopIcmpStage;

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpL4PipelineFactory;

impl TcpL4PipelineFactory {
    pub fn build(&self) -> TcpNoopPipeline {
        NoopTcpStage::default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UdpL4PipelineFactory;

impl UdpL4PipelineFactory {
    pub fn build(&self) -> UdpNoopPipeline {
        NoopUdpStage::default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IcmpL4PipelineFactory;

impl IcmpL4PipelineFactory {
    pub fn build(&self) -> IcmpNoopPipeline {
        NoopIcmpStage::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::sync::Arc;

    #[test]
    fn tcp_factory_pipeline_forwards_packet_id() {
        let mut pipe = TcpL4PipelineFactory::default().build();
        let mut ctx = ();
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x");
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }

    #[test]
    fn udp_factory_pipeline_forwards_packet_id() {
        let mut pipe = UdpL4PipelineFactory::default().build();
        let mut ctx = ();
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x");
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }

    #[test]
    fn icmp_factory_pipeline_forwards_packet_id() {
        let mut pipe = IcmpL4PipelineFactory::default().build();
        let mut ctx = ();
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x");
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }
}
