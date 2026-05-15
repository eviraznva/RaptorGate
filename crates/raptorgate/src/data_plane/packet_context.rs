use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use etherparse::{err::packet, SlicedPacket};
use ouroboros::self_referencing;

use crate::conntrack::entry::{ConntrackEntry, CtInfo};
use crate::conntrack::tuple::Direction;
use crate::dpi::DpiContext;
use crate::identity::IdentityContext;
use crate::ml::MlFeatureVector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PacketId(pub u64);

impl PacketId {
    pub fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        PacketId(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

#[self_referencing]
#[derive(Debug)]
pub struct PacketContext {
    pub id: PacketId,
    pub src_interface: Arc<str>,
    pub warnings: Vec<String>,
    pub arrival_time: SystemTime,
    pub raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub sliced_packet: SlicedPacket<'this>,

    pub dpi_ctx: Option<DpiContext>,
    pub identity_ctx: Option<IdentityContext>,
    pub ml_feature_vector: MlFeatureVector,

    ct_entry: Option<Arc<ConntrackEntry>>,
    ct_info: Option<CtInfo>,
    ct_direction: Option<Direction>,
    ct_is_new: bool,
}

impl Clone for PacketContext {
    fn clone(&self) -> Self {
        let mut cloned = Self::from_raw_full(
            self.borrow_raw().clone(),
            self.borrow_src_interface().clone(),
            self.borrow_warnings().clone(),
            *self.borrow_arrival_time(),
            self.borrow_dpi_ctx().clone(),
            self.borrow_identity_ctx().clone(),
            self.borrow_ct_entry().clone(),
            *self.borrow_ct_info(),
            *self.borrow_ct_direction(),
            *self.borrow_ct_is_new(),
        )
        .expect("cloning PacketContext should never fail since it's already been parsed once");
        let id = *self.borrow_id();
        cloned.with_mut(|fields| *fields.id = id);
        cloned
    }
}

impl PacketContext {
    pub fn from_raw(raw: Vec<u8>, src_interface: Arc<str>) -> Result<Self, packet::SliceError> {
        Self::from_raw_full(
            raw,
            src_interface,
            Vec::new(),
            SystemTime::now(),
            None,
            None,
            None,
            None,
            None,
            false,
        )
    }

    pub fn from_raw_full(
        raw: Vec<u8>,
        src_interface: Arc<str>,
        warnings: Vec<String>,
        arrival_time: SystemTime,
        dpi_ctx: Option<DpiContext>,
        identity_ctx: Option<IdentityContext>,
        ct_entry: Option<Arc<ConntrackEntry>>,
        ct_info: Option<CtInfo>,
        ct_direction: Option<Direction>,
        ct_is_new: bool,
    ) -> Result<Self, packet::SliceError> {
        let mut ctx = PacketContextTryBuilder {
            id: PacketId::default(),
            src_interface,
            warnings,
            arrival_time,
            raw,
            sliced_packet_builder: |raw| SlicedPacket::from_ethernet(raw),
            dpi_ctx,
            identity_ctx,
            ml_feature_vector: MlFeatureVector::default(),
            ct_entry,
            ct_info,
            ct_direction,
            ct_is_new,
        }
        .try_build()?;

        let arrival = *ctx.borrow_arrival_time();
        ctx.with_mut(|fields| {
            *fields.id = PacketId::next();
            fields
                .ml_feature_vector
                .init_from_packet(fields.sliced_packet, arrival);
        });

        Ok(ctx)
    }

    pub fn set_conntrack(
        &mut self,
        entry: Arc<ConntrackEntry>,
        info: CtInfo,
        dir: Direction,
        is_new: bool,
    ) {
        self.with_mut(|fields| {
            *fields.ct_entry = Some(entry);
            *fields.ct_info = Some(info);
            *fields.ct_direction = Some(dir);
            *fields.ct_is_new = is_new;
        });
    }

    pub fn ct(&self) -> Option<&Arc<ConntrackEntry>> {
        self.borrow_ct_entry().as_ref()
    }
    pub fn ct_info(&self) -> Option<CtInfo> {
        *self.borrow_ct_info()
    }
    pub fn ct_direction(&self) -> Option<Direction> {
        *self.borrow_ct_direction()
    }
    pub fn ct_is_new(&self) -> bool {
        *self.borrow_ct_is_new()
    }

    pub fn packet_id(&self) -> PacketId {
        *self.borrow_id()
    }
}
