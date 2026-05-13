pub mod config_bundle;
pub mod conntrack_queries;
pub mod daemon;
pub mod outcomes;
pub mod scenario;
pub mod static_infra;

pub use config_bundle::{
    physical_zone_interface, smoke_icmp_allow_warn_bundle, smoke_tcp_allow_warn_bundle,
    ConfigBundleBuilder,
};
pub use conntrack_queries::ConntrackSnapshotExt;
pub use daemon::{TestDaemon, TestDaemonBuilder, TestDaemonBuildError, TestDeps};
pub use outcomes::{OutcomeMismatch, PipelineOutcome, ProcessOutputAssertExt};
pub use scenario::{
    icmp_echo_ipv4, packets, IcmpSessionV4, PacketsScenario, Scenario, ScenarioRunError,
    SocketV4, TcpSessionScenario, TcpSessionV4, UdpSessionV4,
};

pub use ngfw::daemon::ProcessOutput;
pub use ngfw::events::{
    set_event_capture, Event, EventCapture, EventKind, EventPredicate, WaitForSubsequenceError,
    WaitForSubsequenceResult,
};

use std::future::Future;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;

pub(crate) const FENCE_SETTLE: Duration = Duration::from_millis(2);

static EVENT_CAPTURE_CONCURRENCY: OnceLock<Mutex<()>> = OnceLock::new();

pub fn event_capture_concurrency_mutex() -> &'static Mutex<()> {
    EVENT_CAPTURE_CONCURRENCY.get_or_init(|| Mutex::new(()))
}

pub fn matchers_discriminant_only(pattern_kinds: &[EventKind]) -> Vec<EventPredicate> {
    pattern_kinds
        .iter()
        .map(|k| {
            let d = std::mem::discriminant(k);
            Box::new(move |e: &Event| std::mem::discriminant(&e.kind) == d) as EventPredicate
        })
        .collect()
}

pub fn matchers_kind_exact(pattern_kinds: &[EventKind]) -> Vec<EventPredicate> {
    pattern_kinds
        .iter()
        .map(|k| {
            let k = k.clone();
            Box::new(move |e: &Event| e.kind == k) as EventPredicate
        })
        .collect()
}

pub async fn expect_events<F, Fut>(
    capture: &EventCapture,
    stimulus: F,
    pattern_kinds: &[EventKind],
) -> Result<(), WaitForSubsequenceError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    capture.clear();
    capture.set_fence(SystemTime::now());
    tokio::time::sleep(FENCE_SETTLE).await;
    stimulus().await;
    let matchers = matchers_discriminant_only(pattern_kinds);
    capture.wait_for_subsequence(&matchers).await
}

pub async fn expect_events_exact<F, Fut>(
    capture: &EventCapture,
    stimulus: F,
    pattern_kinds: &[EventKind],
) -> Result<(), WaitForSubsequenceError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    capture.clear();
    capture.set_fence(SystemTime::now());
    tokio::time::sleep(FENCE_SETTLE).await;
    stimulus().await;
    let matchers = matchers_kind_exact(pattern_kinds);
    capture.wait_for_subsequence(&matchers).await
}

#[macro_export]
macro_rules! events {
    ($($pred:expr),* $(,)?) => {
        vec![$(Box::new($pred) as ngfw::events::EventPredicate),*]
    };
}

#[macro_export]
macro_rules! event {
    ($pred:expr) => {
        Box::new($pred) as ngfw::events::EventPredicate
    };
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn expect_events_sees_emitted_after_fence() {
        let _guard = event_capture_concurrency_mutex().lock().await;
        let cap = Arc::new(EventCapture::new());
        set_event_capture(Some(cap.clone()));
        let res = expect_events(&cap, || async {
            ngfw::events::emit(Event::new(EventKind::EventBusConnectedEvent {}));
        }, &[EventKind::EventBusConnectedEvent {}])
        .await;
        set_event_capture(None);
        res.unwrap();
    }

    #[tokio::test]
    async fn expect_events_subsequence_two_kinds() {
        let _guard = event_capture_concurrency_mutex().lock().await;
        let cap = Arc::new(EventCapture::new());
        set_event_capture(Some(cap.clone()));
        let res = expect_events(&cap, || async {
            ngfw::events::emit(Event::new(EventKind::EventBusConnectedEvent {}));
            ngfw::events::emit(Event::new(EventKind::PolicyWarning {
                message: "m".into(),
                verdict: "allow",
            }));
        }, &[
            EventKind::EventBusConnectedEvent {},
            EventKind::PolicyWarning {
                message: String::new(),
                verdict: "allow",
            },
        ])
        .await;
        set_event_capture(None);
        res.unwrap();
    }

    #[tokio::test]
    async fn smoke_icmp_allow_warn_forward_and_policy_warning_event() {
        let _guard = event_capture_concurrency_mutex().lock().await;
        let cap = Arc::new(EventCapture::new());
        set_event_capture(Some(cap.clone()));

        let bundle = smoke_icmp_allow_warn_bundle();
        let td = TestDaemon::builder()
            .with_bundle(bundle)
            .build()
            .await
            .expect("test daemon");

        let raw = icmp_echo_ipv4([192, 168, 10, 1], [192, 168, 20, 10]);

        Scenario::packets()
            .on_iface("eth1")
            .send(raw)
            .expect_packet(PipelineOutcome::Forward)
            .expect_event(event!(|e: &Event| {
                matches!(&e.kind, EventKind::PolicyWarning { verdict, .. } if verdict == &"allow")
            }))
            .run(&td, &cap)
            .await
            .expect("scenario");

        set_event_capture(None);
    }

    #[tokio::test]
    async fn raw_packets_scenario_icmp_forward_only() {
        let _guard = event_capture_concurrency_mutex().lock().await;
        let cap = Arc::new(EventCapture::new());
        set_event_capture(Some(cap.clone()));

        let bundle = smoke_icmp_allow_warn_bundle();
        let td = TestDaemon::builder()
            .with_bundle(bundle)
            .build()
            .await
            .expect("test daemon");

        let raw = icmp_echo_ipv4([192, 168, 10, 2], [192, 168, 20, 11]);

        Scenario::packets()
            .send(raw)
            .expect_packet(PipelineOutcome::Forward)
            .run(&td, &cap)
            .await
            .expect("scenario");

        set_event_capture(None);
    }

    #[tokio::test]
    async fn tcp_session_scenario_handshake_and_data_forward() {
        let _guard = event_capture_concurrency_mutex().lock().await;
        let cap = Arc::new(EventCapture::new());
        set_event_capture(Some(cap.clone()));

        let bundle = smoke_tcp_allow_warn_bundle();
        let td = TestDaemon::builder()
            .with_bundle(bundle)
            .build()
            .await
            .expect("test daemon");

        let client = SocketV4 {
            ip: [192, 168, 10, 3],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 12],
            port: 25,
        };

        Scenario::tcp(client, server)
            .open()
            .client_sends(b"ping")
            .expect_event(event!(|e: &Event| {
                matches!(&e.kind, EventKind::PolicyWarning { verdict, .. } if verdict == &"allow")
            }))
            .run(&td, &cap)
            .await
            .expect("scenario");

        set_event_capture(None);
    }
}
