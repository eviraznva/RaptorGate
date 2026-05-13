pub mod config_bundle;
pub mod conntrack_queries;
pub mod daemon;
pub mod outcomes;
pub mod scenario;
pub mod static_infra;

pub use config_bundle::{physical_zone_interface, ConfigBundleBuilder};
pub use conntrack_queries::ConntrackSnapshotExt;
pub use daemon::{TestDaemon, TestDaemonBuilder, TestDaemonBuildError, TestDeps};
pub use outcomes::{OutcomeMismatch, PipelineOutcome, ProcessOutputAssertExt};
pub use scenario::{
    icmp_echo_ipv4, packets, IcmpSessionV4, PacketsScenario, Scenario, SocketV4, TcpSessionV4,
    UdpSessionV4,
};

pub use ngfw::daemon::ProcessOutput;
pub use ngfw::events::{
    set_event_capture, Event, EventCapture, EventKind, EventPredicate, WaitForSubsequenceError,
    WaitForSubsequenceResult,
};

use std::future::Future;
use std::time::{Duration, SystemTime};

const FENCE_SETTLE: Duration = Duration::from_millis(2);

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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};
    use std::time::SystemTime;

    use ngfw::pipeline::ExecutionAction;
    use tokio::sync::Mutex;

    use crate::ProcessOutputAssertExt;

    use super::*;

    static GLOBAL_CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn global_capture_lock() -> &'static Mutex<()> {
        GLOBAL_CAPTURE_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn expect_events_sees_emitted_after_fence() {
        let _guard = global_capture_lock().lock().await;
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
        let _guard = global_capture_lock().lock().await;
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
        let _guard = global_capture_lock().lock().await;
        let cap = Arc::new(EventCapture::new());
        set_event_capture(Some(cap.clone()));

        let bundle = config_bundle::smoke_icmp_allow_warn_bundle();
        let td = TestDaemon::builder()
            .with_bundle(bundle)
            .build()
            .await
            .expect("test daemon");

        let raw = icmp_echo_ipv4([192, 168, 10, 1], [192, 168, 20, 10]);

        cap.clear();
        cap.set_fence(SystemTime::now());
        tokio::time::sleep(FENCE_SETTLE).await;

        let out = td.daemon().process_raw(raw, Arc::from("eth1")).await;
        out.assert_outcome(PipelineOutcome::Forward)
            .expect("pipeline outcome");
        assert!(
            out.emitted
                .iter()
                .any(|i| matches!(i.action, ExecutionAction::Forward)),
            "expected forward emission"
        );

        let preds = events![|e: &Event| {
            matches!(&e.kind, EventKind::PolicyWarning { verdict, .. } if verdict == &"allow")
        }];
        cap.wait_for_subsequence(&preds)
            .await
            .expect("policy warning event");
        set_event_capture(None);
    }
}
