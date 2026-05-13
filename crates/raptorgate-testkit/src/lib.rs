use std::future::Future;
use std::time::{Duration, SystemTime};

pub use ngfw::events::{
    set_event_capture, Event, EventCapture, EventKind, EventPredicate, WaitForSubsequenceError,
    WaitForSubsequenceResult,
};

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

pub struct Scenario;

impl Scenario {
    pub async fn run_expect_events<F, Fut>(
        capture: &EventCapture,
        stimulus: F,
        pattern_kinds: &[EventKind],
    ) -> Result<(), WaitForSubsequenceError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        expect_events(capture, stimulus, pattern_kinds).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, OnceLock};

    use super::*;

    static GLOBAL_CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn global_capture_lock() -> &'static Mutex<()> {
        GLOBAL_CAPTURE_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn expect_events_sees_emitted_after_fence() {
        let _guard = global_capture_lock().lock().unwrap();
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
        let _guard = global_capture_lock().lock().unwrap();
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
}
