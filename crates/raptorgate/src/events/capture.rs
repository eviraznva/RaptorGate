use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::Event;

pub type EventPredicate = Box<dyn Fn(&Event) -> bool + Send + Sync>;

static EVENT_CAPTURE: ArcSwapOption<EventCapture> = ArcSwapOption::const_empty();

pub fn set_event_capture(capture: Option<Arc<EventCapture>>) {
    EVENT_CAPTURE.store(capture);
}

pub(crate) fn forward_to_capture(event: &Event) {
    if let Some(cap) = EVENT_CAPTURE.load_full() {
        cap.push(event.clone());
    }
}

#[derive(Debug)]
pub struct WaitForSubsequenceResult {
    pub matched: bool,
    pub failed_at: Option<usize>,
    pub received: Vec<Event>,
    pub terminated: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("event subsequence assertion failed at pattern index {failed_at} ({received_count} events after fence)")]
pub struct WaitForSubsequenceError {
    pub failed_at: usize,
    pub received_count: usize,
}

struct CaptureState {
    buffer: Vec<Event>,
    fence: Option<SystemTime>,
}

#[derive(Clone)]
pub struct EventCapture {
    state: Arc<Mutex<CaptureState>>,
    notify: Arc<Notify>,
}

impl EventCapture {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CaptureState { buffer: Vec::new(), fence: None })),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn set_fence(&self, vm_timestamp: SystemTime) {
        self.state.lock().fence = Some(vm_timestamp);
    }

    pub fn clear(&self) {
        self.state.lock().buffer.clear();
    }

    pub fn push(&self, event: Event) {
        self.state.lock().buffer.push(event);
        self.notify.notify_waiters();
    }

    pub fn snapshot(&self) -> Vec<Event> {
        self.state.lock().buffer.clone()
    }

    pub fn events_after_fence(&self) -> Vec<Event> {
        let g = self.state.lock();
        let fence = g.fence;
        g.buffer.iter().filter(|e| is_after_fence(e, fence)).cloned().collect()
    }

    pub fn try_match_subsequence(&self, patterns: &[EventPredicate]) -> WaitForSubsequenceResult {
        let g = self.state.lock();
        let fence = g.fence;
        let relevant: Vec<Event> = g.buffer.iter().filter(|e| is_after_fence(e, fence)).cloned().collect();
        drop(g);
        try_match_patterns(&relevant, patterns)
    }

    pub async fn wait_for_subsequence(&self, patterns: &[EventPredicate]) -> Result<(), WaitForSubsequenceError> {
        if patterns.is_empty() {
            return Ok(());
        }
        loop {
            let result = self.try_match_subsequence(patterns);
            if result.matched {
                return Ok(());
            }
            if result.terminated && !result.matched {
                return Err(WaitForSubsequenceError {
                    failed_at: result.failed_at.unwrap_or(0),
                    received_count: result.received.len(),
                });
            }
            self.notify.notified().await;
        }
    }
}

impl Default for EventCapture {
    fn default() -> Self {
        Self::new()
    }
}

fn is_after_fence(event: &Event, fence: Option<SystemTime>) -> bool {
    let Some(f) = fence else {
        return true;
    };
    event.emitted_at > f
}

fn try_match_patterns(relevant: &[Event], patterns: &[EventPredicate]) -> WaitForSubsequenceResult {
    let mut pattern_idx = 0usize;
    for event in relevant {
        if pattern_idx >= patterns.len() {
            break;
        }
        let pattern = &patterns[pattern_idx];
        if pattern(event) {
            pattern_idx += 1;
        } else if is_out_of_order(event, patterns, pattern_idx) {
            return WaitForSubsequenceResult {
                matched: false,
                failed_at: Some(pattern_idx),
                received: relevant.to_vec(),
                terminated: true,
            };
        }
    }
    if pattern_idx >= patterns.len() {
        WaitForSubsequenceResult {
            matched: true,
            failed_at: None,
            received: relevant.to_vec(),
            terminated: true,
        }
    } else {
        WaitForSubsequenceResult {
            matched: false,
            failed_at: Some(pattern_idx),
            received: relevant.to_vec(),
            terminated: false,
        }
    }
}

fn is_out_of_order(event: &Event, patterns: &[EventPredicate], current_idx: usize) -> bool {
    for j in (current_idx + 1)..patterns.len() {
        if patterns[j](event) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Event, EventKind};

    fn mk_event(kind: EventKind) -> Event {
        Event::new(kind)
    }

    #[test]
    fn subsequence_ordered() {
        let cap = EventCapture::new();
        cap.push(mk_event(EventKind::EventBusConnectedEvent {}));
        cap.push(mk_event(EventKind::PolicyWarning {
            message: "a".into(),
            verdict: "allow",
        }));
        let p0: EventPredicate = Box::new(|e| matches!(e.kind, EventKind::EventBusConnectedEvent {}));
        let p1: EventPredicate = Box::new(|e| matches!(e.kind, EventKind::PolicyWarning { .. }));
        let r = cap.try_match_subsequence(&[p0, p1]);
        assert!(r.matched);
    }

    #[test]
    fn subsequence_detects_gap() {
        let cap = EventCapture::new();
        cap.push(mk_event(EventKind::PolicyWarning {
            message: "x".into(),
            verdict: "drop",
        }));
        let p0: EventPredicate = Box::new(|e| matches!(e.kind, EventKind::EventBusConnectedEvent {}));
        let p1: EventPredicate = Box::new(|e| matches!(e.kind, EventKind::PolicyWarning { .. }));
        let r = cap.try_match_subsequence(&[p0, p1]);
        assert!(!r.matched);
        assert!(r.terminated);
        assert_eq!(r.failed_at, Some(0));
    }

    #[test]
    fn fence_filters_old() {
        let cap = EventCapture::new();
        let t0 = SystemTime::UNIX_EPOCH;
        cap.push(Event {
            emitted_at: t0,
            kind: EventKind::EventBusConnectedEvent {},
        });
        std::thread::sleep(std::time::Duration::from_millis(5));
        cap.set_fence(SystemTime::now());
        cap.push(mk_event(EventKind::PolicyWarning {
            message: "b".into(),
            verdict: "allow",
        }));
        let p: EventPredicate = Box::new(|e| matches!(e.kind, EventKind::PolicyWarning { .. }));
        let r = cap.try_match_subsequence(&[p]);
        assert!(r.matched);
    }
}
