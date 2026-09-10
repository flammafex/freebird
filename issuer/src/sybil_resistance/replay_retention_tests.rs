use super::*;
use std::{collections::HashMap, sync::Mutex, time::Duration};

/// Injected store with explicit elapsed time, matching exclusive TTL expiry.
#[derive(Default)]
pub(crate) struct ClockStore {
    state: Mutex<(u64, HashMap<String, u64>, Vec<Duration>)>,
}

impl ClockStore {
    pub(crate) fn advance_to(&self, elapsed: u64) {
        self.state.lock().unwrap().0 = elapsed;
    }
    pub(crate) fn ttls(&self) -> Vec<Duration> {
        self.state.lock().unwrap().2.clone()
    }
}

impl ReplayStore for ClockStore {
    fn mark_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let now = state.0;
        let key = format!("{namespace}:{key}");
        state.2.push(ttl);
        if state.1.get(&key).is_some_and(|expires| *expires > now) {
            return Err(anyhow!("already used"));
        }
        state.1.insert(key, now.checked_add(ttl.as_secs()).unwrap());
        Ok(())
    }
    fn health_check(&self) -> Result<()> {
        Ok(())
    }
}

#[test]
fn replay_ttl_checked_arithmetic_and_timestamp_extremes() {
    assert_eq!(
        replay_ttl(300, POW_FUTURE_SKEW_SECS).unwrap().as_secs(),
        601
    );
    assert_eq!(
        replay_ttl(300, WEBAUTHN_FUTURE_SKEW_SECS)
            .unwrap()
            .as_secs(),
        361
    );
    assert_eq!(replay_ttl(300, 0).unwrap().as_secs(), 301);
    assert_eq!(replay_ttl(0, 0).unwrap().as_secs(), 1);
    for (age, skew) in [
        (u64::MAX, 1),
        (u64::MAX, 0),
        (0, u64::MAX),
        (i64::MAX as u64, 0),
    ] {
        assert!(replay_ttl(age, skew).is_err());
    }
    assert!(verify_timestamp_at(u64::MAX.into(), 0, 300, POW_FUTURE_SKEW_SECS).is_err());
    assert!(
        verify_timestamp_at(u64::MAX.into(), u64::MAX.into(), 300, POW_FUTURE_SKEW_SECS).is_ok()
    );
    assert!(verify_timestamp_at(
        i64::MIN.into(),
        i64::MAX.into(),
        300,
        WEBAUTHN_FUTURE_SKEW_SECS
    )
    .is_err());
    assert!(verify_timestamp_at(
        i64::MAX.into(),
        i64::MIN.into(),
        300,
        WEBAUTHN_FUTURE_SKEW_SECS
    )
    .is_err());
}
