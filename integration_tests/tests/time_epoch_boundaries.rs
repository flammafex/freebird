// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: time and epoch boundary invariants.
//
// These tests lock in verifier-style behavior for:
// - expiration checks with clock skew tolerance
// - future-exp sanity bounds
// - epoch retention windows

const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 300; // 5 minutes
const DEFAULT_EPOCH_DURATION_SECS: u64 = 86_400; // 1 day

fn is_not_expired(now: i64, exp: i64, skew_secs: i64) -> bool {
    // Verifier rejects when now > exp + skew
    now <= exp + skew_secs
}

fn is_future_exp_valid(now: i64, exp: i64, token_ttl_sec: u64, skew_secs: i64) -> bool {
    // Verifier rejects when exp > now + ttl + skew
    exp <= now + token_ttl_sec as i64 + skew_secs
}

fn current_epoch_from_ts(ts: u64, epoch_duration_sec: u64) -> u32 {
    (ts / epoch_duration_sec) as u32
}

fn is_epoch_valid(epoch: u32, now_ts: u64, epoch_duration_sec: u64, retention: u32) -> bool {
    let current = current_epoch_from_ts(now_ts, epoch_duration_sec);
    let min_valid = current.saturating_sub(retention);
    epoch >= min_valid && epoch <= current
}

#[test]
fn expiration_boundary_with_clock_skew() {
    let now = 1_700_000_000i64;
    let skew = DEFAULT_MAX_CLOCK_SKEW_SECS;

    // Exactly at boundary should be accepted.
    assert!(is_not_expired(now, now - skew, skew));
    // One second beyond boundary should be rejected.
    assert!(!is_not_expired(now, now - skew - 1, skew));
    // Clearly in future should be accepted by expiration check itself.
    assert!(is_not_expired(now, now + 60, skew));
}

#[test]
fn future_expiration_sanity_boundary() {
    let now = 1_700_000_000i64;
    let ttl = 600u64; // 10 minutes
    let skew = DEFAULT_MAX_CLOCK_SKEW_SECS;

    // Exactly max expected boundary should be accepted.
    let max_allowed = now + ttl as i64 + skew;
    assert!(is_future_exp_valid(now, max_allowed, ttl, skew));
    // One second too far in future should be rejected.
    assert!(!is_future_exp_valid(now, max_allowed + 1, ttl, skew));
}

#[test]
fn epoch_retention_window_boundaries() {
    let now_ts = 1_700_000_000u64;
    let epoch_duration = DEFAULT_EPOCH_DURATION_SECS;
    let retention = 2u32;
    let current = current_epoch_from_ts(now_ts, epoch_duration);

    // Valid set: [current-retention, current]
    assert!(is_epoch_valid(current, now_ts, epoch_duration, retention));
    assert!(is_epoch_valid(current - 1, now_ts, epoch_duration, retention));
    assert!(is_epoch_valid(current - 2, now_ts, epoch_duration, retention));

    // Below retention floor should be rejected.
    assert!(!is_epoch_valid(current - 3, now_ts, epoch_duration, retention));
    // Future epochs should be rejected.
    assert!(!is_epoch_valid(current + 1, now_ts, epoch_duration, retention));
}

#[test]
fn epoch_saturating_sub_behavior_at_zero() {
    // At very early timestamps, current epoch can be 0 and min_valid must saturate to 0.
    let now_ts = 1u64;
    let retention = 10u32;
    let current = current_epoch_from_ts(now_ts, DEFAULT_EPOCH_DURATION_SECS);
    assert_eq!(current, 0);

    assert!(is_epoch_valid(0, now_ts, DEFAULT_EPOCH_DURATION_SECS, retention));
    assert!(!is_epoch_valid(1, now_ts, DEFAULT_EPOCH_DURATION_SECS, retention));
}
