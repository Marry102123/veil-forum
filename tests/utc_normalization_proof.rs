//! UTC normalization proof: for each offset variant (-05:00, -12:00, +00:00, +05:30, +08:00, Z)
//! assert with_timezone(&Utc) yields identical timestamp_nanos and to_rfc3339 Nanos Z string.
//! This fills the gap where existing tests only covered +08:00 and Z.

use chrono::{DateTime, SecondsFormat, Utc};
use veil_forum::store::parse_time;

// Canonical UTC instant used as ground truth for all variants.
const EXPECTED_NANOS: i64 = 123_456_789;
const EXPECTED_Z: &str = "2026-08-26T08:19:02.123456789Z";
const EXPECTED_Z_SECS: &str = "2026-08-26T08:19:02Z";

fn expected_utc() -> DateTime<Utc> {
    "2026-08-26T08:19:02.123456789Z"
        .parse::<DateTime<Utc>>()
        .unwrap()
}

fn assert_normalizes(input: &str, expected_z: &str) {
    // 1) direct chrono parse_from_rfc3339 + with_timezone
    let dt_fixed = DateTime::parse_from_rfc3339(input)
        .unwrap_or_else(|e| panic!("parse_from_rfc3339 failed for {:?}: {}", input, e));
    let utc = dt_fixed.with_timezone(&Utc);
    // explicit timestamp_nanos assertion
    assert_eq!(
        utc.timestamp_nanos_opt().unwrap(),
        expected_utc().timestamp_nanos_opt().unwrap(),
        "timestamp_nanos mismatch for {:?} -> {}",
        input,
        utc.to_rfc3339_opts(SecondsFormat::Nanos, true)
    );
    // explicit Nanos Z string assertion
    assert_eq!(
        utc.to_rfc3339_opts(SecondsFormat::Nanos, true),
        expected_z,
        "to_rfc3339 Nanos Z mismatch for {:?}",
        input
    );

    // 2) via parse_time wrapper (which internally does with_timezone(&Utc) or and_utc)
    let via_parse_time = parse_time(input);
    assert_eq!(
        via_parse_time.timestamp_nanos_opt().unwrap(),
        expected_utc().timestamp_nanos_opt().unwrap(),
        "parse_time timestamp_nanos mismatch for {:?}",
        input
    );
    assert_eq!(
        via_parse_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
        expected_z,
        "parse_time to_rfc3339 Nanos Z mismatch for {:?}",
        input
    );

    // 3) cross-check parse_time == direct with_timezone
    assert_eq!(
        via_parse_time.timestamp_nanos_opt().unwrap(),
        utc.timestamp_nanos_opt().unwrap(),
        "parse_time vs direct with_timezone nanos diverge for {:?}",
        input
    );
    assert_eq!(
        via_parse_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
        utc.to_rfc3339_opts(SecondsFormat::Nanos, true),
        "parse_time vs direct Z string diverge for {:?}",
        input
    );
}

// ---------------------------------------------------------------------------
// Per-variant explicit tests (each offset gets its own test for isolated failure)
// ---------------------------------------------------------------------------

#[test]
fn utc_normalization_z_variant() {
    let s = "2026-08-26T08:19:02.123456789Z";
    assert_normalizes(s, EXPECTED_Z);
    // also verify fractional nanos preserved
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        EXPECTED_NANOS
    );
}

#[test]
fn utc_normalization_plus00_variant() {
    let s = "2026-08-26T08:19:02.123456789+00:00";
    assert_normalizes(s, EXPECTED_Z);
}

#[test]
fn utc_normalization_plus00_vs_z_equivalence() {
    let z = parse_time("2026-08-26T08:19:02.123456789Z");
    let plus00 = parse_time("2026-08-26T08:19:02.123456789+00:00");
    // identical timestamp_nanos
    assert_eq!(
        z.timestamp_nanos_opt().unwrap(),
        plus00.timestamp_nanos_opt().unwrap(),
        "+00:00 vs Z timestamp_nanos must be identical"
    );
    // identical Z string
    assert_eq!(
        z.to_rfc3339_opts(SecondsFormat::Nanos, true),
        plus00.to_rfc3339_opts(SecondsFormat::Nanos, true)
    );
    assert_eq!(z.to_rfc3339_opts(SecondsFormat::Nanos, true), EXPECTED_Z);
    // also without nanos
    let z_secs = parse_time("2026-08-26T08:19:02Z");
    let plus00_secs = parse_time("2026-08-26T08:19:02+00:00");
    assert_eq!(
        z_secs.timestamp_nanos_opt().unwrap(),
        plus00_secs.timestamp_nanos_opt().unwrap()
    );
    assert_eq!(
        plus00_secs.to_rfc3339_opts(SecondsFormat::Nanos, true),
        "2026-08-26T08:19:02.000000000Z"
    );
    assert_eq!(
        z_secs.to_rfc3339_opts(SecondsFormat::Nanos, true),
        "2026-08-26T08:19:02.000000000Z"
    );
    // Secs format also Z
    assert_eq!(
        plus00_secs.to_rfc3339_opts(SecondsFormat::Secs, true),
        EXPECTED_Z_SECS
    );
}

#[test]
fn utc_normalization_plus08_variant() {
    let s = "2026-08-26T16:19:02.123456789+08:00";
    assert_normalizes(s, EXPECTED_Z);
}

#[test]
fn utc_normalization_plus0530_halfhour_variant() {
    let s = "2026-08-26T13:49:02.123456789+05:30";
    assert_normalizes(s, EXPECTED_Z);
    // verify half-hour math explicitly: 08:19 +05:30 = 13:49
    let dt = DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
    assert_eq!(dt.to_rfc3339_opts(SecondsFormat::Nanos, true), EXPECTED_Z);
}

#[test]
fn utc_normalization_minus05_variant() {
    let s = "2026-08-26T03:19:02.123456789-05:00";
    assert_normalizes(s, EXPECTED_Z);
}

#[test]
fn utc_normalization_minus12_variant() {
    // -12:00 is previous day 20:19
    let s = "2026-08-25T20:19:02.123456789-12:00";
    assert_normalizes(s, EXPECTED_Z);
}

// ---------------------------------------------------------------------------
// Cross-variant equivalence: all six representations must collapse to same instant
// ---------------------------------------------------------------------------

#[test]
fn utc_normalization_all_variants_identical() {
    let variants = [
        "2026-08-26T08:19:02.123456789Z",
        "2026-08-26T08:19:02.123456789+00:00",
        "2026-08-26T16:19:02.123456789+08:00",
        "2026-08-26T13:49:02.123456789+05:30",
        "2026-08-26T03:19:02.123456789-05:00",
        "2026-08-25T20:19:02.123456789-12:00",
    ];
    let expected = expected_utc();
    let expected_nanos = expected.timestamp_nanos_opt().unwrap();
    let expected_z = expected.to_rfc3339_opts(SecondsFormat::Nanos, true);

    for s in variants {
        let dt = DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        assert_eq!(
            dt.timestamp_nanos_opt().unwrap(),
            expected_nanos,
            "variant {:?} timestamp_nanos",
            s
        );
        assert_eq!(
            dt.to_rfc3339_opts(SecondsFormat::Nanos, true),
            expected_z,
            "variant {:?} Z string",
            s
        );
        let via = parse_time(s);
        assert_eq!(via.timestamp_nanos_opt().unwrap(), expected_nanos);
        assert_eq!(via.to_rfc3339_opts(SecondsFormat::Nanos, true), expected_z);
    }
    // also assert pairwise identical
    let parsed: Vec<DateTime<Utc>> = variants
        .iter()
        .map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
        .collect();
    for w in parsed.windows(2) {
        assert_eq!(
            w[0].timestamp_nanos_opt().unwrap(),
            w[1].timestamp_nanos_opt().unwrap()
        );
        assert_eq!(
            w[0].to_rfc3339_opts(SecondsFormat::Nanos, true),
            w[1].to_rfc3339_opts(SecondsFormat::Nanos, true)
        );
    }
}

// ---------------------------------------------------------------------------
// Without nanos (Secs) variants — prove truncation still normalizes to same wall time
// ---------------------------------------------------------------------------

#[test]
fn utc_normalization_secs_variants() {
    // All without fraction, expect 0 nanos and same Z second
    let variants = [
        ("2026-08-26T08:19:02Z", EXPECTED_Z_SECS),
        ("2026-08-26T08:19:02+00:00", EXPECTED_Z_SECS),
        ("2026-08-26T16:19:02+08:00", EXPECTED_Z_SECS),
        ("2026-08-26T13:49:02+05:30", EXPECTED_Z_SECS),
        ("2026-08-26T03:19:02-05:00", EXPECTED_Z_SECS),
        ("2026-08-25T20:19:02-12:00", EXPECTED_Z_SECS),
    ];
    for (s, exp_secs) in variants {
        let dt = DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        assert_eq!(dt.timestamp_nanos_opt().unwrap() % 1_000_000_000, 0);
        assert_eq!(dt.to_rfc3339_opts(SecondsFormat::Secs, true), exp_secs);
        // Nanos format pads zeros
        assert_eq!(
            dt.to_rfc3339_opts(SecondsFormat::Nanos, true),
            "2026-08-26T08:19:02.000000000Z"
        );
        let via = parse_time(s);
        assert_eq!(
            via.timestamp_nanos_opt().unwrap(),
            dt.timestamp_nanos_opt().unwrap()
        );
    }
}

// ---------------------------------------------------------------------------
// Go .UTC() equivalence note — documented via Rust with_timezone(&Utc) mirroring Go t.UTC()
// ---------------------------------------------------------------------------

#[test]
fn utc_normalization_go_utc_mirror() {
    // Go: t.UTC().Format(time.RFC3339Nano)  == Rust: dt.with_timezone(&Utc).to_rfc3339_opts(Nanos,true)
    // For each variant, simulate Go's t.UTC() by with_timezone and assert identical nanos + Z
    let cases = [
        "2026-08-26T03:19:02-05:00",
        "2026-08-25T20:19:02-12:00",
        "2026-08-26T08:19:02+00:00",
        "2026-08-26T13:49:02.123456789+05:30",
        "2026-08-26T16:19:02+08:00",
        "2026-08-26T08:19:02Z",
    ];
    for s in cases {
        let fixed = DateTime::parse_from_rfc3339(s).unwrap();
        let utc = fixed.with_timezone(&Utc); // mirrors Go t.UTC()
                                             // timestamp_nanos is timezone-agnostic — same instant
        assert_eq!(
            fixed.timestamp_nanos_opt().unwrap(),
            utc.timestamp_nanos_opt().unwrap()
        );
        // but formatted Z string only after with_timezone
        assert!(utc
            .to_rfc3339_opts(SecondsFormat::Nanos, true)
            .ends_with('Z'));
        assert!(utc
            .to_rfc3339_opts(SecondsFormat::Nanos, true)
            .contains("T08:19:02"));
    }
}
