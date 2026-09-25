//! TOTP second factor (RFC 6238).
//!
//! The forum does not implement any of the cryptography itself: `totp-rs`
//! provides an RFC 6238 compliant implementation (verified against the
//! published test vectors in this module's tests) and `qrcode` renders the
//! enrolment QR code as inline SVG, so the no-JavaScript pages need neither an
//! external image nor a client-side script.
//!
//! Design decisions:
//!   * SHA-1, 6 digits, 30 second steps: the combination every authenticator app
//!     supports. HMAC-SHA-1 is not affected by the collision attacks that
//!     retired SHA-1 for signatures.
//!   * One step of clock skew is tolerated in both directions.
//!   * RFC 6238 codes must be accepted only once. The caller stores the last
//!     accepted step and passes it in, so a captured code cannot be replayed.
//!   * Recovery codes are 96 bits of randomness displayed as grouped hex. They
//!     are hashed with SHA-256 for storage because they are high entropy and are
//!     verified at login time.

use anyhow::Context;
use rand::Rng;
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Builder, Secret, Totp};

/// Digits in a generated code.
pub const DIGITS: u8 = 6;
/// Step duration in seconds.
pub const STEP_SECONDS: u64 = 30;
/// Accepted clock skew, in steps, in each direction.
pub const SKEW: u16 = 1;
/// Entropy of a fresh shared secret, in bytes.
const SECRET_BYTES: usize = 20;
/// How many recovery codes are issued at once.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Entropy of a single recovery code, in bytes.
const RECOVERY_CODE_BYTES: usize = 12;
/// Domain separation so a recovery code hash cannot collide with another use of
/// the same digest.
const RECOVERY_HASH_DOMAIN: &[u8] = b"veil-forum-totp-recovery-v1\0";

/// Outcome of checking a submitted code.
#[derive(Debug, PartialEq, Eq)]
pub enum CodeOutcome {
    /// The code is valid for this step and has not been used before.
    Accepted { step: u64 },
    /// The code is valid, but its step was already used (replay).
    Replayed,
    /// The code does not match any accepted step.
    Invalid,
}

fn build(secret_base32: &str, account: &str, issuer: &str) -> anyhow::Result<Totp> {
    let secret = Secret::try_from_base32(secret_base32.trim())
        .map_err(|e| anyhow::anyhow!("invalid TOTP secret: {e}"))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(SKEW)
        .with_step_duration(STEP_SECONDS)
        .with_secret(secret)
        .with_account_name(account)
        .with_issuer(Some(issuer))
        .build()
        .map_err(|e| anyhow::anyhow!("could not build TOTP: {e}"))
}

/// A fresh base32 shared secret for enrolment.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    Secret::new(bytes.to_vec().into_boxed_slice()).to_base32()
}

/// `otpauth://` URI for authenticator apps.
pub fn otpauth_url(secret_base32: &str, account: &str, issuer: &str) -> anyhow::Result<String> {
    build(secret_base32, account, issuer)?
        .to_url()
        .map_err(|e| anyhow::anyhow!("could not build otpauth URL: {e}"))
}

/// Render a URI as an inline SVG QR code. Inline SVG is markup, so the
/// restrictive CSP (`img-src data:`) does not apply and nothing is fetched.
pub fn qr_svg(uri: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(uri.as_bytes()).context("encode QR code")?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

/// Check a submitted code against the shared secret.
///
/// `last_step` is the highest step already accepted for this account, which
/// makes each code single use even inside its validity window.
pub fn verify_code(
    secret_base32: &str,
    account: &str,
    issuer: &str,
    code: &str,
    now: u64,
    last_step: Option<i64>,
) -> anyhow::Result<CodeOutcome> {
    let totp = build(secret_base32, account, issuer)?;
    let code = code.trim().replace(' ', "");
    match totp.check(&code, now) {
        None => Ok(CodeOutcome::Invalid),
        Some(step) => match last_step {
            Some(used) if step as i64 <= used => Ok(CodeOutcome::Replayed),
            _ => Ok(CodeOutcome::Accepted { step }),
        },
    }
}

/// The code an authenticator app would show at `time`.
///
/// Verification is the only production use of this module, so this exists for
/// the tests and for the enrolment walkthrough in the documentation.
pub fn code_at(
    secret_base32: &str,
    account: &str,
    issuer: &str,
    time: u64,
) -> anyhow::Result<String> {
    Ok(build(secret_base32, account, issuer)?
        .generate(time)
        .to_string())
}

/// Fresh recovery codes, displayed exactly once.
pub fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; RECOVERY_CODE_BYTES];
            rand::rng().fill_bytes(&mut bytes);
            let encoded = hex::encode(bytes);
            encoded
                .as_bytes()
                .chunks(4)
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<Vec<_>>()
                .join("-")
        })
        .collect()
}

/// Normalise user input: case and separators must not matter at verification
/// time, because people retype recovery codes by hand.
pub fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Hash a recovery code for storage.
pub fn hash_recovery_code(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_HASH_DOMAIN);
    hasher.update(normalize_recovery_code(input).as_bytes());
    hex::encode(hasher.finalize())
}

/// Does the input look like a recovery code rather than a 6 digit code?
pub fn looks_like_recovery_code(input: &str) -> bool {
    normalize_recovery_code(input).len() >= 16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference vectors detect interoperability and
    /// time-step calculation regressions that end-to-end happy paths can miss.
    #[test]
    fn matches_rfc6238_test_vectors() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(8)
            .with_skew(0)
            .with_step_duration(30)
            .with_secret(Secret::new_stack(*b"12345678901234567890"))
            .with_account_name("vector")
            .with_issuer(Some("veil-forum"))
            .build()
            .expect("build reference TOTP");
        for (time, expected) in [
            (59_u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(totp.generate(time).to_string(), expected, "T={time}");
        }
    }

    #[test]
    fn accepts_current_code_and_rejects_wrong_input() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let code = code_at(&secret, "alice", "veil-forum", now).expect("code");
        assert!(matches!(
            verify_code(&secret, "alice", "veil-forum", &code, now, None).unwrap(),
            CodeOutcome::Accepted { .. }
        ));
        assert_eq!(
            verify_code(&secret, "alice", "veil-forum", &code, now + 300, None).unwrap(),
            CodeOutcome::Invalid
        );
        for junk in ["", "not-a-code", "12345", "1234567", "abcdef"] {
            assert_eq!(
                verify_code(&secret, "alice", "veil-forum", junk, now, None).unwrap(),
                CodeOutcome::Invalid,
                "input {junk:?}"
            );
        }
    }

    #[test]
    fn tolerates_one_step_of_clock_skew() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let totp = build(&secret, "alice", "veil-forum").unwrap();
        let previous = totp.generate(now - STEP_SECONDS).to_string();
        let current = totp.generate(now).to_string();
        let next = totp.generate(now + STEP_SECONDS).to_string();
        let too_old = totp.generate(now - 3 * STEP_SECONDS).to_string();

        for code in [&previous, &current, &next] {
            assert!(matches!(
                verify_code(&secret, "alice", "veil-forum", code, now, None).unwrap(),
                CodeOutcome::Accepted { .. }
            ));
        }
        assert_eq!(
            verify_code(&secret, "alice", "veil-forum", &too_old, now, None).unwrap(),
            CodeOutcome::Invalid
        );
    }

    #[test]
    fn rejects_replayed_steps() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let totp = build(&secret, "alice", "veil-forum").unwrap();
        let current = totp.generate(now).to_string();
        let step = (now / STEP_SECONDS) as i64;

        // Accepted the first time, refused once the step is recorded as used.
        assert!(matches!(
            verify_code(&secret, "alice", "veil-forum", &current, now, None).unwrap(),
            CodeOutcome::Accepted { .. }
        ));
        assert_eq!(
            verify_code(&secret, "alice", "veil-forum", &current, now, Some(step)).unwrap(),
            CodeOutcome::Replayed
        );
        // A later step is still fine.
        let later = totp.generate(now + STEP_SECONDS).to_string();
        assert!(matches!(
            verify_code(
                &secret,
                "alice",
                "veil-forum",
                &later,
                now + STEP_SECONDS,
                Some(step)
            )
            .unwrap(),
            CodeOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn enrolment_material_is_scannable_and_renders_inline() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32, "20 bytes base32 without padding");
        let url = otpauth_url(&secret, "alice", "veil-forum").expect("url");
        assert!(url.starts_with("otpauth://totp/veil-forum:alice?secret="));
        assert!(url.contains("issuer=veil-forum"));
        let svg = qr_svg(&url).expect("qr");
        assert!(svg.contains("<svg"), "inline svg expected");
        assert!(!svg.contains("<script"));
    }

    #[test]
    fn recovery_codes_are_random_grouped_and_hash_stable() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), RECOVERY_CODE_COUNT, "codes must be unique");
        for code in &codes {
            assert_eq!(code.len(), 29, "12 bytes hex in 4 char groups");
            assert!(code.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        }
        // Hashing ignores case and separators.
        let first = &codes[0];
        let hash = hash_recovery_code(first);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_recovery_code(&first.to_uppercase()));
        assert_eq!(hash, hash_recovery_code(&first.replace('-', "")));
        assert_ne!(hash, hash_recovery_code(&codes[1]));
        assert!(looks_like_recovery_code(first));
        assert!(!looks_like_recovery_code("123456"));
    }
}
