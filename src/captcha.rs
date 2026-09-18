//! Self-hosted, single-use image CAPTCHA challenges.
//!
//! Image rendering is delegated to the maintained `captcha` crate. This
//! module owns challenge binding, expiry, attempt limits, and replay safety.
use captcha::filters::{Dots, Noise};
use captcha::Captcha;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type HmacSha256 = Hmac<Sha256>;
const TTL_SECONDS: i64 = 300;
const MAX_ATTEMPTS: u8 = 5;
const MAX_CHALLENGES: usize = 10_000;
// Every character exists in captcha's embedded font. Exclude lookalikes such
// as I/1, O/0, and S/5 so Tor users can solve a challenge without guesswork.
const HUMAN_CHARS: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', '2', '3', '4', '6', '7', '8', '9',
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Difficulty {
    Low,
    Medium,
    High,
}

impl Difficulty {
    pub fn from_config(value: Option<String>) -> Self {
        match value.as_deref() {
            Some("high") => Self::High,
            Some("medium") => Self::Medium,
            _ => Self::Low,
        }
    }

    fn parameters(self) -> (u32, f32, u32, u32) {
        match self {
            // characters, noise density, dots, wave amplitude
            Self::Low => (5, 0.035, 3, 0),
            Self::Medium => (5, 0.08, 8, 5),
            Self::High => (6, 0.13, 14, 9),
        }
    }
}

/// Render one challenge image and return the text it shows, so the properties
/// of the puzzle (length, alphabet, answer space) can be asserted by tests.
fn render_challenge(difficulty: Difficulty) -> (String, String) {
    let (characters, noise, dots, wave_amplitude) = difficulty.parameters();
    let mut captcha = Captcha::new();
    captcha
        .set_chars(HUMAN_CHARS)
        .add_chars(characters)
        .view(240, 80)
        .apply_filter(Noise::new(noise))
        .apply_filter(Dots::new(dots));
    if wave_amplitude > 0 {
        captcha.apply_filter(captcha::filters::Wave::new(1.0, wave_amplitude as f64).horizontal());
    }
    (
        captcha.chars_as_string().to_ascii_uppercase(),
        captcha.as_base64().unwrap_or_default(),
    )
}

#[derive(Clone)]
pub struct Manager {
    key: [u8; 32],
    challenges: Arc<Mutex<HashMap<String, ChallengeRecord>>>,
}

struct ChallengeRecord {
    scope: String,
    expires_at: i64,
    answer_mac: Vec<u8>,
    attempts: u8,
}

pub struct Challenge {
    pub image_base64: String,
    pub id: String,
    pub expires_at: i64,
    pub token: String,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self {
            key,
            challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn generate(&self, scope: crate::pow::Scope, difficulty: Difficulty) -> Challenge {
        let (answer, image_base64) = render_challenge(difficulty);
        let mut raw_id = [0u8; 16];
        rand::rng().fill_bytes(&mut raw_id);
        let id = hex::encode(raw_id);
        let expires_at = Utc::now().timestamp() + TTL_SECONDS;
        let scope = scope.as_str().to_string();
        let answer_mac = self.answer_mac(&scope, &id, expires_at, &answer);
        let token = self.challenge_token(&scope, &id, expires_at);
        let mut challenges = self.challenges.lock().unwrap_or_else(|p| p.into_inner());
        let now = Utc::now().timestamp();
        challenges.retain(|_, value| value.expires_at >= now);
        if challenges.len() >= MAX_CHALLENGES {
            if let Some(oldest) = challenges
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone())
            {
                challenges.remove(&oldest);
            }
        }
        challenges.insert(
            id.clone(),
            ChallengeRecord {
                scope,
                expires_at,
                answer_mac,
                attempts: 0,
            },
        );
        Challenge {
            image_base64,
            id,
            expires_at,
            token,
        }
    }

    pub fn verify(
        &self,
        scope: crate::pow::Scope,
        id: &str,
        expires_at: i64,
        token: &str,
        answer: &str,
    ) -> anyhow::Result<()> {
        if id.len() != 32
            || !id.chars().all(|c| c.is_ascii_hexdigit())
            || answer.is_empty()
            || answer.len() > 16
        {
            anyhow::bail!("invalid captcha fields");
        }
        let scope = scope.as_str();
        let now = Utc::now().timestamp();
        if expires_at < now || expires_at > now + TTL_SECONDS {
            anyhow::bail!("captcha expired");
        }
        let provided = hex::decode(token).map_err(|_| anyhow::anyhow!("invalid captcha token"))?;
        HmacSha256::new_from_slice(&self.key)
            .expect("fixed key")
            .chain_update(format!("veil-forum-captcha-v1:{scope}:{id}:{expires_at}").as_bytes())
            .verify_slice(&provided)
            .map_err(|_| anyhow::anyhow!("captcha token mismatch"))?;
        let mut challenges = self.challenges.lock().unwrap_or_else(|p| p.into_inner());
        let record = challenges
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("captcha missing or already used"))?;
        if record.scope != scope || record.expires_at != expires_at || record.expires_at < now {
            challenges.remove(id);
            anyhow::bail!("captcha expired");
        }
        let candidate = self.answer_mac(scope, id, expires_at, &answer.to_ascii_uppercase());
        let correct = constant_time_eq(&candidate, &record.answer_mac);
        if !correct {
            let record = challenges
                .get_mut(id)
                .expect("existing challenge remains present");
            record.attempts += 1;
            let exhausted = record.attempts >= MAX_ATTEMPTS;
            if exhausted {
                challenges.remove(id);
            }
            anyhow::bail!("captcha answer incorrect");
        }
        challenges.remove(id);
        Ok(())
    }

    fn answer_mac(&self, scope: &str, id: &str, expires_at: i64, answer: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("fixed key");
        mac.update(
            format!(
                "answer:{scope}:{id}:{expires_at}:{}",
                answer.to_ascii_uppercase()
            )
            .as_bytes(),
        );
        mac.finalize().into_bytes().to_vec()
    }
    fn challenge_token(&self, scope: &str, id: &str, expires_at: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("fixed key");
        mac.update(format!("veil-forum-captcha-v1:{scope}:{id}:{expires_at}").as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The challenge has to stay expensive to guess. This guards a real
    /// regression: an arithmetic challenge with two small operands has an answer
    /// space of about twenty, which a script defeats within its five attempts.
    #[test]
    fn challenge_answer_space_stays_wide() {
        for difficulty in [Difficulty::Low, Difficulty::Medium, Difficulty::High] {
            let length = match difficulty {
                Difficulty::High => 6,
                Difficulty::Low | Difficulty::Medium => 5,
            };
            let mut seen = std::collections::HashSet::new();
            for _ in 0..200 {
                let (answer, image) = render_challenge(difficulty);
                assert_eq!(answer.chars().count(), length, "answer was {answer}");
                assert!(
                    answer.chars().all(|c| HUMAN_CHARS.contains(&c)),
                    "answer {answer} left the human-readable alphabet"
                );
                assert!(!image.is_empty(), "the challenge image must render");
                seen.insert(answer);
            }
            let space = (HUMAN_CHARS.len() as f64).powi(length as i32);
            assert!(space >= 1e7, "answer space of {space:.0} is too small");
            assert!(
                seen.len() >= 195,
                "only {} distinct answers in 200 draws",
                seen.len()
            );
        }
    }

    #[test]
    fn generated_challenge_is_scoped_signed_and_single_use() {
        let manager = Manager::new();
        let challenge = manager.generate(crate::pow::Scope::Login, Difficulty::Low);
        assert!(!challenge.image_base64.is_empty());
        assert!(manager
            .verify(
                crate::pow::Scope::Post,
                &challenge.id,
                challenge.expires_at,
                &challenge.token,
                "wrong",
            )
            .is_err());
        // The invalid scope must not consume a valid challenge.
        let challenges = manager.challenges.lock().unwrap_or_else(|p| p.into_inner());
        assert!(challenges.contains_key(&challenge.id));
    }

    #[test]
    fn answer_mac_comparison_is_case_insensitive() {
        let manager = Manager::new();
        let id = "a".repeat(32);
        let expires_at = Utc::now().timestamp() + TTL_SECONDS;
        assert_eq!(
            manager.answer_mac("login", &id, expires_at, "ABC123"),
            manager.answer_mac("login", &id, expires_at, "abc123")
        );
    }
}
