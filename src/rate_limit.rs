use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota, RateLimiter};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use std::{num::NonZeroU32, sync::Arc};

type HmacSha256 = Hmac<Sha256>;

/// Process-local abuse controls. They intentionally keep no IP address, raw
/// session identifier, username, or durable client record.
#[derive(Clone)]
pub struct Limits {
    auth: Arc<DefaultDirectRateLimiter>,
    challenges: Arc<DefaultDirectRateLimiter>,
    posting: Arc<DefaultKeyedRateLimiter<String>>,
    key: Arc<[u8; 32]>,
}

impl Limits {
    pub fn new() -> Self {
        let mut key = [0; 32];
        rand::rng().fill_bytes(&mut key);
        Self {
            // Login and registration already require PoW. These global limits
            // bound concurrent abuse without creating client fingerprints.
            auth: Arc::new(RateLimiter::direct(Quota::per_minute(
                NonZeroU32::new(30).expect("nonzero quota"),
            ))),
            challenges: Arc::new(RateLimiter::direct(Quota::per_minute(
                NonZeroU32::new(120).expect("nonzero quota"),
            ))),
            // One burst plus one sustained post/minute per anonymous session
            // digest. Governor evicts idle keyed entries automatically.
            posting: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(1).expect("nonzero quota"),
            ))),
            key: Arc::new(key),
        }
    }

    pub fn allow_auth(&self) -> bool {
        self.auth.check().is_ok()
    }

    pub fn allow_challenge(&self) -> bool {
        self.challenges.check().is_ok()
    }

    pub fn allow_post(&self, session_id: Option<&str>) -> bool {
        let Some(session_id) = session_id else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref()).expect("fixed HMAC key");
        mac.update(session_id.as_bytes());
        let key = hex::encode(mac.finalize().into_bytes());
        self.posting.check_key(&key).is_ok()
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}
