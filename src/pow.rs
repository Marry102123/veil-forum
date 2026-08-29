use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type HmacSha256 = Hmac<Sha256>;
const DEFAULT_MINUTES: f64 = 0.02;
const MAX_MINUTES: f64 = 10.0;
const POW_DOMAIN: &[u8] = b"veil-forum-pow-v2";
const MAX_USED_CHALLENGES: usize = 10_000;

#[derive(Clone)]
pub struct Manager {
    hmac_key: Vec<u8>,
    used: Arc<Mutex<HashMap<String, i64>>>,
    store: crate::store::Store,
}

#[derive(Clone, Debug)]
pub enum Scope {
    Register,
    Post,
}
impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Post => "post",
        }
    }
    fn config_key(&self) -> &'static str {
        match self {
            Self::Register => "pow_register_minutes",
            Self::Post => "pow_post_minutes",
        }
    }
}

#[derive(serde::Serialize)]
pub struct Challenge {
    pub challenge: String,
    pub salt: String,
    pub difficulty: u32,
    pub expires_at: i64,
    pub hmac: String,
    pub scope: String,
}

pub fn minutes_to_difficulty(m: f64) -> u32 {
    let m = if m <= 0.0 { DEFAULT_MINUTES } else { m };
    let secs = m * 60.0;
    let rate = 10.0;
    let hashes = secs * rate;

    (hashes.max(1.0).log2().round() as i32).clamp(4, 24) as u32
}

impl Manager {
    pub fn new(store: crate::store::Store) -> Self {
        let mut k = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self {
            hmac_key: k,
            used: Arc::new(Mutex::new(HashMap::new())),
            store,
        }
    }
    async fn get_minutes(&self, s: &Scope) -> f64 {
        // 与 Go `v,err:=store.GetConfig` err→DefaultMinutes 一致：DB 错误也 fallback
        let v = self.store.get_config(s.config_key()).await.unwrap_or(None);
        if let Some(v) = v {
            if let Ok(f) = v.trim().parse::<f64>() {
                if f > 0.0 {
                    return f.min(MAX_MINUTES);
                }
            }
        }
        DEFAULT_MINUTES
    }
    pub async fn get_difficulty(&self, s: &Scope) -> u32 {
        minutes_to_difficulty(self.get_minutes(s).await)
    }
    pub async fn generate(&self, scope: Scope) -> Challenge {
        let diff = self.get_difficulty(&scope).await;
        let mut rb = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rb);
        let mut sb = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut sb);
        let ch = hex::encode(rb);
        let salt = hex::encode(sb);
        let exp = Utc::now().timestamp() + 300;
        let payload = format!("{}:{}:{}:{}:{}", ch, salt, diff, exp, scope.as_str());
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        mac.update(payload.as_bytes());
        let hmac = hex::encode(mac.finalize().into_bytes());
        Challenge {
            challenge: ch,
            salt,
            difficulty: diff,
            expires_at: exp,
            hmac,
            scope: scope.as_str().to_string(),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn verify(
        &self,
        scope: Scope,
        ch: &str,
        salt: &str,
        diff: u32,
        exp: i64,
        hmac_hex: &str,
        nonce: &str,
    ) -> anyhow::Result<()> {
        if Utc::now().timestamp() > exp {
            anyhow::bail!("challenge expired");
        }
        let payload = format!("{}:{}:{}:{}:{}", ch, salt, diff, exp, scope.as_str());
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        mac.update(payload.as_bytes());
        let provided = hex::decode(hmac_hex).map_err(|_| anyhow::anyhow!("invalid hmac"))?;
        if mac.verify_slice(&provided).is_err() {
            anyhow::bail!("hmac mismatch");
        }
        // 预占用防重放，短临界区，不跨 await
        {
            let mut used = self.used.lock().unwrap();
            if used.contains_key(hmac_hex) {
                anyhow::bail!("challenge already used");
            }
            let now = Utc::now().timestamp();
            used.retain(|_, e| *e >= now);
            if used.len() >= MAX_USED_CHALLENGES {
                if let Some(oldest) = used
                    .iter()
                    .min_by_key(|(_, expires_at)| **expires_at)
                    .map(|(key, _)| key.clone())
                {
                    used.remove(&oldest);
                }
            }
            used.insert(hmac_hex.to_string(), exp);
        }
        let cur = self.get_difficulty(&scope).await;
        if diff < cur {
            // 回滚预占用
            self.used.lock().unwrap().remove(hmac_hex);
            anyhow::bail!("difficulty too low: got {} want {}", diff, cur);
        }
        let mut hasher = Sha256::new();
        hasher.update(POW_DOMAIN);
        hasher.update(salt.as_bytes());
        hasher.update(ch.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();
        if !has_leading_zeros(&hash, diff) {
            self.used.lock().unwrap().remove(hmac_hex);
            anyhow::bail!("pow failed");
        }
        Ok(())
    }
}
fn has_leading_zeros(hash: &[u8], bits: u32) -> bool {
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    for &byte in hash.iter().take(full) {
        if byte != 0 {
            return false;
        }
    }
    if rem > 0 && hash[full] >> (8 - rem) != 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_is_bounded_and_monotonic() {
        assert_eq!(minutes_to_difficulty(0.0), 4);
        assert_eq!(minutes_to_difficulty(-1.0), 4);
        assert!(minutes_to_difficulty(0.02) < minutes_to_difficulty(1.0));
        assert_eq!(minutes_to_difficulty(10.0), 13);
        assert!(minutes_to_difficulty(1000.0) <= 24);
    }

    #[test]
    fn leading_zero_check_handles_bit_boundaries() {
        assert!(has_leading_zeros(&[0, 0, 0, 1], 24));
        assert!(!has_leading_zeros(&[0, 0, 1, 0], 24));
        assert!(has_leading_zeros(&[0b0000_1111], 4));
        assert!(!has_leading_zeros(&[0b0001_0000], 4));
    }
}
