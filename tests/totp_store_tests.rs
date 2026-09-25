//! Store-level tests for the TOTP second factor: enrolment, recovery codes, and
//! the pending-login window between the password step and the code.

use sqlx::PgPool;
use veil_forum::store::{Store, PENDING_LOGIN_MAX_ATTEMPTS};
use veil_forum::totp;

async fn fixture(pool: PgPool) -> anyhow::Result<(Store, i64)> {
    let store = Store { pool };
    store.seed_defaults().await?;
    let user_id = store.create_user("alice", "hash", false).await?;
    Ok((store, user_id))
}

async fn hash_all(codes: &[String]) -> Vec<String> {
    codes
        .iter()
        .map(|code| totp::hash_recovery_code(code))
        .collect()
}

#[sqlx::test]
async fn enrolment_activates_only_after_confirmation(pool: PgPool) -> anyhow::Result<()> {
    let (store, user_id) = fixture(pool).await?;
    let secret = totp::generate_secret();

    // A pending secret must not count as an active second factor.
    store.set_totp_pending(user_id, &secret).await?;
    let state = store.totp_state(user_id).await?;
    assert!(!state.is_active(), "pending enrolment is not active");
    assert_eq!(state.pending_secret.as_deref(), Some(secret.as_str()));
    assert_eq!(state.unused_recovery_codes, 0);

    let codes = totp::generate_recovery_codes();
    store.activate_totp(user_id, &secret, 56_666_666).await?;
    store
        .replace_recovery_codes(user_id, &hash_all(&codes).await)
        .await?;

    let state = store.totp_state(user_id).await?;
    assert!(state.is_active());
    assert_eq!(state.secret.as_deref(), Some(secret.as_str()));
    assert_eq!(state.pending_secret, None, "pending state is cleared");
    assert_eq!(state.last_step, Some(56_666_666));
    assert_eq!(state.unused_recovery_codes, codes.len() as i64);
    Ok(())
}

#[sqlx::test]
async fn recovery_codes_are_single_use(pool: PgPool) -> anyhow::Result<()> {
    let (store, user_id) = fixture(pool).await?;
    let codes = totp::generate_recovery_codes();
    let hashes = hash_all(&codes).await;
    store.replace_recovery_codes(user_id, &hashes).await?;
    assert_eq!(
        store.totp_state(user_id).await?.unused_recovery_codes,
        codes.len() as i64
    );

    let first = totp::hash_recovery_code(&codes[0]);
    assert!(store.consume_recovery_code(user_id, &first).await?);
    assert!(
        !store.consume_recovery_code(user_id, &first).await?,
        "a recovery code must not work twice"
    );
    assert_eq!(
        store.totp_state(user_id).await?.unused_recovery_codes,
        codes.len() as i64 - 1
    );

    // Case and separators must not matter.
    let loose = codes[1].to_uppercase().replace('-', " ");
    // An unknown code is rejected, and codes belonging to another account do
    // not leak across users.
    assert!(
        store
            .consume_recovery_code(user_id, &totp::hash_recovery_code(&loose))
            .await?
    );
    assert!(
        !store
            .consume_recovery_code(user_id, &totp::hash_recovery_code("0000-0000-0000"))
            .await?
    );
    let other = store.create_user("bob", "hash", false).await?;
    assert!(!store.consume_recovery_code(other, &first).await?);

    // Regenerating invalidates the previous set.
    let fresh = totp::generate_recovery_codes();
    store
        .replace_recovery_codes(user_id, &hash_all(&fresh).await)
        .await?;
    assert_eq!(
        store.totp_state(user_id).await?.unused_recovery_codes,
        fresh.len() as i64
    );
    assert!(
        !store
            .consume_recovery_code(user_id, &totp::hash_recovery_code(&codes[2]))
            .await?
    );
    Ok(())
}

#[sqlx::test]
async fn pending_login_is_short_lived_and_single_use(pool: PgPool) -> anyhow::Result<()> {
    let (store, user_id) = fixture(pool).await?;
    let id = store.create_pending_login(user_id).await?;
    let pending = store
        .pending_login(&id)
        .await?
        .expect("usable pending login");
    assert_eq!(pending.user_id, user_id);
    assert_eq!(pending.attempts, 0);
    assert!(pending.expires_at > pending.created_at);

    // Unknown ids are not usable.
    assert!(store.pending_login("deadbeef").await?.is_none());

    // Consuming is single use and bound to the user.
    let other = store.create_user("bob", "hash", false).await?;
    assert!(!store.consume_pending_login(&id, other).await?);
    assert!(store.consume_pending_login(&id, user_id).await?);
    assert!(!store.consume_pending_login(&id, user_id).await?);
    assert!(store.pending_login(&id).await?.is_none());

    // Attempts are capped, after which the pending login is unusable.
    let id = store.create_pending_login(user_id).await?;
    for expected in 1..=PENDING_LOGIN_MAX_ATTEMPTS {
        assert_eq!(store.fail_pending_login(&id).await?, expected);
    }
    assert!(
        store.pending_login(&id).await?.is_none(),
        "too many failed attempts must invalidate the pending login"
    );
    Ok(())
}

#[sqlx::test]
async fn expired_pending_logins_are_rejected_and_cleaned(pool: PgPool) -> anyhow::Result<()> {
    let (store, user_id) = fixture(pool).await?;
    let id = store.create_pending_login(user_id).await?;
    let digest = veil_forum::auth::digest_token(&id);
    // Backdate the expiry instead of waiting five minutes.
    sqlx::query("UPDATE pending_logins SET expires_at = $1 WHERE id = $2")
        .bind(chrono::Utc::now() - chrono::Duration::seconds(1))
        .bind(&digest)
        .execute(&store.pool)
        .await?;
    assert!(store.pending_login(&id).await?.is_none());
    assert!(store.delete_expired_pending_logins().await? >= 1);

    // Creating a new pending login also clears that user's stale rows.
    let first = store.create_pending_login(user_id).await?;
    let first_digest = veil_forum::auth::digest_token(&first);
    sqlx::query("UPDATE pending_logins SET expires_at = $1 WHERE id = $2")
        .bind(chrono::Utc::now() - chrono::Duration::seconds(1))
        .bind(&first_digest)
        .execute(&store.pool)
        .await?;
    let second = store.create_pending_login(user_id).await?;
    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_logins WHERE user_id=$1")
        .bind(user_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(remaining.0, 1, "only the fresh pending login remains");
    assert_eq!(
        store.pending_login(&second).await?.unwrap().user_id,
        user_id
    );
    Ok(())
}

#[sqlx::test]
async fn disabling_removes_secret_and_recovery_codes(pool: PgPool) -> anyhow::Result<()> {
    let (store, user_id) = fixture(pool).await?;
    let secret = totp::generate_secret();
    store.set_totp_pending(user_id, &secret).await?;
    store.activate_totp(user_id, &secret, 1).await?;
    store
        .replace_recovery_codes(user_id, &hash_all(&totp::generate_recovery_codes()).await)
        .await?;

    store.disable_totp(user_id).await?;
    let state = store.totp_state(user_id).await?;
    assert!(!state.is_active());
    assert_eq!(state.secret, None);
    assert_eq!(state.last_step, None);
    assert_eq!(state.pending_secret, None);
    assert_eq!(state.unused_recovery_codes, 0);

    // Disabling twice is harmless.
    store.disable_totp(user_id).await?;
    Ok(())
}
