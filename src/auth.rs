use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(64 * 1024, 3, 4, Some(32)).unwrap(),
    );
    let hash = argon2
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .to_string();
    Ok(hash)
}
pub fn verify_password(hash: &str, pw: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(pw.as_bytes(), &parsed)
        .is_ok()
}
pub async fn ensure_admin(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    if cnt.0 != 0 {
        return Ok(());
    }
    let password = std::env::var("VEIL_ADMIN_PASSWORD").map_err(|_| {
        anyhow::anyhow!("empty database requires VEIL_ADMIN_PASSWORD for first administrator setup")
    })?;
    if password.chars().count() < 12 || password.chars().count() > 128 {
        anyhow::bail!("VEIL_ADMIN_PASSWORD must contain 12-128 characters");
    }
    let h = hash_password(&password)?;
    sqlx::query("INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,1,?)")
        .bind("admin")
        .bind(h)
        .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .execute(pool)
        .await?;
    Ok(())
}
