//! Migration and config-storage semantics that the E2E suites cannot isolate.
//!
//! Default config values are asserted over real HTTP in
//! `tests/config_effects_e2e.rs`, and concurrent config writes are exercised by
//! the admin settings journeys, so neither is repeated here. What remains is
//! the persistence layer's own contract: the migrator must be versioned and
//! idempotent on every service start, and a storage failure must stay
//! distinguishable from a missing key.

use sqlx::PgPool;
use veil_forum::store::Store;

/// `sqlx::test` provisions a fresh database with migrations applied; first-run
/// defaults live in the store, so they are seeded explicitly here.
async fn config_store(pool: PgPool) -> anyhow::Result<Store> {
    let store = Store { pool };
    store.seed_defaults().await?;
    Ok(store)
}

#[sqlx::test]
async fn migrations_are_versioned_and_idempotent(pool: PgPool) -> anyhow::Result<()> {
    let store = config_store(pool).await?;
    // Every embedded migration is recorded exactly once. Keep this in step with
    // the files in migrations/.
    let applied: Vec<(i64,)> =
        sqlx::query_as("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&store.pool)
            .await?;
    assert_eq!(
        applied.iter().map(|v| v.0).collect::<Vec<_>>(),
        vec![1_i64, 2_i64, 3_i64, 4_i64, 5_i64],
        "baseline, TOTP, session digest, and anonymous identity migrations"
    );
    // Re-running the migrator must be a no-op: no duplicate markers and no data
    // loss. This is what happens on every service start.
    sqlx::query("INSERT INTO configs(key, value) VALUES('migration_test', 'preserved')")
        .execute(&store.pool)
        .await?;
    sqlx::migrate!("./migrations").run(&store.pool).await?;
    let value: (String,) = sqlx::query_as("SELECT value FROM configs WHERE key='migration_test'")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(value.0, "preserved");
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(count.0, 5, "re-running the migrator adds no rows");
    Ok(())
}

#[sqlx::test]
async fn get_config_db_error_vs_not_found_distinction(pool: PgPool) -> anyhow::Result<()> {
    let store = config_store(pool.clone()).await?;
    assert_eq!(store.get_config("no_such").await?, None);
    // Closing the pool makes the same call fail, which must stay
    // distinguishable from a missing key.
    pool.close().await;
    assert!(store.get_config("no_such").await.is_err());
    Ok(())
}
