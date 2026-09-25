//! Config semantics tests: GetConfig/SetConfig/GetAllConfigs.
//! Covers missing keys, empty values, UPSERT, GetAllConfigs, and concurrent SET.

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
        vec![1_i64, 2_i64, 3_i64, 4_i64],
        "baseline, TOTP, session digest, and anonymous identity migrations"
    );
    for (key, expected) in [
        ("reports_enabled", "1"),
        ("registration_pow_enabled", "1"),
        ("registration_invite_enabled", "1"),
        ("footer_text", ""),
    ] {
        assert_eq!(store.get_config(key).await?.as_deref(), Some(expected));
    }

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
    assert_eq!(count.0, 4, "re-running the migrator adds no rows");
    Ok(())
}

#[sqlx::test]
async fn set_config_concurrent_upsert(pool: PgPool) -> anyhow::Result<()> {
    // Concurrent UPSERTs of the same key: no lost writes, no errors, and the
    // final value is one of the written values. PostgreSQL serves these from
    // separate pool connections rather than serializing on a single writer.
    let store = config_store(pool).await?;
    let values: Vec<String> = (0..20).map(|i| format!("val_{i}")).collect();
    let mut handles = Vec::new();
    for v in values.clone() {
        let s = store.clone();
        let v2 = v.clone();
        handles.push(tokio::spawn(async move {
            s.set_config("concurrent_key", &v2).await
        }));
    }
    for h in handles {
        h.await.unwrap()?;
    }
    let final_val = store
        .get_config("concurrent_key")
        .await?
        .expect("concurrent_key must exist");
    assert!(values.contains(&final_val), "final {final_val} not in set");

    // Concurrent writes of different keys must all land.
    let mut handles2 = Vec::new();
    for i in 0..20 {
        let s = store.clone();
        handles2.push(tokio::spawn(async move {
            s.set_config(&format!("ck_{i}"), &format!("v{i}")).await
        }));
    }
    for h in handles2 {
        h.await.unwrap()?;
    }
    let all = store.get_all_configs().await?;
    for i in 0..20 {
        assert_eq!(all.get(&format!("ck_{i}")).unwrap(), &format!("v{i}"));
    }
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
