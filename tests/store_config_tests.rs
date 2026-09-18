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
        vec![1_i64],
        "only the embedded baseline schema is applied"
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
    assert_eq!(count.0, 1, "re-running the migrator adds no rows");
    Ok(())
}

#[sqlx::test]
async fn get_config_missing_key_returns_none_not_error(pool: PgPool) -> anyhow::Result<()> {
    let store = config_store(pool).await?;
    let v = store.get_config("not_exist_key_12345").await?;
    assert_eq!(v, None, "a missing key must be Ok(None), not an error");
    assert_eq!(store.get_config_opt("not_exist_key_12345").await, None);
    Ok(())
}

#[sqlx::test]
async fn get_config_empty_value_roundtrip(pool: PgPool) -> anyhow::Result<()> {
    let store = config_store(pool).await?;
    // configs.value is NOT NULL, so an empty string must survive the round trip
    // through both the UPSERT and GetAllConfigs.
    store.set_config("empty_key", "").await?;
    let v = store.get_config("empty_key").await?;
    assert_eq!(v, Some("".to_string()));
    let all = store.get_all_configs().await?;
    assert_eq!(all.get("empty_key").unwrap(), "");
    store.set_config("empty_key", "nonempty").await?;
    assert_eq!(
        store.get_config("empty_key").await?,
        Some("nonempty".into())
    );
    store.set_config("empty_key", "").await?;
    assert_eq!(store.get_config("empty_key").await?, Some("".into()));
    Ok(())
}

#[sqlx::test]
async fn set_config_upsert_semantics(pool: PgPool) -> anyhow::Result<()> {
    let store = config_store(pool).await?;
    store.set_config("upsert_k", "v1").await?;
    assert_eq!(store.get_config("upsert_k").await?, Some("v1".into()));
    store.set_config("upsert_k", "v2").await?;
    assert_eq!(store.get_config("upsert_k").await?, Some("v2".into()));
    // Setting the same value twice must not error.
    store.set_config("upsert_k", "v2").await?;
    assert_eq!(store.get_config("upsert_k").await?, Some("v2".into()));
    // Seed defaults must remain overridable.
    store.set_config("site_name", "new_name").await?;
    assert_eq!(
        store.get_config("site_name").await?,
        Some("new_name".into())
    );
    let all = store.get_all_configs().await?;
    assert_eq!(all.get("upsert_k").unwrap(), "v2");
    assert_eq!(all.get("site_name").unwrap(), "new_name");
    Ok(())
}

#[sqlx::test]
async fn get_all_configs_contains_defaults_and_inserted(pool: PgPool) -> anyhow::Result<()> {
    let store = config_store(pool).await?;
    let all = store.get_all_configs().await?;
    for k in [
        "pow_register_minutes",
        "pow_post_minutes",
        "registration_mode",
        "site_name",
        "footer_text",
        "default_locale",
    ] {
        assert!(all.contains_key(k), "seed 缺失 {k}");
    }
    store.set_config("extra_a", "1").await?;
    store.set_config("extra_b", "2").await?;
    let all2 = store.get_all_configs().await?;
    assert_eq!(all2.get("extra_a").unwrap(), "1");
    assert_eq!(all2.get("extra_b").unwrap(), "2");
    assert!(all2.len() >= all.len() + 2);
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
