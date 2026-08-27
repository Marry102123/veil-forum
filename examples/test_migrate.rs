use sqlx::{Row, SqlitePool};
use veil_forum::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // test 1: :memory: double open / double migrate via Store::open
    let s = Store::open(":memory:").await?;
    // verify columns exist
    let rows = sqlx::query("PRAGMA table_info(users)")
        .fetch_all(&s.pool)
        .await?;
    let has_locale = rows.iter().any(|r| r.get::<String, _>("name") == "locale");
    println!("has_locale after first migrate: {}", has_locale);
    assert!(has_locale, "locale column missing after 001+002");

    let rows2 = sqlx::query("PRAGMA table_info(boards)")
        .fetch_all(&s.pool)
        .await?;
    let has_ni18n = rows2
        .iter()
        .any(|r| r.get::<String, _>("name") == "name_i18n");
    println!("has_name_i18n after first migrate: {}", has_ni18n);
    assert!(has_ni18n);

    let cfg: Option<(String,)> =
        sqlx::query_as("SELECT value FROM configs WHERE key='default_locale'")
            .fetch_optional(&s.pool)
            .await?;
    println!("default_locale: {:?}", cfg);
    assert_eq!(cfg.unwrap().0, "zh");

    // idempotency: call migrate again via reopening same in-memory? For file we test duplicate
    // Instead simulate second migrate by executing same SQL again with our logic: run raw queries that should not error
    // We call Store::open again on same memory won't share, so test file DB
    let path = "/tmp/secure_forum_test_migrate.db";
    let _ = std::fs::remove_file(path);
    let s1 = Store::open(path).await?;
    println!("first file open ok");
    // second open on same file should be idempotent (calls migrate again)
    let s2 = Store::open(path).await?;
    println!("second file open ok (idempotent)");
    // third: directly re-execute 002 statements to ensure OR IGNORE / duplicate handling
    // Do duplicate inserts
    sqlx::query("INSERT OR IGNORE INTO configs(key,value) VALUES('default_locale','zh')")
        .execute(&s2.pool)
        .await?;
    println!("duplicate INSERT OR IGNORE ok");
    // duplicate ALTER should be ignored by our migrate but raw ALTER would error – test that we handle it
    let res = sqlx::query("ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT 'zh'")
        .execute(&s2.pool)
        .await;
    println!(
        "raw duplicate ALTER error (expected): {:?}",
        res.err().map(|e| e.to_string())
    );

    // Verify that repeated Store::open doesn't corrupt data
    let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM configs WHERE key='default_locale'")
        .fetch_one(&s2.pool)
        .await?;
    println!("default_locale count (should be 1): {}", cnt.0);
    assert_eq!(cnt.0, 1);

    // Verify that 001 IF NOT EXISTS still works on second run
    let s3 = Store::open(path).await?;
    println!("third open ok");
    let _ = std::fs::remove_file(path);
    println!("ALL MIGRATE IDEMPOTENCY CHECKS PASSED");
    Ok(())
}
