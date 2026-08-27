//! Reverse interop test: Rust Store::open("/tmp/shared2.db") writes, Go Store Open reads same file.
//! Mirrors forward_shared_db but opposite direction. Ensures seedDefaults INSERT OR IGNORE.

#![cfg(feature = "external-go-interop")]

use std::process::Command;
use veil_forum::store::Store;

const DB_PATH: &str = "/tmp/shared2.db";

#[tokio::test]
async fn reverse_rust_writes_go_reads_file_db() -> anyhow::Result<()> {
    // Ensure clean for deterministic run — caller may have cleaned via Rust writer, but we ensure fresh
    let _ = std::fs::remove_file(DB_PATH);
    let _ = std::fs::remove_file(format!("{}-wal", DB_PATH));
    let _ = std::fs::remove_file(format!("{}-shm", DB_PATH));
    // 1. Run Rust writer example (creates rows via Rust APIs into /tmp/shared2.db)
    // Using cargo run --example ensures same Store::open path as spec
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args([
            "run",
            "--manifest-path",
            &format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR")),
            "--example",
            "reverse_interop",
            "--",
            DB_PATH,
        ])
        .output()
        .expect("cargo run reverse_interop");
    println!("Rust stdout:\n{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("Rust stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "Rust reverse writer failed");

    // Parse SUMMARY for ids (optional, but we also query DB directly in Go verifier)
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let summary = stdout
        .lines()
        .find(|l| l.starts_with("SUMMARY"))
        .expect("SUMMARY missing");
    assert!(
        summary.contains("uid1=1") || summary.contains("uid1="),
        "SUMMARY malformed"
    );

    assert!(
        std::path::Path::new(DB_PATH).exists(),
        "DB file not created"
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 2. Verify via Rust itself that rows exist (first direction: Rust can read what it wrote, and second Rust open not clobber)
    let store = Store::open(DB_PATH).await?;
    let u1 = store
        .get_user_by_username("reverse_user")
        .await?
        .expect("reverse_user missing");
    assert_eq!(u1.password_hash, "hash_reverse_user");
    let site = store.get_config("site_name").await?.expect("site_name");
    assert_eq!(
        site, "reverse-custom-site",
        "Rust second open must preserve custom site_name"
    );
    drop(store);

    // 3. Run Go verifier: Go Open same file asserts reads via Go store query helpers
    let go_bin = std::env::var("VEIL_GO_BIN").unwrap_or_else(|_| "go".to_string());
    let go_project = std::env::var("VEIL_GO_PROJECT")
        .expect("VEIL_GO_PROJECT is required when external-go-interop is enabled");
    let go_out = Command::new(go_bin)
        .args(["run", "./cmd/reverse_interop", DB_PATH])
        .current_dir(go_project)
        .output()
        .expect("go run reverse_interop");
    println!("Go stdout:\n{}", String::from_utf8_lossy(&go_out.stdout));
    eprintln!("Go stderr:\n{}", String::from_utf8_lossy(&go_out.stderr));
    assert!(
        go_out.status.success(),
        "Go reverse verifier failed: {:?}",
        go_out.status
    );
    let go_stdout = String::from_utf8_lossy(&go_out.stdout);
    assert!(
        go_stdout.contains("Go reverse interop SUCCESS"),
        "Go verifier did not report SUCCESS"
    );

    // 4. Verify after Go second open, Rust can still read (Go did not clobber)
    let store3 = Store::open(DB_PATH).await?;
    let u1_again = store3
        .get_user_by_username("reverse_user")
        .await?
        .expect("after Go, reverse_user missing");
    assert_eq!(u1_again.username, "reverse_user");
    let site2 = store3.get_config("site_name").await?.unwrap();
    assert_eq!(
        site2, "reverse-custom-site",
        "Go second open must not clobber INSERT OR IGNORE"
    );
    let pow = store3.get_config("pow_register_minutes").await?.unwrap();
    assert_eq!(pow, "0.99");
    // Verify FTS still works after Go open
    let (hits, threads, total) = store3.search_posts("reverse", 1, 10).await?;
    assert!(total >= 1, "FTS after Go open total {}", total);
    assert!(!hits.is_empty());
    println!("Reverse interop SUCCESS (both directions, not clobber): users boards threads posts sessions invites verified");
    Ok(())
}

#[tokio::test]
async fn reverse_seed_defaults_insert_or_ignore() -> anyhow::Result<()> {
    // Isolated check: second open does not insert duplicate general board or overwrite configs
    let path = "/tmp/shared2-seedtest.db";
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path));
    let _ = std::fs::remove_file(format!("{}-shm", path));

    let s1 = Store::open(path).await?;
    // seed should have general
    let b = s1
        .get_board_by_slug("general")
        .await?
        .expect("general missing after first open");
    assert_eq!(b.slug, "general");
    s1.set_config("site_name", "custom_before_second").await?;
    s1.pool.close().await;

    let s2 = Store::open(path).await?;
    let site = s2.get_config("site_name").await?.unwrap();
    assert_eq!(
        site, "custom_before_second",
        "second Rust open clobbered site_name"
    );
    let b2 = s2
        .get_board_by_slug("general")
        .await?
        .expect("general missing after second open");
    assert_eq!(
        b2.id, b.id,
        "general board id changed on second open (duplicate insert?)"
    );
    // counts must still be 1
    let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boards WHERE slug='general'")
        .fetch_one(&s2.pool)
        .await?;
    assert_eq!(cnt.0, 1);
    let ccnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM configs WHERE key='site_name'")
        .fetch_one(&s2.pool)
        .await?;
    assert_eq!(ccnt.0, 1);
    s2.pool.close().await;
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path));
    let _ = std::fs::remove_file(format!("{}-shm", path));
    println!("seedDefaults INSERT OR IGNORE semantics verified for Rust-Rust second open");
    Ok(())
}
