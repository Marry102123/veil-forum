//! Reverse interop writer: Rust Store::open("/tmp/shared2.db") creates rows via Rust APIs
//! Mirrors Go forward_interop but in opposite direction.

use sqlx::Row;
use veil_forum::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = "/tmp/shared2.db";
    if std::env::args().len() > 1 {
        // allow override but default is /tmp/shared2.db
    }
    let arg_path = std::env::args().nth(1).unwrap_or_else(|| path.to_string());
    let db_path = arg_path.as_str();

    // Clean leftover WAL/SHM handling is done by Store::open; but for determinism ensure fresh if caller wants
    // We do NOT auto-delete here when file exists, to test second-open clobber check later.
    // However if run in isolation, we clean previous reverse data so test is deterministic.
    // If file exists, we reuse it and clean prior reverse rows.

    let store = Store::open(db_path).await?;
    println!("Rust Store::open({}) ok", db_path);

    // Clean prior reverse data (deterministic rerun without deleting whole file)
    let _ = sqlx::query("DELETE FROM posts WHERE content_md LIKE 'reverse%' OR content_md LIKE 'Second reverse%' OR content_md LIKE 'Anonymous reverse%'").execute(&store.pool).await;
    let _ = sqlx::query("DELETE FROM threads WHERE title LIKE 'Reverse%'")
        .execute(&store.pool)
        .await;
    let _ = sqlx::query("DELETE FROM sessions WHERE id LIKE 'rev-sess-placeholder%'")
        .execute(&store.pool)
        .await;
    // We'll delete sessions created by previous run via searching for reverse users, but easier: delete by user later
    let _ = sqlx::query("DELETE FROM invite_codes WHERE code LIKE 'REVERSE-%'")
        .execute(&store.pool)
        .await;
    let _ = sqlx::query("DELETE FROM boards WHERE slug LIKE 'reverse-%'")
        .execute(&store.pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE username LIKE 'reverse_user%'")
        .execute(&store.pool)
        .await;
    // Need to cleanup sessions that may remain after user delete cascading? Do after.

    println!("cleaned leftover reverse rows");

    // 1. users
    let uid1 = store
        .create_user("reverse_user", "hash_reverse_user", false)
        .await?;
    let uid2 = store
        .create_user("reverse_user2", "hash_reverse_user2", true)
        .await?;
    println!("users: reverse_user id={} reverse_user2 id={}", uid1, uid2);
    assert_eq!(uid2, uid1 + 1, "auto-increment users not sequential");

    // 2. boards
    let bid1 = store
        .create_board(
            "reverse-board",
            "Reverse Board",
            "Reverse description 123 测试中文",
            true,
            true,
        )
        .await?;
    let bid2 = store
        .create_board(
            "reverse-board2",
            "Reverse Board2",
            "Second board desc",
            false,
            false,
        )
        .await?;
    println!(
        "boards: reverse-board id={} reverse-board2 id={}",
        bid1, bid2
    );
    assert_eq!(bid2, bid1 + 1);

    // Verify seedDefaults did not clobber: custom config test
    // Set a custom site_name that Go's second open must not overwrite (INSERT OR IGNORE semantics)
    store.set_config("site_name", "reverse-custom-site").await?;
    store.set_config("pow_register_minutes", "0.99").await?;
    println!("set_config site_name=reverse-custom-site pow_register_minutes=0.99");

    // Also store a marker to verify configs persist
    let all_before = store.get_all_configs().await?;
    println!("configs after Rust write: {:?}", all_before.keys());

    // 3. threads — creates thread + first post
    let tid = store
        .create_thread(
            bid1,
            uid1,
            "Reverse Thread Title 测试 中文 🎉",
            "Hello **markdown** with 中文 🎉 reverse content MD",
            "<p>Hello <strong>markdown</strong> with 中文 🎉 reverse content MD</p>",
            false,
        )
        .await?;
    println!("threads: id={} board={} author={}", tid, bid1, uid1);

    // 4. posts — second post via CreatePost, plus anonymous
    let pid2 = store
        .create_post(
            tid,
            bid1,
            uid1,
            false,
            "Second reverse post md with unicode: naïve café reverse second",
            "<p>Second reverse post html naïve café</p>",
        )
        .await?;
    println!("posts: second pid={} thread={}", pid2, tid);
    let pid3 = store
        .create_post(
            tid,
            bid1,
            uid2,
            true,
            "Anonymous reverse post md reverse anon",
            "<p>anon html</p>",
        )
        .await?;
    println!("posts: anon pid={}", pid3);

    // Verify reply_count bumped correctly (should be 2 after two CreatePost, thread started 0)
    let rc: (i64,) = sqlx::query_as("SELECT reply_count FROM threads WHERE id=?")
        .bind(tid)
        .fetch_one(&store.pool)
        .await?;
    println!("thread reply_count after 2 posts: {}", rc.0);
    assert_eq!(rc.0, 2);

    // 5. sessions
    let sess_id = store.create_session(uid1).await?;
    println!(
        "sessions: id={} user={} len={}",
        sess_id,
        uid1,
        sess_id.len()
    );
    assert_eq!(sess_id.len(), 64);

    // 6. invite_codes
    let invite_code = "REVERSE-INVITE-ABC123";
    store.create_invite(invite_code, uid1).await?;
    println!("invite: code={} created_by={}", invite_code, uid1);
    let invite_code2 = "REVERSE-INVITE-USED456";
    store.create_invite(invite_code2, uid1).await?;
    store.use_invite(invite_code2, uid2).await?;
    println!("invite used: code={} used_by={}", invite_code2, uid2);

    // Ensure WAL checkpoint
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&store.pool)
        .await;

    // Emit SUMMARY for Go verifier to parse
    println!(
        "SUMMARY uid1={} uid2={} bid1={} bid2={} tid={} pid2={} pid3={} sess={} invite={}",
        uid1, uid2, bid1, bid2, tid, pid2, pid3, sess_id, invite_code
    );

    // Capture ids for after-close verification via second Rust open (implicitly testing close)
    // Drop pool explicitly to close: need to close underlying pool
    store.pool.close().await;
    println!("Rust writer done, pool closed");

    // Verify second open does not clobber: reopen immediately in Rust and check configs still custom
    let store2 = Store::open(db_path).await?;
    let site = store2
        .get_config("site_name")
        .await?
        .expect("site_name missing after reopen");
    assert_eq!(
        site, "reverse-custom-site",
        "seedDefaults INSERT OR IGNORE clobbered custom site_name on second open!"
    );
    let pow = store2.get_config("pow_register_minutes").await?.unwrap();
    assert_eq!(pow, "0.99", "pow_register_minutes clobbered");
    let default_pow_login = store2.get_config("pow_login_minutes").await?.unwrap();
    assert_eq!(
        default_pow_login, "0.02",
        "default pow_login should still be 0.02"
    );
    // verify board count and users still present
    let cnt: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE username LIKE 'reverse_user%'")
            .fetch_one(&store2.pool)
            .await?;
    assert_eq!(cnt.0, 2);
    let bcnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boards WHERE slug LIKE 'reverse-%'")
        .fetch_one(&store2.pool)
        .await?;
    assert_eq!(bcnt.0, 2);
    // verify configs not duplicated
    let cfgcnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM configs WHERE key='site_name'")
        .fetch_one(&store2.pool)
        .await?;
    assert_eq!(cfgcnt.0, 1, "site_name should have exactly 1 row");
    println!(
        "Rust second open verified no clobber: site_name={} pow={}",
        site, pow
    );
    store2.pool.close().await;

    Ok(())
}
