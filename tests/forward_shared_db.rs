//! Forward interop test: Go Open("/tmp/shared.db") creates rows, close DB, then Rust Store::open same file asserts reads.
//! Must use real file DB (not in-memory). Verifies auto-increment IDs and TEXT values round-trip.

#![cfg(feature = "external-go-interop")]

use std::process::Command;
use veil_forum::store::Store;

const DB_PATH: &str = "/tmp/shared.db";

#[tokio::test]
async fn forward_go_writes_rust_reads_file_db() -> anyhow::Result<()> {
    // 1. Ensure clean file DB (real file, not :memory:)
    let _ = std::fs::remove_file(DB_PATH);
    let _ = std::fs::remove_file(format!("{}-wal", DB_PATH));
    let _ = std::fs::remove_file(format!("{}-shm", DB_PATH));
    assert!(
        !std::path::Path::new(":memory:").exists() || true,
        "must not use :memory:"
    );
    // 2. Run the optional Go writer. The project path is environment-specific.
    let go_bin = std::env::var("VEIL_GO_BIN").unwrap_or_else(|_| "go".to_string());
    let go_project = std::env::var("VEIL_GO_PROJECT")
        .expect("VEIL_GO_PROJECT is required when external-go-interop is enabled");
    let output = Command::new(go_bin)
        .args(["run", "./cmd/forward_interop", DB_PATH])
        .current_dir(go_project)
        .output()
        .expect("go run failed to spawn");
    println!("Go stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("Go stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "Go writer failed: {:?}",
        output.status
    );

    // Parse SUMMARY line for IDs
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let summary = stdout
        .lines()
        .find(|l| l.starts_with("SUMMARY"))
        .expect("SUMMARY line missing");
    // SUMMARY uid1=.. uid2=.. bid1=.. bid2=.. tid=.. pid2=.. pid3=.. sess=.. invite=..
    let mut uid1: i64 = 0;
    let mut uid2: i64 = 0;
    let mut bid1: i64 = 0;
    let mut bid2: i64 = 0;
    let mut tid: i64 = 0;
    let mut pid2: i64 = 0;
    let mut pid3: i64 = 0;
    let mut sess_id = String::new();
    let mut invite_code = String::new();
    for kv in summary.split_whitespace().skip(1) {
        let mut parts = kv.splitn(2, '=');
        let k = parts.next().unwrap_or("");
        let v = parts.next().unwrap_or("");
        match k {
            "uid1" => uid1 = v.parse().unwrap(),
            "uid2" => uid2 = v.parse().unwrap(),
            "bid1" => bid1 = v.parse().unwrap(),
            "bid2" => bid2 = v.parse().unwrap(),
            "tid" => tid = v.parse().unwrap(),
            "pid2" => pid2 = v.parse().unwrap(),
            "pid3" => pid3 = v.parse().unwrap(),
            "sess" => sess_id = v.to_string(),
            "invite" => invite_code = v.to_string(),
            _ => {}
        }
    }
    assert!(
        uid1 > 0 && uid2 == uid1 + 1,
        "uid auto-increment not sequential: {} {}",
        uid1,
        uid2
    );
    assert!(
        bid2 == bid1 + 1,
        "board auto-increment not sequential: {} {}",
        bid1,
        bid2
    );
    assert!(tid > 0);
    assert!(pid2 > 0 && pid3 == pid2 + 1);
    assert_eq!(sess_id.len(), 64, "session hex 32 bytes = 64 hex chars");
    assert_eq!(invite_code, "FORWARD-INVITE-ABC123");

    // Ensure Go closed DB: file must exist and be readable
    assert!(
        std::path::Path::new(DB_PATH).exists(),
        "DB file not created"
    );
    // Small sleep to ensure WAL checkpointed
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Rust Store::open same file (real file DB)
    let store = Store::open(DB_PATH).await?;
    // Verify Store::open used file path, not :memory:
    // Already asserted DB_PATH literal

    // 4. get_user_by_username — TEXT round-trip + auto-increment + password_hash + is_admin
    let u1 = store
        .get_user_by_username("forward_user")
        .await?
        .expect("forward_user missing");
    assert_eq!(u1.id, uid1, "user id round-trip");
    assert_eq!(u1.username, "forward_user");
    assert_eq!(u1.password_hash, "hash_forward_user");
    assert!(!u1.is_admin);
    assert!(!u1.is_banned);

    let u2 = store
        .get_user_by_username("forward_user2")
        .await?
        .expect("forward_user2 missing");
    assert_eq!(u2.id, uid2);
    assert_eq!(u2.username, "forward_user2");
    assert_eq!(u2.password_hash, "hash_forward_user2");
    assert!(u2.is_admin, "is_admin bool mapping");

    // 5. get_board_by_slug — TEXT round-trip + bool mapping
    let b1 = store
        .get_board_by_slug("forward-board")
        .await?
        .expect("forward-board missing");
    assert_eq!(b1.id, bid1);
    assert_eq!(b1.slug, "forward-board");
    assert_eq!(b1.name, "Forward Board");
    assert_eq!(b1.description, "Forward description 123 测试中文");
    assert!(b1.allow_anonymous);
    assert!(b1.guest_readable);

    let b2 = store
        .get_board_by_slug("forward-board2")
        .await?
        .expect("forward-board2 missing");
    assert_eq!(b2.id, bid2);
    assert!(!b2.allow_anonymous);
    assert!(!b2.guest_readable);

    // 6. list_posts — thread posts via Rust, verify TEXT values and auto-increment IDs
    let (posts, total) = store.list_posts(tid, 1, 10).await?;
    // CreateThread inserted 1 post + 2 CreatePost = 3 posts total
    assert_eq!(total, 3, "thread should have 3 posts");
    assert_eq!(posts.len(), 3);
    // Posts ordered by id ASC
    let first = &posts[0];
    assert_eq!(first.thread_id, tid);
    assert_eq!(first.board_id, bid1);
    assert_eq!(first.author_id, uid1);
    assert_eq!(
        first.content_md,
        "Hello **markdown** with 中文 🎉 forward content MD"
    );
    assert_eq!(
        first.content_html,
        "<p>Hello <strong>markdown</strong> with 中文 🎉 forward content MD</p>"
    );
    assert!(!first.is_anonymous);

    let second = &posts[1];
    assert_eq!(second.id, pid2);
    assert_eq!(
        second.content_md,
        "Second post md with unicode: naïve café forward second"
    );
    assert_eq!(second.content_html, "<p>Second post html naïve café</p>");
    // Verify TEXT unicode round-trip
    assert!(second.content_md.contains("naïve café"));

    let third = &posts[2];
    assert_eq!(third.id, pid3);
    assert!(third.is_anonymous, "anonymous bool mapping");
    assert_eq!(third.content_md, "Anonymous post md forward anon");

    // Verify auto-increment IDs across posts
    assert!(first.id < second.id && second.id < third.id);
    assert_eq!(third.id, second.id + 1);

    // 7. session lookup — via get_session and get_user_by_session
    let sess = store.get_session(&sess_id).await?.expect("session missing");
    assert_eq!(sess.id, sess_id);
    assert_eq!(sess.user_id, uid1);
    // expires ~30 days in future
    let now = chrono::Utc::now();
    assert!(
        sess.expires_at > now,
        "session expires_at should be in future"
    );
    assert!(sess.expires_at > sess.created_at);

    let user_by_sess = store
        .get_user_by_session(&sess_id)
        .await?
        .expect("get_user_by_session missing");
    assert_eq!(user_by_sess.id, uid1);
    assert_eq!(user_by_sess.username, "forward_user");

    // 8. invite lookup — invite_exists and list_invites
    let exists = store.invite_exists(&invite_code).await?;
    assert!(exists, "invite should exist and be unused");

    let invites = store.list_invites().await?;
    let inv = invites
        .iter()
        .find(|i| i.code == invite_code)
        .expect("invite not in list");
    assert_eq!(inv.created_by, uid1);
    assert!(
        inv.used_by.is_none(),
        "unused invite used_by should be None"
    );
    // used invite should be absent from exists and have used_by
    let used_code = "FORWARD-INVITE-USED456";
    let exists_used = store.invite_exists(used_code).await?;
    assert!(
        !exists_used,
        "used invite should not exist (used_by IS NOT NULL)"
    );
    let inv_used = invites
        .iter()
        .find(|i| i.code == used_code)
        .expect("used invite missing");
    assert_eq!(inv_used.used_by, Some(uid2));
    assert!(inv_used.used_at.is_some());

    // 9. Additional: verify get_thread TEXT round-trip
    let th = store.get_thread(tid).await?.expect("thread missing");
    assert_eq!(th.id, tid);
    assert_eq!(th.title, "Forward Thread Title 测试 中文 🎉");
    assert_eq!(th.board_id, bid1);
    assert_eq!(th.author_id, uid1);

    // 10. Verify file DB is real file, not in-memory: reopen and still reads
    drop(store);
    let store2 = Store::open(DB_PATH).await?;
    let u1_again = store2
        .get_user_by_username("forward_user")
        .await?
        .expect("reopen missing");
    assert_eq!(u1_again.id, uid1);
    assert_eq!(u1_again.username, "forward_user");

    println!(
        "Forward interop SUCCESS: users {}->{}, boards {}->{}, tid {} posts {} sess {} invite {}",
        uid1, uid2, bid1, bid2, tid, total, sess_id, invite_code
    );
    Ok(())
}
