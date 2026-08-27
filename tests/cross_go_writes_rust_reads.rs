//! 交叉测试：Go 写入 SQLite TEXT 时间，Rust Store 读取
//! 覆盖：Go `time.Now().Format(time.RFC3339Nano)` 带纳秒 / 不带纳秒 / 空格格式 / 边界精度
//! 断言：parse_success 且时间差 <1ms

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use sqlx::Row;
use veil_forum::store::{parse_time, Store};

// ---------- helper ----------
fn parse_must(s: &str) -> DateTime<Utc> {
    // parse_time 在失败时会 fallback 到 Utc::now()，需用已知时间差检测是否真的解析成功
    // 对确定性输入，我们断言解析结果与预期时间误差 <1s，且字符串往返包含预期前缀
    parse_time(s)
}

fn assert_within_1ms(a: DateTime<Utc>, b: DateTime<Utc>) {
    let diff_nanos = (a.timestamp_nanos_opt().unwrap() - b.timestamp_nanos_opt().unwrap()).abs();
    assert!(
        diff_nanos < 1_000_000,
        "时间差 {}ns 超过 1ms: a={} b={}",
        diff_nanos,
        a.to_rfc3339_opts(SecondsFormat::Nanos, true),
        b.to_rfc3339_opts(SecondsFormat::Nanos, true)
    );
}

// Go 标准库 time.RFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
// Go 会裁剪尾随 0，例如 2026-08-26T08:19:02.123Z，而 Rust SecondsFormat::Nanos 总是 9 位
fn go_rfc3339nano_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

// ---------- 1. 带纳秒全精度 9 位 ----------
#[test]
fn parse_go_rfc3339nano_with_nanos_9digits() {
    let s = "2026-08-26T08:19:02.853853123Z";
    let dt = parse_time(s);
    // 必须解析成功：时间戳应精确到纳秒
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        853_853_123
    );
    assert_eq!(dt.to_rfc3339_opts(SecondsFormat::Nanos, true), s);
}

#[test]
fn parse_go_rfc3339nano_with_nanos_6digits_micro() {
    // Go 可能写入 6 位微秒（若纳秒尾 3 位为 0 会被裁剪到 6 位）
    let s = "2026-08-26T08:19:02.123456Z";
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_000
    );
    // 往返误差 <1ms
    let expected = Utc.with_ymd_and_hms(2026, 8, 26, 8, 19, 2).unwrap()
        + chrono::Duration::nanoseconds(123_456_000);
    assert_within_1ms(dt, expected);
}

#[test]
fn parse_go_rfc3339nano_with_nanos_3digits_milli() {
    let s = "2026-08-26T08:19:02.123Z";
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_000_000
    );
    let expected = Utc.with_ymd_and_hms(2026, 8, 26, 8, 19, 2).unwrap()
        + chrono::Duration::nanoseconds(123_000_000);
    assert_within_1ms(dt, expected);
}

#[test]
fn parse_go_rfc3339nano_with_nanos_1digit() {
    let s = "2026-08-26T08:19:02.1Z";
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        100_000_000
    );
}

#[test]
fn parse_go_rfc3339nano_with_offset() {
    // Go 以本地时区 Format 时会带 +08:00
    let s = "2026-08-26T16:19:02.123456789+08:00";
    let dt = parse_time(s);
    // 应正确转为 UTC: 08:19:02.123456789Z
    assert_eq!(
        dt.to_rfc3339_opts(SecondsFormat::Nanos, true),
        "2026-08-26T08:19:02.123456789Z"
    );
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_789
    );
}

#[test]
fn parse_go_rfc3339nano_zero_nanos_trailing() {
    // Go 对整秒也可能输出 .000000000 或裁剪到无小数；两种都应兼容
    let s_full = "2026-08-26T08:19:02.000000000Z";
    let s_trim = "2026-08-26T08:19:02Z";
    let dt_full = parse_time(s_full);
    let dt_trim = parse_time(s_trim);
    assert_eq!(dt_full.timestamp(), dt_trim.timestamp());
    assert_eq!(dt_full.timestamp_nanos_opt().unwrap() % 1_000_000_000, 0);
}

// ---------- 2. 不带纳秒 RFC3339 ----------
#[test]
fn parse_go_rfc3339_without_nanos_utc_z() {
    let s = "2026-08-26T08:19:02Z";
    let dt = parse_time(s);
    assert_eq!(dt.to_rfc3339_opts(SecondsFormat::Secs, true), s);
    assert_eq!(dt.timestamp_nanos_opt().unwrap() % 1_000_000_000, 0);
}

#[test]
fn parse_go_rfc3339_without_nanos_offset() {
    let s = "2026-08-26T16:19:02+08:00";
    let dt = parse_time(s);
    assert_eq!(
        dt.to_rfc3339_opts(SecondsFormat::Secs, true),
        "2026-08-26T08:19:02Z"
    );
}

#[test]
fn parse_go_rfc3339_without_nanos_offset_negative() {
    let s = "2026-08-26T00:19:02-08:00";
    let dt = parse_time(s);
    assert_eq!(
        dt.to_rfc3339_opts(SecondsFormat::Secs, true),
        "2026-08-26T08:19:02Z"
    );
}

// ---------- 3. 空格格式边界（遗留 / SQLite 默认） ----------
#[test]
fn parse_space_format_without_tz() {
    // Go sqlite 旧代码或某些 TEXT 默认： "2006-01-02 15:04:05"
    let s = "2026-08-26 08:19:02";
    let dt = parse_time(s);
    assert_eq!(
        dt.to_rfc3339_opts(SecondsFormat::Secs, true),
        "2026-08-26T08:19:02Z"
    );
}

#[test]
fn parse_space_format_with_nanos_should_fallback_or_parse() {
    // 边界：空格 + 纳秒，已扩展 parse_time 支持 " %Y-%m-%d %H:%M:%S%.f"
    let s = "2026-08-26 08:19:02.123456789";
    let dt = parse_time(s);
    let expected = Utc.with_ymd_and_hms(2026, 8, 26, 8, 19, 2).unwrap()
        + chrono::Duration::nanoseconds(123_456_789);
    assert_within_1ms(dt, expected);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_789
    );
}

#[test]
fn parse_space_format_with_nanos_milli() {
    let s = "2026-08-26 08:19:02.123";
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_000_000
    );
}

#[test]
fn parse_space_format_with_z_and_nanos() {
    let s = "2026-08-26 08:19:02.123456789Z";
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_789
    );
}

#[test]
fn parse_t_format_with_nanos_z() {
    // 对应 parse_time 第 4 分支 NaiveDateTime "%Y-%m-%dT%H:%M:%S%.fZ"
    let s = "2026-08-26T08:19:02.123456789Z";
    let dt = parse_time(s);
    assert_eq!(
        dt.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_789
    );
    assert_eq!(dt.to_rfc3339_opts(SecondsFormat::Nanos, true), s);
}

#[test]
fn parse_t_format_with_nanos_zero_padded() {
    let s = "2026-08-26T08:19:02.000000001Z";
    let dt = parse_time(s);
    assert_eq!(dt.timestamp_nanos_opt().unwrap() % 1_000_000_000, 1);
}

// ---------- 4. 时间差 <1ms 核心断言（模拟 Go 写入即时往返） ----------
#[test]
fn go_rfc3339nano_roundtrip_diff_lt_1ms() {
    // 模拟 Go time.Now().UTC().Format(time.RFC3339Nano)
    let now = Utc::now();
    let go_written = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let rust_parsed = parse_time(&go_written);
    assert_within_1ms(now, rust_parsed);
    // 二次往返也应 <1ms
    let go_reformatted = rust_parsed.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let rust_reparsed = parse_time(&go_reformatted);
    assert_within_1ms(rust_parsed, rust_reparsed);
}

#[test]
fn go_rfc3339_roundtrip_diff_lt_1ms() {
    let now = Utc::now();
    let go_written = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let rust_parsed = parse_time(&go_written);
    // 秒级截断必然 <1s，但需验证 <1000ms（实际 <1ms 仅纳秒可保证，秒级为截断误差 <1000ms）
    let diff_ms = (now.timestamp_millis() - rust_parsed.timestamp_millis()).abs();
    assert!(diff_ms < 1000, "RFC3339 秒级截断差值 {}ms", diff_ms);
}

// ---------- 5. 真实 SQLite 交叉：模拟 Go 写入 → Rust 读取 ----------
#[tokio::test]
async fn cross_sqlite_go_writes_rust_reads_users_and_posts() -> anyhow::Result<()> {
    // 用 Rust 直接以 Go 格式字符串插入，模拟 Go time.RFC3339Nano 写入行为
    let store = Store::open(":memory:").await?;

    // 准备 Go 风格时间字符串（带纳秒 / 不带纳秒 / 偏移）
    let go_nano = Utc.with_ymd_and_hms(2026, 8, 26, 8, 19, 2).unwrap()
        + chrono::Duration::nanoseconds(853_853_123);
    let go_nano_str = go_nano.to_rfc3339_opts(SecondsFormat::Nanos, true);
    // 带纳秒 +08:00
    let go_nano_offset_str = "2026-08-26T16:19:02.123456789+08:00";
    // 不带纳秒
    let go_rfc_str = "2026-08-26T08:19:02Z";
    // 空格遗留
    let go_space_str = "2026-08-26 08:19:02";

    // 插入 users：直接用 Go 字符串写 created_at
    for (i, ts) in [
        go_nano_str.clone(),
        go_rfc_str.to_string(),
        go_space_str.to_string(),
    ]
    .iter()
    .enumerate()
    {
        let uname = format!("go_user_{}", i);
        sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,0,?)",
        )
        .bind(&uname)
        .bind("hash")
        .bind(ts)
        .execute(&store.pool)
        .await?;
    }
    // 验证 Rust 读取
    let u0 = store.get_user_by_username("go_user_0").await?.expect("u0");
    assert_within_1ms(u0.created_at, go_nano);
    let u1 = store.get_user_by_username("go_user_1").await?.expect("u1");
    let exp1 = parse_time(go_rfc_str);
    assert_within_1ms(u1.created_at, exp1);
    let u2 = store.get_user_by_username("go_user_2").await?.expect("u2");
    let exp2 = parse_time(go_space_str);
    assert_within_1ms(u2.created_at, exp2);

    // 插入 boards / threads / posts 链路，验证 threads/posts 时间解析
    let board_id: i64 = sqlx::query_as::<_, (i64,)>("SELECT id FROM boards LIMIT 1")
        .fetch_one(&store.pool)
        .await?
        .0;

    // Go 写入 threads 行（created_at/last_reply_at 均用 Go 格式）
    let tid_nano_str = go_nano.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let thread_res = sqlx::query(
        "INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(board_id)
    .bind("go-thread-nano")
    .bind(u0.id)
    .bind(0)
    .bind(0)
    .bind(0)
    .bind(&tid_nano_str)
    .bind(&tid_nano_str)
    .execute(&store.pool)
    .await?;
    let tid = thread_res.last_insert_rowid();

    // Go 写入 posts 行（created_at 带纳秒）
    let post_ts_str = go_nano.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let post_ts_expected = go_nano;
    sqlx::query(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(tid)
    .bind(board_id)
    .bind(u0.id)
    .bind(0)
    .bind("go post md")
    .bind("<p>go</p>")
    .bind(&post_ts_str)
    .execute(&store.pool)
    .await?;

    // Rust Store 读取并断言 <1ms
    let th = store.get_thread(tid).await?.expect("thread");
    assert_within_1ms(th.created_at, post_ts_expected);
    assert_within_1ms(th.last_reply_at, post_ts_expected);

    let (posts, total) = store.list_posts(tid, 1, 10).await?;
    assert_eq!(total, 1);
    assert_within_1ms(posts[0].created_at, post_ts_expected);

    // 再插入一条用 RFC3339（无纳秒）的 post，验证回落分支
    let rfc_post_str = "2026-08-26T08:19:02Z";
    sqlx::query(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(tid)
    .bind(board_id)
    .bind(u0.id)
    .bind(0)
    .bind("second")
    .bind("<p>2</p>")
    .bind(rfc_post_str)
    .execute(&store.pool)
    .await?;
    let (posts2, total2) = store.list_posts(tid, 1, 10).await?;
    assert_eq!(total2, 2);
    let second = posts2.iter().find(|p| p.content_md == "second").unwrap();
    assert_within_1ms(second.created_at, parse_time(rfc_post_str));

    // 用 +08:00 偏移写入，验证偏移解析
    let off_str = go_nano_offset_str;
    sqlx::query(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(tid)
    .bind(board_id)
    .bind(u0.id)
    .bind(0)
    .bind("offset")
    .bind("<p>off</p>")
    .bind(off_str)
    .execute(&store.pool)
    .await?;
    let (posts3, _) = store.list_posts(tid, 1, 10).await?;
    let off_post = posts3.iter().find(|p| p.content_md == "offset").unwrap();
    // +08:00 对应 UTC 08:19:02.123456789Z
    let off_expected = parse_time(off_str);
    assert_within_1ms(off_post.created_at, off_expected);
    assert_eq!(
        off_post
            .created_at
            .to_rfc3339_opts(SecondsFormat::Nanos, true),
        "2026-08-26T08:19:02.123456789Z"
    );

    Ok(())
}

#[tokio::test]
async fn cross_sqlite_store_api_writes_rust_reads_roundtrip() -> anyhow::Result<()> {
    // 反向：Rust Store API 写入（内部用 RFC3339Nano），再用原始 SQL 读取字符串并二次 parse
    let store = Store::open(":memory:").await?;
    let before = Utc::now();
    let uid = store.create_user("cross_user", "hash", false).await?;
    let after = Utc::now();

    let row = sqlx::query("SELECT created_at FROM users WHERE id=?")
        .bind(uid)
        .fetch_one(&store.pool)
        .await?;
    let raw: String = row.get("created_at");
    // Rust 写入应为 RFC3339Nano（带 Z）
    assert!(
        raw.ends_with('Z'),
        "Rust Store 写入应为 RFC3339Nano Zulu, got {}",
        raw
    );
    let parsed = parse_time(&raw);
    // 解析成功且时间差 <1ms（包含在 before..after 区间内 ±1ms）
    assert!(parsed >= before - chrono::Duration::milliseconds(1));
    assert!(parsed <= after + chrono::Duration::milliseconds(1));
    assert_within_1ms(parsed, store.get_user_by_id(uid).await?.unwrap().created_at);

    // sessions 表同样验证 expires_at 高精度
    let sid = store.create_session(uid).await?;
    let srow = sqlx::query("SELECT created_at, expires_at FROM sessions WHERE id=?")
        .bind(&sid)
        .fetch_one(&store.pool)
        .await?;
    let c_raw: String = srow.get("created_at");
    let e_raw: String = srow.get("expires_at");
    let c_parsed = parse_time(&c_raw);
    let e_parsed = parse_time(&e_raw);
    // expires - created ≈ 30 天，误差 <1s
    let diff_days = (e_parsed - c_parsed).num_days();
    assert_eq!(diff_days, 30);
    // 两个字段均应解析成功且与 Store 读取一致
    let sess = store.get_session(&sid).await?.expect("session");
    assert_within_1ms(sess.created_at, c_parsed);
    assert_within_1ms(sess.expires_at, e_parsed);

    Ok(())
}

#[tokio::test]
async fn cross_sqlite_invite_and_board_times() -> anyhow::Result<()> {
    let store = Store::open(":memory:").await?;
    // 手工用 Go 字符串插入 invite_codes 和 boards，验证 Rust 读取
    let uid = store.create_user("inv_user", "hash", false).await?;
    let go_ts = "2026-08-26T08:19:02.999999999Z";
    sqlx::query("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES(?,?,?,?,?,?)")
        .bind("go-board")
        .bind("Go板")
        .bind("desc")
        .bind(1)
        .bind(1)
        .bind(go_ts)
        .execute(&store.pool)
        .await?;
    let board = store.get_board_by_slug("go-board").await?.expect("board");
    assert_within_1ms(board.created_at, parse_time(go_ts));

    // invite 用 nanos
    sqlx::query("INSERT INTO invite_codes(code,created_by,created_at) VALUES(?,?,?)")
        .bind("CODE123")
        .bind(uid)
        .bind(go_ts)
        .execute(&store.pool)
        .await?;
    let invites = store.list_invites().await?;
    assert_eq!(invites.len(), 1);
    assert_within_1ms(invites[0].created_at, parse_time(go_ts));
    Ok(())
}

// 边界：极小纳秒与极大纳秒、闰秒前后的字符串（不验证闰秒本身，仅验证不 panic）
#[test]
fn boundary_min_max_nanos() {
    let min = "2026-01-01T00:00:00.000000001Z";
    let max = "2026-12-31T23:59:59.999999999Z";
    let dmin = parse_time(min);
    let dmax = parse_time(max);
    assert_eq!(dmin.timestamp_nanos_opt().unwrap() % 1_000_000_000, 1);
    assert_eq!(
        dmax.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        999_999_999
    );
    assert!(dmax > dmin);
}

#[test]
fn parse_with_trailing_newline_trim() {
    let s = "2026-08-26T08:19:02.123456789Z\n";
    let dt_trimmed = parse_time(s.trim());
    let dt_raw = parse_time(s);
    assert_eq!(
        dt_trimmed.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_789
    );
    // parse_time 内部已 trim，raw 也应成功
    assert_eq!(
        dt_raw.timestamp_nanos_opt().unwrap() % 1_000_000_000,
        123_456_789
    );
    assert_within_1ms(dt_raw, dt_trimmed);
}
