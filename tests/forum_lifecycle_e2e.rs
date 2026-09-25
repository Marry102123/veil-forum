//! Real HTTP + real PostgreSQL forum content lifecycle journey.
//!
//! Failure modes intentionally covered before implementation:
//! 1. A valid member cannot log in through the HTTP form or receives no session cookie.
//! 2. An administrator cannot create an anonymous-capable, guest-readable board via HTTP.
//! 3. Thread or reply form submission fails despite a valid CSRF token and session.
//! 4. Anonymous content leaks the real username or fails to display `Anonymous` publicly.
//! 5. The thread page does not render the created posts, or board reply counts drift.
//! 6. A moderator's soft delete does not hide a reply from an ordinary member.
//! 7. An owner cannot restore the deleted reply through the governance form.
//! 8. Restore does not make the reply publicly visible again.
//! 9. Soft delete/restore does not preserve the expected `reply_count` historical counter.
//! 10. Delete/restore audit rows have the wrong actor, target, or success value.
//! 11. Final PostgreSQL rows disagree with the HTTP-visible lifecycle state.
//! 12. Anonymous thread, opening post, or anonymous reply attribution remains in PostgreSQL.
//! 13. Replaying the anonymous-identity migration does not scrub legacy anonymous
//!     threads, or mistakenly scrubs a named thread that merely has an anonymous reply.
//! 14. A named thread loses its author identity, or its named post cannot enforce cooldown.
//!
//! Normal content mutations and visibility checks use HTTP forms. Direct inserts are
//! limited to legacy pre-migration rows and the exact migration replay needed to prove
//! historical scrubbing; identity, password-hash, role, and board moderation remain fixtures.
//! The test binds a real loopback TCP listener and uses PostgreSQL via `sqlx::test`.
//!
//! Reproduce with:
//! `DATABASE_URL="$TEST_DATABASE_URL" cargo test --test forum_lifecycle_e2e -- --nocapture`
//! A credential-free verification report is written to
//! `target/forum-lifecycle-e2e-report.json` by the same command.

use anyhow::{bail, Context};
use axum::body::Body;
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tower::ServiceExt;
use veil_forum::{
    auth, captcha, handler, pow, rate_limit,
    store::{Role, Store},
};

const MEMBER_PASSWORD: &str = "Cobalt-Cedar4-River";
const MODERATOR_PASSWORD: &str = "Lumen-Willow6-Summit";
const OWNER_PASSWORD: &str = "Summit-Harbor9-Falcon";
const THREAD_TITLE: &str = "Lifecycle journey anonymous thread";
const THREAD_BODY: &str = "thread-body-lifecycle-unique";
const REPLY_BODY: &str = "reply-body-lifecycle-unique";
const NAMED_THREAD_TITLE: &str = "Lifecycle named identity thread";
const NAMED_THREAD_BODY: &str = "thread-body-named-lifecycle-unique";
const LEGACY_ANONYMOUS_TITLE: &str = "Legacy anonymous identity thread";
const LEGACY_NAMED_TITLE: &str = "Legacy named thread with anonymous reply";

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn location(&self) -> &str {
        self.header("location").unwrap_or_default()
    }

    fn session_cookie(&self) -> anyhow::Result<String> {
        self.header("set-cookie")
            .and_then(|value| value.split(';').next())
            .filter(|value| value.starts_with("session_id="))
            .map(str::to_owned)
            .context("login response did not set a session_id cookie")
    }
}

struct TestServer {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn start(pool: PgPool) -> anyhow::Result<Self> {
        let store = Store { pool: pool.clone() };
        store.seed_defaults().await?;
        let state = handler::AppState {
            pow: pow::Manager::new(store.clone()),
            captcha: captcha::Manager::new(),
            limits: rate_limit::Limits::new(),
            secure_session_cookie: false,
            store,
        };
        let app = handler::routes(state);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let request = match read_http_request(&mut socket).await {
                        Ok(request) => request,
                        Err(_) => return,
                    };
                    let response = app.oneshot(request).await.unwrap_or_else(|error| {
                        axum::response::Response::builder()
                            .status(500)
                            .body(Body::from(format!("test server error: {error}")))
                            .expect("static test error response")
                    });
                    let (parts, body) = response.into_parts();
                    let bytes = axum::body::to_bytes(body, usize::MAX)
                        .await
                        .unwrap_or_default();
                    let mut wire = format!(
                        "HTTP/1.1 {} {}\r\n",
                        parts.status.as_u16(),
                        parts.status.canonical_reason().unwrap_or("Response")
                    );
                    for (name, value) in &parts.headers {
                        wire.push_str(name.as_str());
                        wire.push_str(": ");
                        wire.push_str(value.to_str().unwrap_or_default());
                        wire.push_str("\r\n");
                    }
                    wire.push_str("Content-Length: ");
                    wire.push_str(&bytes.len().to_string());
                    wire.push_str("\r\nConnection: close\r\n\r\n");
                    let _ = socket.write_all(wire.as_bytes()).await;
                    let _ = socket.write_all(&bytes).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Ok(Self { address, task })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_http_request(
    socket: &mut tokio::net::TcpStream,
) -> anyhow::Result<axum::extract::Request> {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            bail!("client closed before completing HTTP request");
        }
        wire.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
            let header_end = header_end + 4;
            let head = String::from_utf8(wire[..header_end].to_vec())?;
            let mut lines = head.lines();
            let request_line = lines.next().context("missing HTTP request line")?;
            let mut parts = request_line.split_whitespace();
            let method = parts.next().context("missing HTTP method")?;
            let target = parts.next().context("missing HTTP target")?;
            let header_lines: Vec<&str> = lines.collect();
            let content_length = header_lines
                .iter()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if wire.len() >= header_end + content_length {
                let mut builder = axum::http::Request::builder().method(method).uri(target);
                for line in header_lines {
                    if let Some((name, value)) = line.split_once(':') {
                        builder = builder.header(name.trim(), value.trim());
                    }
                }
                return Ok(builder.body(Body::from(
                    wire[header_end..header_end + content_length].to_vec(),
                ))?);
            }
        }
        if wire.len() > 64 * 1024 {
            bail!("HTTP request headers exceeded 64 KiB");
        }
    }
}

async fn request(
    server: &TestServer,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> anyhow::Result<HttpResponse> {
    let mut socket = tokio::net::TcpStream::connect(server.address).await?;
    let body = form.unwrap_or_default();
    let host = server.address.to_string();
    let mut wire = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nConnection: close\r\n"
    );
    if let Some(cookie) = cookie {
        wire.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    if form.is_some() {
        wire.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }
    wire.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    socket.write_all(wire.as_bytes()).await?;

    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).await?;
    let separator = raw
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .context("HTTP response has no header terminator")?
        + 4;
    let head = String::from_utf8(raw[..separator].to_vec())?;
    let body = String::from_utf8(raw[separator..].to_vec())?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("HTTP response has no status code")?
        .parse::<u16>()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(*byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn form_value(key: &str, value: &str) -> String {
    format!("{}={}", encode(key), encode(value))
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| form_value(key, value))
        .collect::<Vec<_>>()
        .join("&")
}

async fn csrf(server: &TestServer, path: &str, cookie: Option<&str>) -> anyhow::Result<String> {
    let response = request(server, "GET", path, cookie, None).await?;
    if response.status != 200 {
        bail!("CSRF page {path} returned HTTP {}", response.status);
    }
    let marker = "name=\"csrf_token\" value=\"";
    let start = response.body.find(marker).context("CSRF token missing")? + marker.len();
    let length = response.body[start..]
        .find('"')
        .context("unterminated CSRF token")?;
    Ok(response.body[start..start + length].to_owned())
}

async fn login(
    server: &TestServer,
    username: &str,
    password: &str,
) -> anyhow::Result<(String, String)> {
    let token = csrf(server, "/login", None).await?;
    let response = request(
        server,
        "POST",
        "/login",
        None,
        Some(&form_body(&[
            ("csrf_token", &token),
            ("username", username),
            ("password", password),
        ])),
    )
    .await?;
    if response.status != 303 {
        bail!(
            "login for {username} returned HTTP {}: {}",
            response.status,
            response.body
        );
    }
    Ok((response.session_cookie()?, token))
}

fn article_id(html: &str, unique_body: &str) -> anyhow::Result<i64> {
    let body_at = html
        .find(unique_body)
        .context("expected post body missing from HTML")?;
    let prefix = &html[..body_at];
    let mut search_from = prefix.len();
    let article_at = loop {
        let Some(relative) = prefix[..search_from].rfind("id=\"p") else {
            bail!("post body has no article id");
        };
        let candidate = relative;
        let digits_start = candidate + 5;
        if html
            .as_bytes()
            .get(digits_start)
            .is_some_and(u8::is_ascii_digit)
        {
            break candidate;
        }
        if candidate == 0 {
            bail!("post body has no article id");
        }
        search_from = candidate;
    };
    let digits_start = article_at + 5;
    let digits_end = html[digits_start..]
        .find(|character: char| !character.is_ascii_digit())
        .context("post article id is missing digits")?
        + digits_start;
    html[digits_start..digits_end].parse().with_context(|| {
        format!(
            "post article id is not an integer: {:?}",
            &html[digits_start..digits_end]
        )
    })
}

fn article(html: &str, post_id: i64) -> anyhow::Result<String> {
    let marker = format!("id=\"p{post_id}\"");
    let start = html.find(&marker).context("post article missing")?;
    let end = html[start..]
        .find("</article>")
        .context("post article is unterminated")?
        + start;
    Ok(html[start..end].to_owned())
}

fn board_reply_count(html: &str, title: &str) -> anyhow::Result<String> {
    let title_at = html
        .find(title)
        .context("thread title missing from board page")?;
    let row_start = html[..title_at]
        .rfind("<div class=\"thread-row")
        .unwrap_or(0);
    let row = &html[row_start..];
    let count_at = row
        .find("<div class=\"replies\"><b>")
        .context("reply count missing")?;
    let start = count_at + "<div class=\"replies\"><b>".len();
    let end = row[start..]
        .find("</b>")
        .context("reply count is unterminated")?
        + start;
    Ok(row[start..end].to_owned())
}

async fn assert_audit(
    pool: &PgPool,
    action: &str,
    target_type: &str,
    target_id: i64,
    actor_id: i64,
) -> anyhow::Result<()> {
    let matches: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE action=$1 AND target_type=$2 AND target_id=$3 AND actor_user_id=$4 AND success=TRUE",
    )
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(actor_id)
    .fetch_one(pool)
    .await?;
    if matches.0 != 1 {
        bail!(
            "expected one successful {action} audit row, found {}",
            matches.0
        );
    }
    Ok(())
}

struct LifecycleReport {
    path: std::path::PathBuf,
    started_at: String,
    ended_at: Option<String>,
    result: &'static str,
    failed_step: Option<&'static str>,
    expected_checks: Vec<&'static str>,
    completed_checks: Vec<String>,
    finalized: bool,
}

impl LifecycleReport {
    fn start() -> anyhow::Result<Self> {
        let input = format!(
            "{THREAD_TITLE}|{THREAD_BODY}|{REPLY_BODY}|{NAMED_THREAD_TITLE}|{NAMED_THREAD_BODY}|{LEGACY_ANONYMOUS_TITLE}|{LEGACY_NAMED_TITLE}"
        );
        let input_sha256 = hex::encode(Sha256::digest(input.as_bytes()));
        let mut report = Self {
            path: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/forum-lifecycle-e2e-report.json"),
            started_at: utc_now(),
            ended_at: None,
            result: "failed",
            failed_step: Some("test_execution"),
            expected_checks: vec![
                "fixtures: users roles and anonymous-capable board",
                "anonymous thread and both posts have NULL author_id",
                "legacy migration clears anonymous thread/posts only",
                "named thread and named reply retain author identity",
                "named reply cooldown remains enforced",
                "moderator delete and owner restore audit lifecycle",
                "final PostgreSQL lifecycle counters and anonymous flags",
            ],
            completed_checks: Vec::new(),
            finalized: false,
        };
        report.write(input_sha256, "running_or_interrupted")?;
        Ok(report)
    }

    fn step(&mut self, step: &'static str) -> &'static str {
        self.failed_step = Some(step);
        step
    }

    fn complete(&mut self, step: &str, checks: &[&'static str]) {
        if self.failed_step == Some(step) {
            self.completed_checks
                .extend(checks.iter().map(|check| (*check).to_owned()));
            self.failed_step = None;
        }
    }

    fn succeed(&mut self) -> anyhow::Result<()> {
        self.result = "passed";
        self.failed_step = None;
        if let Err(error) = self.write(self.input_sha256(), "completed") {
            self.result = "failed";
            self.failed_step = Some("report_write");
            return Err(error);
        }
        Ok(())
    }

    fn input_sha256(&self) -> String {
        let input = format!(
            "{THREAD_TITLE}|{THREAD_BODY}|{REPLY_BODY}|{NAMED_THREAD_TITLE}|{NAMED_THREAD_BODY}|{LEGACY_ANONYMOUS_TITLE}|{LEGACY_NAMED_TITLE}"
        );
        hex::encode(Sha256::digest(input.as_bytes()))
    }

    fn write(
        &mut self,
        input_sha256: String,
        execution_status: &'static str,
    ) -> anyhow::Result<()> {
        if execution_status != "running_or_interrupted" {
            self.ended_at = Some(utc_now());
        }
        let report = serde_json::json!({
            "schema": "forum-lifecycle-e2e/v3",
            "version": env!("CARGO_PKG_VERSION"),
            "started_at_utc": self.started_at,
            "ended_at_utc": self.ended_at,
            "result": self.result,
            "failed_step": self.failed_step,
            "test_execution": {
                "status": execution_status,
                "panic_detected": execution_status == "panic",
            },
            "input_summary": {
                "database": "sqlx isolated PostgreSQL database",
                "transport": "real loopback TCP HTTP",
                "input_sha256": input_sha256,
                "fixtures": ["member", "moderator", "owner", "anonymous and named lifecycle content"],
                "secrets": "test-only passwords, sessions, cookies, and CSRF tokens excluded"
            },
            "checks": {
                "expected": self.expected_checks,
                "completed": self.completed_checks,
            },
            "artifacts": {
                "report_path": self.path,
                "log_path": "raw cargo output not captured"
            },
            "reproduce_command": "DATABASE_URL=\"$TEST_DATABASE_URL\" cargo test --test forum_lifecycle_e2e -- --nocapture",
            "verification_command": "python3 -m json.tool target/forum-lifecycle-e2e-report.json",
            "credentials_included": false
        });
        let parent = self
            .path
            .parent()
            .context("E2E report path has no parent directory")?;
        std::fs::create_dir_all(parent).context("create target report directory")?;
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        let temporary = self.path.with_extension("json.tmp");
        if let Err(error) = std::fs::write(&temporary, bytes) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error).context("write temporary E2E verification report");
        }
        if let Err(error) = std::fs::rename(&temporary, &self.path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error).context("atomically replace E2E verification report");
        }
        self.finalized = execution_status != "running_or_interrupted";
        Ok(())
    }
}

impl Drop for LifecycleReport {
    fn drop(&mut self) {
        if !self.finalized {
            let execution_status = if std::thread::panicking() {
                "panic"
            } else {
                "error"
            };
            let _ = self.write(self.input_sha256(), execution_status);
        }
    }
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[sqlx::test]
async fn forum_content_survives_real_http_delete_and_restore_lifecycle(
    pool: PgPool,
) -> anyhow::Result<()> {
    let mut report = LifecycleReport::start()?;
    let result = forum_content_lifecycle_inner(pool, &mut report).await;
    if result.is_ok() {
        report.succeed()?;
    }
    result
}

async fn forum_content_lifecycle_inner(
    pool: PgPool,
    report: &mut LifecycleReport,
) -> anyhow::Result<()> {
    let step = report.step("fixture_setup");
    let member_password_hash =
        tokio::task::spawn_blocking(|| auth::hash_password(MEMBER_PASSWORD)).await??;
    let moderator_password_hash =
        tokio::task::spawn_blocking(|| auth::hash_password(MODERATOR_PASSWORD)).await??;
    let owner_password_hash =
        tokio::task::spawn_blocking(|| auth::hash_password(OWNER_PASSWORD)).await??;
    let store = Store { pool: pool.clone() };
    let member_id = store
        .create_user("lifecycle_member", &member_password_hash, false)
        .await?;
    let moderator_id = store
        .create_user("lifecycle_moderator", &moderator_password_hash, false)
        .await?;
    let owner_id = store
        .create_user("lifecycle_owner", &owner_password_hash, true)
        .await?;
    store.grant_role(owner_id, Role::Owner, None).await?;
    store
        .grant_role(moderator_id, Role::Moderator, Some(owner_id))
        .await?;

    let server = TestServer::start(pool.clone()).await?;
    store.set_config("login_pow_enabled", "0").await?;
    store.set_config("login_captcha_enabled", "0").await?;
    store.set_config("post_pow_enabled", "0").await?;
    store.set_config("post_captcha_enabled", "0").await?;
    store.set_config("post_cooldown_seconds", "0").await?;

    let (owner_cookie, _) = login(&server, "lifecycle_owner", OWNER_PASSWORD).await?;
    let create_board_csrf = csrf(&server, "/admin/settings", Some(&owner_cookie)).await?;
    let board_response = request(
        &server,
        "POST",
        "/admin/board/create",
        Some(&owner_cookie),
        Some(&form_body(&[
            ("csrf_token", &create_board_csrf),
            ("slug", "lifecycle"),
            ("name", "Lifecycle"),
            ("description", "Lifecycle E2E board"),
            ("allow_anonymous", "on"),
            ("guest_readable", "on"),
        ])),
    )
    .await?;
    if board_response.status != 303 {
        bail!(
            "board creation returned HTTP {}: {}",
            board_response.status,
            board_response.body
        );
    }
    let board: (i64,) = sqlx::query_as("SELECT id FROM boards WHERE slug='lifecycle'")
        .fetch_one(&pool)
        .await?;
    store
        .add_board_moderator(board.0, moderator_id, Some(owner_id))
        .await?;
    report.complete(step, &["fixtures: users roles and anonymous-capable board"]);

    let step = report.step("anonymous_thread_and_reply");
    let (member_cookie, _) = login(&server, "lifecycle_member", MEMBER_PASSWORD).await?;
    let new_thread_csrf = csrf(&server, "/b/lifecycle", Some(&member_cookie)).await?;
    let thread_response = request(
        &server,
        "POST",
        "/b/lifecycle/new",
        Some(&member_cookie),
        Some(&form_body(&[
            ("csrf_token", &new_thread_csrf),
            ("title", THREAD_TITLE),
            ("content", THREAD_BODY),
            ("anonymous", "on"),
        ])),
    )
    .await?;
    if thread_response.status != 303 || !thread_response.location().starts_with("/t/") {
        bail!(
            "thread creation returned HTTP {}: {}",
            thread_response.status,
            thread_response.body
        );
    }
    let thread_id = thread_response
        .location()
        .trim_start_matches("/t/")
        .parse::<i64>()?;

    let (reply_cookie, _) = login(&server, "lifecycle_member", MEMBER_PASSWORD).await?;
    let reply_csrf = csrf(&server, &format!("/t/{thread_id}"), Some(&reply_cookie)).await?;
    let reply_response = request(
        &server,
        "POST",
        &format!("/t/{thread_id}/reply"),
        Some(&reply_cookie),
        Some(&form_body(&[
            ("csrf_token", &reply_csrf),
            ("content", REPLY_BODY),
            ("anonymous", "on"),
        ])),
    )
    .await?;
    if reply_response.status != 303 {
        bail!(
            "reply creation returned HTTP {}: {}",
            reply_response.status,
            reply_response.body
        );
    }

    let public_page = request(&server, "GET", &format!("/t/{thread_id}"), None, None).await?;
    if public_page.status != 200 {
        bail!("public thread returned HTTP {}", public_page.status);
    }
    if public_page.body.contains("lifecycle_member") {
        bail!("anonymous thread leaked the real member username");
    }
    let first_post_id = article_id(&public_page.body, THREAD_BODY)?;
    let reply_post_id = article_id(&public_page.body, REPLY_BODY)?;
    let first_article = article(&public_page.body, first_post_id)?;
    if !first_article.contains("Anonymous") {
        bail!("anonymous thread author was not rendered as Anonymous");
    }
    if public_page.body.matches("class=\"social-post\"").count() != 2 {
        bail!("thread page did not render exactly the thread body and reply");
    }

    let anonymous_identity: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT th.author_id,
                (SELECT author_id FROM posts WHERE id=$2),
                (SELECT author_id FROM posts WHERE id=$3)
         FROM threads th WHERE th.id=$1",
    )
    .bind(thread_id)
    .bind(first_post_id)
    .bind(reply_post_id)
    .fetch_one(&pool)
    .await?;
    if anonymous_identity != (None, None, None) {
        bail!("anonymous identity remained in PostgreSQL: {anonymous_identity:?}");
    }
    if !article(&public_page.body, reply_post_id)?.contains("Anonymous") {
        bail!("anonymous reply author was not rendered as Anonymous");
    }
    report.complete(
        step,
        &["anonymous thread and both posts have NULL author_id"],
    );

    // Legacy rows model the pre-migration invariant: both author columns were
    // NOT NULL even for anonymous content. Replay the exact migration file and
    // prove both directions, including a named thread with an anonymous reply.
    let step = report.step("legacy_identity_migration");
    let legacy_anonymous_thread: i64 = sqlx::query_scalar(
        "INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at)
         VALUES($1,$2,$3,FALSE,FALSE,1,now(),now()) RETURNING id",
    )
    .bind(board.0)
    .bind(LEGACY_ANONYMOUS_TITLE)
    .bind(member_id)
    .fetch_one(&pool)
    .await?;
    let legacy_anonymous_opening: i64 = sqlx::query_scalar(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at)
         VALUES($1,$2,$3,TRUE,'legacy anonymous opening','<p>legacy anonymous opening</p>',now()) RETURNING id",
    )
    .bind(legacy_anonymous_thread)
    .bind(board.0)
    .bind(member_id)
    .fetch_one(&pool)
    .await?;
    let legacy_anonymous_reply: i64 = sqlx::query_scalar(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at)
         VALUES($1,$2,$3,TRUE,'legacy anonymous reply','<p>legacy anonymous reply</p>',now()) RETURNING id",
    )
    .bind(legacy_anonymous_thread)
    .bind(board.0)
    .bind(member_id)
    .fetch_one(&pool)
    .await?;
    let legacy_named_thread: i64 = sqlx::query_scalar(
        "INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at)
         VALUES($1,$2,$3,FALSE,FALSE,1,now(),now()) RETURNING id",
    )
    .bind(board.0)
    .bind(LEGACY_NAMED_TITLE)
    .bind(moderator_id)
    .fetch_one(&pool)
    .await?;
    let legacy_named_opening: i64 = sqlx::query_scalar(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at)
         VALUES($1,$2,$3,FALSE,'legacy named opening','<p>legacy named opening</p>',now()) RETURNING id",
    )
    .bind(legacy_named_thread)
    .bind(board.0)
    .bind(moderator_id)
    .fetch_one(&pool)
    .await?;
    let legacy_named_thread_anonymous_reply: i64 = sqlx::query_scalar(
        "INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at)
         VALUES($1,$2,$3,TRUE,'legacy anonymous reply to named','<p>legacy anonymous reply to named</p>',now()) RETURNING id",
    )
    .bind(legacy_named_thread)
    .bind(board.0)
    .bind(moderator_id)
    .fetch_one(&pool)
    .await?;

    sqlx::raw_sql(include_str!("../migrations/0004_anonymous_identity.sql"))
        .execute(&pool)
        .await?;
    type LegacyIdentityScrub = (
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let legacy_scrubbed: LegacyIdentityScrub = sqlx::query_as(
        "SELECT
                (SELECT author_id FROM threads WHERE id=$1),
                (SELECT author_id FROM posts WHERE id=$2),
                (SELECT author_id FROM posts WHERE id=$3),
                (SELECT author_id FROM threads WHERE id=$4),
                (SELECT author_id FROM posts WHERE id=$5),
                (SELECT author_id FROM posts WHERE id=$6)",
    )
    .bind(legacy_anonymous_thread)
    .bind(legacy_anonymous_opening)
    .bind(legacy_anonymous_reply)
    .bind(legacy_named_thread)
    .bind(legacy_named_opening)
    .bind(legacy_named_thread_anonymous_reply)
    .fetch_one(&pool)
    .await?;
    if legacy_scrubbed
        != (
            None,
            None,
            None,
            Some(moderator_id),
            Some(moderator_id),
            None,
        )
    {
        bail!("migration replay scrubbed the wrong identities: {legacy_scrubbed:?}");
    }
    let legacy_anon_view = request(
        &server,
        "GET",
        &format!("/t/{legacy_anonymous_thread}"),
        None,
        None,
    )
    .await?;
    if legacy_anon_view.status != 200
        || legacy_anon_view.body.contains("lifecycle_member")
        || !legacy_anon_view.body.contains("Anonymous")
    {
        bail!("migrated legacy anonymous thread was not publicly anonymous");
    }
    report.complete(
        step,
        &["legacy migration clears anonymous thread/posts only"],
    );

    // Named content must retain attribution. The second post is rejected by the
    // user-level cooldown, proving anonymous rows do not become the cooldown source
    // and the named opening post does.
    let step = report.step("named_identity_and_cooldown");
    let (named_cookie, _) = login(&server, "lifecycle_member", MEMBER_PASSWORD).await?;
    let named_csrf = csrf(&server, "/b/lifecycle", Some(&named_cookie)).await?;
    let named_thread_response = request(
        &server,
        "POST",
        "/b/lifecycle/new",
        Some(&named_cookie),
        Some(&form_body(&[
            ("csrf_token", &named_csrf),
            ("title", NAMED_THREAD_TITLE),
            ("content", NAMED_THREAD_BODY),
        ])),
    )
    .await?;
    if named_thread_response.status != 303 || !named_thread_response.location().starts_with("/t/") {
        bail!(
            "named thread creation returned HTTP {}: {}",
            named_thread_response.status,
            named_thread_response.body
        );
    }
    let named_thread_id = named_thread_response
        .location()
        .trim_start_matches("/t/")
        .parse::<i64>()?;
    let named_state: (Option<i64>, Option<i64>, i64) = sqlx::query_as(
        "SELECT th.author_id,
                (SELECT author_id FROM posts WHERE thread_id=th.id ORDER BY id LIMIT 1),
                (SELECT COUNT(*) FROM posts WHERE thread_id=th.id)
         FROM threads th WHERE th.id=$1",
    )
    .bind(named_thread_id)
    .fetch_one(&pool)
    .await?;
    if named_state != (Some(member_id), Some(member_id), 1) {
        bail!("named thread identity was not preserved: {named_state:?}");
    }
    let (named_reply_cookie, _) = login(&server, "lifecycle_member", MEMBER_PASSWORD).await?;
    let named_reply_csrf = csrf(
        &server,
        &format!("/t/{named_thread_id}"),
        Some(&named_reply_cookie),
    )
    .await?;
    let named_reply_response = request(
        &server,
        "POST",
        &format!("/t/{named_thread_id}/reply"),
        Some(&named_reply_cookie),
        Some(&form_body(&[
            ("csrf_token", &named_reply_csrf),
            ("content", "named-reply-lifecycle-unique"),
        ])),
    )
    .await?;
    if named_reply_response.status != 303 {
        bail!(
            "named reply creation returned HTTP {}: {}",
            named_reply_response.status,
            named_reply_response.body
        );
    }
    let named_reply: (Option<i64>, bool) = sqlx::query_as(
        "SELECT author_id, is_anonymous FROM posts
         WHERE thread_id=$1 AND id <> (SELECT MIN(id) FROM posts WHERE thread_id=$1)",
    )
    .bind(named_thread_id)
    .fetch_one(&pool)
    .await?;
    if named_reply != (Some(member_id), false) {
        bail!("named reply identity was not preserved: {named_reply:?}");
    }
    let named_view = request(&server, "GET", &format!("/t/{named_thread_id}"), None, None).await?;
    if named_view.status != 200 || !named_view.body.contains("lifecycle_member") {
        bail!("named thread author was not rendered");
    }
    store.set_config("post_cooldown_seconds", "60").await?;
    let cooldown_response = request(
        &server,
        "POST",
        &format!("/t/{named_thread_id}/reply"),
        Some(&named_reply_cookie),
        Some(&form_body(&[
            // The same-session token was obtained before the cooldown was
            // enabled. Once cooling down, the page intentionally omits both
            // the reply form and its CSRF field.
            ("csrf_token", &named_reply_csrf),
            ("content", "reply-must-be-cooled-down"),
        ])),
    )
    .await?;
    if cooldown_response.status != 429 {
        bail!(
            "named reply cooldown returned HTTP {} instead of 429: {}",
            cooldown_response.status,
            cooldown_response.body
        );
    }
    store.set_config("post_cooldown_seconds", "0").await?;
    if board_reply_count(
        &request(&server, "GET", "/b/lifecycle", None, None)
            .await?
            .body,
        THREAD_TITLE,
    )? != "1"
    {
        bail!("board page did not report one reply");
    }
    report.complete(
        step,
        &[
            "named thread and named reply retain author identity",
            "named reply cooldown remains enforced",
        ],
    );

    let step = report.step("moderator_delete_and_owner_restore");
    let (moderator_cookie, _) = login(&server, "lifecycle_moderator", MODERATOR_PASSWORD).await?;
    // Keep the moderator scoped to the board used by this journey.
    store
        .add_board_moderator(board.0, moderator_id, Some(owner_id))
        .await?;
    let moderator_id_check: i64 =
        sqlx::query_scalar("SELECT id FROM users WHERE username='lifecycle_moderator'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(moderator_id_check, moderator_id);
    let delete_csrf = csrf(&server, &format!("/t/{thread_id}"), Some(&moderator_cookie)).await?;
    let delete_response = request(
        &server,
        "POST",
        &format!("/admin/post/{reply_post_id}/delete"),
        Some(&moderator_cookie),
        Some(&form_body(&[("csrf_token", &delete_csrf)])),
    )
    .await?;
    if delete_response.status != 303 {
        bail!(
            "post deletion returned HTTP {}: {}",
            delete_response.status,
            delete_response.body
        );
    }
    let deleted_state: (Option<chrono::DateTime<chrono::Utc>>, Option<i64>, i64) = sqlx::query_as(
        "SELECT deleted_at, deleted_by_user_id, (SELECT COUNT(*) FROM posts WHERE id=$1 AND deleted_at IS NULL) FROM posts WHERE id=$1",
    )
    .bind(reply_post_id)
    .fetch_one(&pool)
    .await?;
    if deleted_state.0.is_none() {
        bail!("post deletion returned success but the row is still visible");
    }
    let member_view = request(
        &server,
        "GET",
        &format!("/t/{thread_id}"),
        Some(&member_cookie),
        None,
    )
    .await?;
    if member_view.status != 200 || member_view.body.contains(REPLY_BODY) {
        bail!("ordinary member could still see the soft-deleted reply");
    }
    if member_view.body.matches("class=\"social-post\"").count() != 1 {
        bail!("ordinary member view did not hide exactly the deleted reply");
    }
    if board_reply_count(
        &request(&server, "GET", "/b/lifecycle", None, None)
            .await?
            .body,
        THREAD_TITLE,
    )? != "1"
    {
        bail!("soft delete incorrectly changed the maintained historical reply count");
    }

    let governance_csrf = csrf(&server, "/governance/trash", Some(&owner_cookie)).await?;
    let restore_response = request(
        &server,
        "POST",
        &format!("/governance/post/{reply_post_id}/restore"),
        Some(&owner_cookie),
        Some(&form_body(&[("csrf_token", &governance_csrf)])),
    )
    .await?;
    if restore_response.status != 303 {
        bail!(
            "post restore returned HTTP {}: {}",
            restore_response.status,
            restore_response.body
        );
    }
    let restored_view = request(&server, "GET", &format!("/t/{thread_id}"), None, None).await?;
    if restored_view.status != 200 || !restored_view.body.contains(REPLY_BODY) {
        bail!("restored reply was not publicly visible");
    }
    if restored_view.body.matches("class=\"social-post\"").count() != 2 {
        bail!("restored view did not contain exactly two visible posts");
    }
    if board_reply_count(
        &request(&server, "GET", "/b/lifecycle", None, None)
            .await?
            .body,
        THREAD_TITLE,
    )? != "1"
    {
        bail!("restore changed the maintained reply count");
    }

    assert_audit(
        &pool,
        "post.soft_delete",
        "post",
        reply_post_id,
        moderator_id,
    )
    .await?;
    assert_audit(&pool, "post.restore", "post", reply_post_id, owner_id).await?;
    report.complete(
        step,
        &["moderator delete and owner restore audit lifecycle"],
    );

    let step = report.step("final_postgresql_state");
    let final_state: (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<i64>,
        i64,
        i64,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT p.deleted_at, p.deleted_by_user_id, th.reply_count,
                (SELECT COUNT(*) FROM posts WHERE thread_id=p.thread_id AND deleted_at IS NULL),
                p.is_anonymous, (SELECT is_anonymous FROM posts WHERE id=$2)
         FROM posts p JOIN threads th ON th.id=p.thread_id WHERE p.id=$1",
    )
    .bind(reply_post_id)
    .bind(first_post_id)
    .fetch_one(&pool)
    .await?;
    if final_state.0.is_some()
        || final_state.1.is_some()
        || final_state.2 != 1
        || final_state.3 != 2
    {
        bail!("final database state disagrees with restored two-post lifecycle: {final_state:?}");
    }
    if !final_state.4 || !final_state.5 {
        bail!("anonymous flags were not persisted for both posts");
    }
    let _: i64 = sqlx::query_scalar("SELECT id FROM users WHERE id=$1")
        .bind(member_id)
        .fetch_one(&pool)
        .await?;
    report.complete(
        step,
        &["final PostgreSQL lifecycle counters and anonymous flags"],
    );

    Ok(())
}
