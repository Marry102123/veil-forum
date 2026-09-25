//! Real HTTP + real PostgreSQL governance E2E.
//!
//! Failure modes exercised by the single end-to-end journey below:
//! 1. An owner cannot grant or revoke a role through the public HTTP form, or
//!    the response reports success without changing `user_roles`.
//! 2. A newly granted administrator retains governance access after revocation.
//! 3. An ordinary member can enter governance or mutate moderation state.
//! 4. A global moderator can moderate every board instead of only assigned boards.
//! 5. A report cannot be submitted/resolved/dismissed through HTTP, transitions
//!    to the wrong terminal state, or loses resolver/note/audit information.
//! 6. An unauthorized user can restore a soft-deleted thread, an authorized user
//!    cannot, or restoration leaves `deleted_at`/`deleted_by_user_id` inconsistent.
//! 7. The HTTP service and PostgreSQL transaction boundary diverge, so a response
//!    succeeds but the observable database state is not committed.
//!
//! Run with a PostgreSQL URL understood by sqlx, for example:
//! `DATABASE_URL=postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum \
//!   cargo test --test governance_e2e -- --nocapture`
//! The sqlx test harness creates and drops an isolated real database. A
//! credential-free JSON result is written atomically to
//! `target/governance-e2e-report.json` for success, error, and panic outcomes.

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use sqlx::{PgPool, Row};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{timeout, Duration},
};
use veil_forum::{
    captcha, handler, pow, rate_limit,
    store::{Role, Store},
};

const HOST: &str = "127.0.0.1";
const PASSWORD: &str = "Prairie-Quartz8-Cobalt";

struct E2eReport {
    test: &'static str,
    path: std::path::PathBuf,
    started_at: String,
    ended_at: Option<String>,
    result: &'static str,
    failed_step: Option<&'static str>,
    expected_checks: Vec<&'static str>,
    completed_checks: Vec<&'static str>,
    written: bool,
}

impl E2eReport {
    fn start() -> Self {
        Self {
            test: "governance_http_lifecycle_enforces_roles_scopes_reports_and_restore",
            path: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/governance-e2e-report.json"),
            started_at: utc_now(),
            ended_at: None,
            result: "failed",
            failed_step: Some("fixture_setup"),
            expected_checks: vec![
                "role grant and revoke lifecycle",
                "fixture setup",
                "real loopback TCP HTTP",
                "member and administrator authorization",
                "scoped moderator boundary",
                "report resolve and dismiss lifecycle",
                "soft delete and restore lifecycle",
                "database and audit final state",
            ],
            completed_checks: Vec::new(),
            written: false,
        }
    }

    fn step(&mut self, step: &'static str) -> &'static str {
        self.failed_step = Some(step);
        step
    }

    fn complete(&mut self, step: &str, checks: &[&'static str]) {
        if self.failed_step == Some(step) {
            self.completed_checks.extend_from_slice(checks);
            self.failed_step = None;
        }
    }

    fn succeed(&mut self) -> Result<()> {
        self.result = "passed";
        self.failed_step = None;
        if let Err(error) = self.write() {
            self.result = "failed";
            self.failed_step = Some("report_write");
            return Err(error);
        }
        Ok(())
    }

    fn write(&mut self) -> Result<()> {
        self.ended_at = Some(utc_now());
        let report = serde_json::json!({
            "schema_version": 1,
            "test": self.test,
            "started_at_utc": self.started_at,
            "ended_at_utc": self.ended_at,
            "input_summary": {
                "database": "sqlx isolated PostgreSQL database",
                "transport": "real loopback TCP HTTP",
                "identities": ["owner", "member", "scoped moderator"],
                "content": ["two boards", "reportable threads", "soft-deletion case"],
                "secrets": "test-only passwords, sessions, cookies, and TOTP state excluded"
            },
            "result": self.result,
            "failed_step": self.failed_step,
            "key_checks": {
                "expected": self.expected_checks,
                "completed": self.completed_checks
            },
            "artifacts": {
                "report_path": self.path,
                "log_path": serde_json::Value::Null,
                "log_policy": "no logs captured; raw cargo output is intentionally excluded"
            },
            "reproduce_command": "DATABASE_URL=<test-postgres-url> cargo test --test governance_e2e -- --nocapture",
            "credentials_included": false
        });
        let Some(parent) = self.path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(parent)?;
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        let temporary = self.path.with_extension("json.tmp");
        if let Err(error) = std::fs::write(&temporary, bytes) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        if let Err(error) = std::fs::rename(&temporary, &self.path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        self.written = true;
        Ok(())
    }
}

impl Drop for E2eReport {
    fn drop(&mut self) {
        if !self.written {
            let _ = self.write();
        }
    }
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

struct HttpResponse {
    status: u16,
    body: String,
}

struct HttpClient {
    authority: String,
}

impl HttpClient {
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        form: Option<&str>,
    ) -> Result<HttpResponse> {
        let body = form.unwrap_or_default();
        let host = self
            .authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(HOST);
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if let Some(cookie) = cookie {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        if form.is_some() {
            request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            request.push_str(&format!("Origin: http://{host}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));

        let mut stream = TcpStream::connect(&self.authority).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut raw = Vec::new();
        timeout(Duration::from_secs(15), stream.read_to_end(&mut raw)).await??;
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .context("HTTP response has no header terminator")?;
        // This header slice is UTF-8 because test-generated usernames, reasons,
        // and notes are ASCII. Cookie values are hexadecimal.
        let head = String::from_utf8(raw[..split].to_vec())?;
        let body = String::from_utf8(raw[split + 4..].to_vec())?;
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .context("HTTP status missing")?
            .parse::<u16>()?;
        Ok(HttpResponse { status, body })
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Result<HttpResponse> {
        self.request("GET", path, cookie, None).await
    }

    async fn post(
        &self,
        path: &str,
        cookie: Option<&str>,
        fields: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let encoded = fields
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        self.request("POST", path, cookie, Some(&encoded)).await
    }
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

async fn csrf(client: &HttpClient, path: &str, cookie: &str) -> Result<String> {
    let response = client.get(path, Some(cookie)).await?;
    anyhow::ensure!(
        response.status == 200,
        "GET {path} returned {}",
        response.status
    );
    let marker = "name=\"csrf_token\" value=\"";
    let start = response.body.find(marker).context("CSRF field missing")? + marker.len();
    let end = start
        + response.body[start..]
            .find('"')
            .context("CSRF token unterminated")?;
    Ok(response.body[start..end].to_owned())
}

async fn form_post(
    client: &HttpClient,
    page: &str,
    action: &str,
    cookie: &str,
    extra: &[(&str, &str)],
) -> Result<HttpResponse> {
    let token = csrf(client, page, cookie).await?;
    let mut fields = vec![("csrf_token", token.as_str())];
    fields.extend_from_slice(extra);
    client.post(action, Some(cookie), &fields).await
}

async fn fixture_user(store: &Store, username: &str) -> Result<(i64, String)> {
    let id = store
        .create_user(username, &veil_forum::auth::hash_password(PASSWORD)?, false)
        .await?;
    let session = store.create_session(id).await?;
    Ok((id, format!("session_id={session}")))
}

async fn count_role(pool: &PgPool, user_id: i64, role: &str) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_name=$2")
            .bind(user_id)
            .bind(role)
            .fetch_one(pool)
            .await?,
    )
}

async fn thread_flags(
    pool: &PgPool,
    thread_id: i64,
) -> Result<(bool, bool, Option<chrono::DateTime<chrono::Utc>>)> {
    let row = sqlx::query("SELECT is_locked,is_pinned,deleted_at FROM threads WHERE id=$1")
        .bind(thread_id)
        .fetch_one(pool)
        .await?;
    Ok((
        row.get("is_locked"),
        row.get("is_pinned"),
        row.get("deleted_at"),
    ))
}

#[sqlx::test]
async fn governance_http_lifecycle_enforces_roles_scopes_reports_and_restore(
    pool: PgPool,
) -> Result<()> {
    let mut report = E2eReport::start();
    let step = report.step("fixture_setup");
    let store = Store { pool: pool.clone() };
    store.seed_defaults().await?;

    // Fixtures establish identities, one global moderator role plus its sole board
    // scope, and reportable content. Every permission transition below is driven
    // over a real TCP HTTP request and checked against PostgreSQL afterward.
    let (owner_id, owner_cookie) = fixture_user(&store, "governance_owner").await?;
    store.grant_role(owner_id, Role::Owner, None).await?;
    let (member_id, member_cookie) = fixture_user(&store, "governance_member").await?;
    // Role grants require an active second factor. Activate a test-only TOTP
    // state before exercising the HTTP grant path; the secret is never exposed.
    let member_totp_secret = veil_forum::totp::generate_secret();
    store
        .activate_totp(member_id, &member_totp_secret, 0)
        .await?;
    let (moderator_id, moderator_cookie) = fixture_user(&store, "governance_moderator").await?;
    store
        .grant_role(moderator_id, Role::Moderator, Some(owner_id))
        .await?;
    let board_a = store
        .create_board("governance-a", "Governance A", "", false, true)
        .await?;
    let board_b = store
        .create_board("governance-b", "Governance B", "", false, true)
        .await?;
    store
        .add_board_moderator(board_a, moderator_id, Some(owner_id))
        .await?;
    let thread_a = store
        .create_thread(
            board_a,
            member_id,
            "Scoped moderation target",
            "A",
            "<p>A</p>",
            false,
        )
        .await?;
    let thread_b = store
        .create_thread(
            board_b,
            member_id,
            "Out of scope target",
            "B",
            "<p>B</p>",
            false,
        )
        .await?;
    report.complete(step, &["fixture setup"]);

    let step = report.step("http_server");
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let authority = listener.local_addr()?.to_string();
    let state = handler::AppState {
        store: store.clone(),
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: rate_limit::Limits::new(),
        secure_session_cookie: false,
    };
    let app = handler::routes(state);
    let server: JoinHandle<Result<()>> =
        tokio::spawn(async move { axum::serve(listener, app).await.map_err(Into::into) });
    let client = HttpClient {
        authority: authority.clone(),
    };
    report.complete(step, &["real loopback TCP HTTP"]);

    let result = async {
        let step = report.step("member_denial_and_roles");
        // An ordinary member is denied before any privileged transition.
        anyhow::ensure!(client.get("/governance", Some(&member_cookie)).await?.status == 403);
        let denied = form_post(
            &client,
            &format!("/t/{thread_b}"),
            &format!("/admin/thread/{thread_b}/lock"),
            &member_cookie,
            &[],
        )
        .await?;
        anyhow::ensure!(denied.status == 403);
        anyhow::ensure!(!thread_flags(&pool, thread_b).await?.0);

        // Owner grants admin through HTTP, grants are immediately effective,
        // and an admin cannot manage roles because only the owner may do so.
        let granted = form_post(
            &client,
            "/governance/users",
            &format!("/governance/user/{member_id}/role"),
            &owner_cookie,
            &[("operation", "grant"), ("role", "admin")],
        ).await?;
        anyhow::ensure!(granted.status == 303, "grant status {}", granted.status);
        anyhow::ensure!(count_role(&pool, member_id, "admin").await? == 1);
        anyhow::ensure!(client.get("/governance", Some(&member_cookie)).await?.status == 200);
        let admin_role_attempt = form_post(
            &client,
            &format!("/t/{thread_b}"),
            &format!("/governance/user/{moderator_id}/role"),
            &member_cookie,
            &[("operation", "grant"), ("role", "admin")],
        ).await?;
        anyhow::ensure!(admin_role_attempt.status == 403);
        anyhow::ensure!(count_role(&pool, moderator_id, "admin").await? == 0);

        let revoked = form_post(
            &client,
            "/governance/users",
            &format!("/governance/user/{member_id}/role"),
            &owner_cookie,
            &[("operation", "revoke"), ("role", "admin")],
        ).await?;
        anyhow::ensure!(revoked.status == 303, "revoke status {}", revoked.status);
        anyhow::ensure!(count_role(&pool, member_id, "admin").await? == 0);
        anyhow::ensure!(client.get("/governance", Some(&member_cookie)).await?.status == 403);
        report.complete(
            step,
            &[
                "member and administrator authorization",
                "role grant and revoke lifecycle",
            ],
        );

        // The moderator can enter governance and lock only the assigned board.
        let step = report.step("moderator_scope");
        anyhow::ensure!(client.get("/governance", Some(&moderator_cookie)).await?.status == 200);
        let scoped = form_post(
            &client,
            &format!("/t/{thread_a}"),
            &format!("/admin/thread/{thread_a}/lock"),
            &moderator_cookie,
            &[],
        ).await?;
        anyhow::ensure!(scoped.status == 303, "scoped lock status {}", scoped.status);
        anyhow::ensure!(thread_flags(&pool, thread_a).await?.0);
        let out_of_scope = form_post(
            &client,
            &format!("/t/{thread_b}"),
            &format!("/admin/thread/{thread_b}/lock"),
            &moderator_cookie,
            &[],
        ).await?;
        anyhow::ensure!(out_of_scope.status == 403);
        anyhow::ensure!(!thread_flags(&pool, thread_b).await?.0);
        report.complete(step, &["scoped moderator boundary"]);

        // A member submits a report. The owner resolves it, then a second report
        // is dismissed. Terminal resolver, note and audit state are persisted.
        let step = report.step("report_lifecycle");
        let report_one_page = format!("/t/{thread_b}");
        let submitted = form_post(
            &client,
            &report_one_page,
            &format!("/report/thread/{thread_b}"),
            &member_cookie,
            &[("reason", "governance resolve case")],
        ).await?;
        anyhow::ensure!(submitted.status == 303, "report submit status {}", submitted.status);
        let report_one: i64 = sqlx::query_scalar(
            "SELECT id FROM reports WHERE target_id=$1 AND reason='governance resolve case' ORDER BY id DESC LIMIT 1",
        ).bind(thread_b).fetch_one(&pool).await?;
        let resolved = form_post(
            &client,
            "/governance/reports",
            &format!("/governance/report/{report_one}/resolve"),
            &owner_cookie,
            &[("note", "resolved through governance HTTP")],
        ).await?;
        anyhow::ensure!(resolved.status == 303);
        let report_row = sqlx::query("SELECT status,resolved_by_user_id,resolution_note,resolved_at FROM reports WHERE id=$1")
            .bind(report_one).fetch_one(&pool).await?;
        anyhow::ensure!(report_row.get::<String, _>("status") == "resolved");
        anyhow::ensure!(report_row.get::<Option<i64>, _>("resolved_by_user_id") == Some(owner_id));
        anyhow::ensure!(report_row.get::<Option<String>, _>("resolution_note").as_deref() == Some("resolved through governance HTTP"));
        anyhow::ensure!(report_row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("resolved_at").is_some());

        let submitted_two = form_post(
            &client,
            &report_one_page,
            &format!("/report/thread/{thread_b}"),
            &member_cookie,
            &[("reason", "governance dismiss case")],
        ).await?;
        anyhow::ensure!(submitted_two.status == 303);
        let report_two: i64 = sqlx::query_scalar(
            "SELECT id FROM reports WHERE target_id=$1 AND reason='governance dismiss case' ORDER BY id DESC LIMIT 1",
        ).bind(thread_b).fetch_one(&pool).await?;
        let dismissed = form_post(
            &client,
            "/governance/reports",
            &format!("/governance/report/{report_two}/dismiss"),
            &owner_cookie,
            &[("note", "dismissed through governance HTTP")],
        ).await?;
        anyhow::ensure!(dismissed.status == 303);
        let terminal: (String, Option<i64>, Option<String>, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT status,resolved_by_user_id,resolution_note,resolved_at FROM reports WHERE id=$1")
                .bind(report_two).fetch_one(&pool).await?;
        anyhow::ensure!(terminal.0 == "dismissed");
        anyhow::ensure!(terminal.1 == Some(owner_id));
        anyhow::ensure!(terminal.2.as_deref() == Some("dismissed through governance HTTP"));
        anyhow::ensure!(terminal.3.is_some());
        report.complete(step, &["report resolve and dismiss lifecycle"]);

        // Scoped moderator soft-deletes content. A member cannot restore it; the
        // owner can, and both deletion marker and actor marker are cleared.
        let step = report.step("delete_restore");
        let deleted = form_post(
            &client,
            &format!("/t/{thread_a}"),
            &format!("/admin/thread/{thread_a}/delete"),
            &moderator_cookie,
            &[],
        ).await?;
        anyhow::ensure!(deleted.status == 303);
        let deletion = sqlx::query("SELECT deleted_at,deleted_by_user_id FROM threads WHERE id=$1")
            .bind(thread_a).fetch_one(&pool).await?;
        anyhow::ensure!(deletion.get::<Option<chrono::DateTime<chrono::Utc>>, _>("deleted_at").is_some());
        anyhow::ensure!(deletion.get::<Option<i64>, _>("deleted_by_user_id") == Some(moderator_id));

        let denied_restore = form_post(
            &client,
            &format!("/t/{thread_b}"),
            &format!("/governance/thread/{thread_a}/restore"),
            &member_cookie,
            &[],
        ).await?;
        anyhow::ensure!(denied_restore.status == 403);
        anyhow::ensure!(thread_flags(&pool, thread_a).await?.2.is_some());
        let restored = form_post(
            &client,
            "/governance/trash",
            &format!("/governance/thread/{thread_a}/restore"),
            &owner_cookie,
            &[],
        ).await?;
        anyhow::ensure!(restored.status == 303);
        let restored_state = sqlx::query("SELECT deleted_at,deleted_by_user_id FROM threads WHERE id=$1")
            .bind(thread_a).fetch_one(&pool).await?;
        anyhow::ensure!(restored_state.get::<Option<chrono::DateTime<chrono::Utc>>, _>("deleted_at").is_none());
        anyhow::ensure!(restored_state.get::<Option<i64>, _>("deleted_by_user_id").is_none());
        report.complete(step, &["soft delete and restore lifecycle"]);

        let step = report.step("audit_final_state");
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE actor_user_id=$1 AND action IN ('role.change','report.resolved','report.dismissed','thread.soft_delete','thread.restore') AND success",
        ).bind(owner_id).fetch_one(&pool).await?;
        anyhow::ensure!(audit_count >= 5, "missing governance audit records: {audit_count}");
        report.complete(step, &["database and audit final state"]);

        Ok::<(), anyhow::Error>(())
    }.await;

    server.abort();
    result?;
    report.succeed()?;
    Ok(())
}
