//! Real HTTP search and privacy E2E coverage.
//!
//! Failure modes exercised through `GET /search` and checked against PostgreSQL:
//! - a public post is returned to a visitor and a private post is not;
//! - an authenticated member sees the private post, so the difference is not a
//!   missing result set caused by fixture creation;
//! - a soft-deleted post is absent even though its row remains in PostgreSQL;
//! - Unicode, `%` and `_` are literal user input, while a long input is bounded
//!   without turning a request into an error or a broad match;
//! - reserved characters and Unicode remain literal after URL decoding, and
//!   total/page metadata remains correct for a multi-page result.
//!
//! The application is driven only through its HTTP router. The pool is used
//! solely to create realistic rows and to verify the final database state.

use axum::{
    body::to_bytes,
    http::{Request, StatusCode},
};
use chrono::{SecondsFormat, Utc};
use sqlx::PgPool;
use tower::ServiceExt;
use veil_forum::{captcha, handler, pow, rate_limit, store::Store};

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
            test: "http_search_preserves_visibility_deletion_and_input_boundaries",
            path: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/search-privacy-e2e-report.json"),
            started_at: utc_now(),
            ended_at: None,
            result: "failed",
            failed_step: Some("fixture_setup"),
            expected_checks: vec![
                "public and private visibility",
                "fixture setup",
                "soft deletion persistence and exclusion",
                "literal Unicode and wildcard input",
                "long query boundary",
                "multi-page totals",
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

    fn succeed(&mut self) -> anyhow::Result<()> {
        self.result = "passed";
        self.failed_step = None;
        if let Err(error) = self.write() {
            self.result = "failed";
            self.failed_step = Some("report_write");
            return Err(error);
        }
        Ok(())
    }

    fn write(&mut self) -> anyhow::Result<()> {
        self.ended_at = Some(utc_now());
        let report = serde_json::json!({
            "schema_version": 1,
            "test": self.test,
            "started_at_utc": self.started_at,
            "ended_at_utc": self.ended_at,
            "input_summary": {
                "database": "sqlx isolated PostgreSQL database",
                "transport": "real axum router",
                "queries": ["visibility markers", "Unicode", "wildcards", "4096-byte query", "paging"],
                "secrets": "test-only session values excluded"
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
            "reproduce_command": "DATABASE_URL=<test-postgres-url> cargo test --test search_privacy_e2e -- --nocapture",
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

async fn app(pool: &PgPool) -> anyhow::Result<(axum::Router, Store)> {
    let store = Store { pool: pool.clone() };
    store.seed_defaults().await?;
    let state = handler::AppState {
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: rate_limit::Limits::new(),
        secure_session_cookie: false,
        store: store.clone(),
    };
    Ok((handler::routes(state), store))
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        encoded.push_str(&format!("%{byte:02X}"));
    }
    encoded
}

async fn get_search(
    application: &axum::Router,
    query: &str,
    page: usize,
    cookie: Option<&str>,
) -> anyhow::Result<(StatusCode, String)> {
    let mut request = Request::get(format!("/search?q={}&page={page}", percent_encode(query)))
        .body(axum::body::Body::empty())?;
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(axum::http::header::COOKIE, cookie.parse()?);
    }
    let response = application.clone().oneshot(request).await?;
    let status = response.status();
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    Ok((status, body))
}

fn result_count(html: &str) -> usize {
    html.matches("class=\"card\" style=\"padding:7px 9px\"")
        .count()
}

#[sqlx::test]
async fn http_search_preserves_visibility_deletion_and_input_boundaries(
    pool: PgPool,
) -> anyhow::Result<()> {
    let mut report = E2eReport::start();
    let step = report.step("fixture_setup");
    let (application, store) = app(&pool).await?;
    let member = store.create_user("search-member", "hash", false).await?;
    let public_board = store
        .get_board_by_slug("general")
        .await?
        .expect("default board");
    let private_board = store
        .create_board("private", "Private", "members", false, false)
        .await?;

    let public_thread = store
        .create_thread(
            public_board.id,
            member,
            "public search marker",
            "public body",
            "<p>public body</p>",
            false,
        )
        .await?;
    let _private_thread = store
        .create_thread(
            private_board,
            member,
            "private search marker",
            "private body",
            "<p>private body</p>",
            false,
        )
        .await?;
    let deleted_post = store
        .create_post(
            public_thread,
            public_board.id,
            member,
            false,
            "deleted marker",
            "<p>deleted marker</p>",
        )
        .await?;
    assert!(store.soft_delete_post(deleted_post, Some(member)).await?);
    report.complete(step, &["fixture setup"]);

    let step = report.step("visibility_and_deletion");
    let (status, visitor) = get_search(&application, "search marker", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result_count(&visitor), 1);
    assert!(visitor.contains(">public search marker</a>"));
    assert!(!visitor.contains(">private search marker</a>"));
    assert!(!visitor.contains(">deleted marker</a>"));
    assert!(visitor.contains("1 results"));

    let (status, private_member) = get_search(
        &application,
        "private search marker",
        1,
        Some("session_id=not-a-session"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(private_member.contains("0 results"));
    assert_eq!(result_count(&private_member), 0);
    let session = store.create_session(member).await?;
    let (status, private_member) = get_search(
        &application,
        "private search marker",
        1,
        Some(&format!("session_id={session}")),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result_count(&private_member), 1);
    assert!(private_member.contains(">private search marker</a>"));
    assert!(private_member.contains("1 results"));

    let (status, deleted) = get_search(&application, "deleted marker", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(deleted.contains("0 results"));
    let still_present: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM posts WHERE id=$1 AND deleted_at IS NOT NULL")
            .bind(deleted_post)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        still_present.0, 1,
        "deletion must be observable in PostgreSQL"
    );
    report.complete(
        step,
        &[
            "public and private visibility",
            "soft deletion persistence and exclusion",
        ],
    );

    let step = report.step("input_boundaries");
    let (status, unicode) = get_search(&application, "中文检索", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(unicode.contains("0 results"));
    let unicode_thread = store
        .create_thread(
            public_board.id,
            member,
            "中文检索主题",
            "Unicode 内容",
            "<p>Unicode 内容</p>",
            false,
        )
        .await?;
    let _ = unicode_thread;
    let (status, unicode) = get_search(&application, "中文检索", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(unicode.contains("中文检索主题"));

    let wildcard_thread = store
        .create_thread(
            public_board.id,
            member,
            "wildcard safety",
            "literal 50% and underscore _",
            "<p>wildcard</p>",
            false,
        )
        .await?;
    let _ = wildcard_thread;
    let (status, wildcard) = get_search(&application, "%", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(wildcard.contains("1 results"));
    let (status, underscore) = get_search(&application, "_", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(underscore.contains("1 results"));
    report.complete(step, &["literal Unicode and wildcard input"]);

    let step = report.step("long_query");
    let long_query = "x".repeat(4096);
    let (status, long) = get_search(&application, &long_query, 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(long.contains("0 results"));
    report.complete(step, &["long query boundary"]);

    let step = report.step("pagination");
    let page_thread = store
        .create_thread(
            public_board.id,
            member,
            "page marker",
            "page marker",
            "<p>page marker</p>",
            false,
        )
        .await?;
    for index in 0..21 {
        store
            .create_post(
                page_thread,
                public_board.id,
                member,
                false,
                &format!("page item {index}"),
                "<p>page</p>",
            )
            .await?;
    }
    let (status, first_page) = get_search(&application, "page item", 1, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(first_page.contains("21 results"));
    assert!(first_page.contains("Page 1/2"));
    assert_eq!(result_count(&first_page), 20);
    let (status, page_html) = get_search(&application, "page item", 2, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page_html.contains("Page 2/2"));
    assert_eq!(result_count(&page_html), 1);

    report.complete(step, &["multi-page totals"]);
    report.succeed()?;
    Ok(())
}
