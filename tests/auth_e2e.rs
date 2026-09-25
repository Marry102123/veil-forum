//! End-to-end authentication journey over the real axum router and PostgreSQL.
//!
//! Failure modes covered before implementation:
//! 1. First-run bootstrap does not create exactly one `admin` owner with a
//!    verifiable password hash.
//! 2. CSRF or same-origin checks do not reject forged form submissions.
//! 3. An administrator cannot create a real invite row through HTTP.
//! 4. A missing, already used, or expired invite creates a user or is
//!    otherwise accepted.
//! 5. Registration is not atomic with invite consumption, or a duplicate
//!    username consumes the invite that was presented with it.
//! 6. A successful registration does not persist the user and issue a usable
//!    session cookie.
//! 7. Valid credentials fail, or bad/unknown credentials are accepted.
//! 8. Logout leaves the database session usable or fails to expire the cookie.
//! 9. Password change accepts the wrong current password or stores an unusable
//!    hash, or a pre-change session survives while the changing session does
//!    not.
//! 10. HTTP redirects, Set-Cookie attributes, database rows, and final
//!     authenticated/unauthenticated behavior disagree.
//!
//! Reproduction:
//! `DATABASE_URL=postgres://veil:veil@localhost/veil_forum_test \
//!  cargo test --test auth_e2e -- --nocapture`
//! `sqlx::test` creates and migrates an isolated PostgreSQL database per case.
//! The command writes a credential-free JSON report to
//! `target/auth-e2e-report.json` for success, error, and panic outcomes.

use anyhow::Context;
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use chrono::{SecondsFormat, Utc};
use sqlx::PgPool;
use tower::ServiceExt;
use veil_forum::{captcha, handler, pow, store::Store};

const ADMIN_PASSWORD: &str = "Glacier-Maple7-Raven";
const MEMBER_PASSWORD: &str = "Harbor-Cedar9-Phoenix";
const NEW_PASSWORD: &str = "Juniper-Quartz5-Falcon";
const WEAK_PASSWORD: &str = "password";

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
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/auth-e2e-report.json");
        Self {
            test: "authentication_registration_login_logout_and_password_change",
            path,
            started_at: utc_now(),
            ended_at: None,
            result: "failed",
            failed_step: Some("fixture_setup"),
            expected_checks: vec![
                "admin seed and password hash",
                "application setup",
                "secure session cookie attributes",
                "CSRF and invite lifecycle",
                "registration atomicity and weak password rejection",
                "login rejection and ban enforcement",
                "logout and session cleanup",
                "user weak password rejection and password change",
                "admin weak password rejection",
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
                "fixtures": ["first-run admin", "single-use invite", "member account"],
                "secrets": "test-only values excluded"
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
            "reproduce_command": "DATABASE_URL=<test-postgres-url> cargo test --test auth_e2e -- --nocapture",
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

async fn app_with_store(pool: &PgPool) -> anyhow::Result<(axum::Router, Store)> {
    let store = Store { pool: pool.clone() };
    store.seed_defaults().await?;
    let state = handler::AppState {
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: veil_forum::rate_limit::Limits::new(),
        secure_session_cookie: true,
        store: store.clone(),
    };
    Ok((handler::routes(state), store))
}

async fn request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> anyhow::Result<Response> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "forum.test")
        .header(header::ORIGIN, "http://forum.test");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    if form.is_some() {
        req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let req = req.body(Body::from(form.unwrap_or_default().to_owned()))?;
    Ok(app.clone().oneshot(req).await?)
}

async fn get(app: &axum::Router, uri: &str, cookie: Option<&str>) -> anyhow::Result<Response> {
    request(app, Method::GET, uri, cookie, None).await
}

async fn post_form(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
    form: &str,
) -> anyhow::Result<Response> {
    request(app, Method::POST, uri, cookie, Some(form)).await
}

async fn csrf(app: &axum::Router, uri: &str, cookie: Option<&str>) -> anyhow::Result<String> {
    let response = get(app, uri, cookie).await?;
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).context("CSRF token missing")? + marker.len();
    let end = html[start..].find('"').context("unterminated CSRF token")? + start;
    Ok(html[start..end].to_owned())
}

fn session_cookie(response: &Response) -> anyhow::Result<String> {
    let value = response
        .headers()
        .get(header::SET_COOKIE)
        .context("Set-Cookie missing")?
        .to_str()?;
    let pair = value.split(';').next().unwrap_or_default();
    anyhow::ensure!(pair.starts_with("session_id="), "unexpected cookie {value}");
    Ok(pair.to_owned())
}

fn assert_secure_session_cookie(response: &Response) -> anyhow::Result<()> {
    let value = response
        .headers()
        .get(header::SET_COOKIE)
        .context("Set-Cookie missing")?
        .to_str()?;
    anyhow::ensure!(
        value.contains("; Secure"),
        "missing Secure attribute: {value}"
    );
    anyhow::ensure!(
        value.contains("; HttpOnly"),
        "missing HttpOnly attribute: {value}"
    );
    anyhow::ensure!(
        value.contains("; SameSite=Strict"),
        "missing SameSite=Strict attribute: {value}"
    );
    Ok(())
}

fn cookie_value<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    cookie.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

async fn login(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> anyhow::Result<(Response, String)> {
    let anonymous = csrf(app, "/login", None).await?;
    let form = format!(
        "csrf_token={anonymous}&username={username}&password={password}",
        username = username,
        password = password
    );
    let response = post_form(app, "/login", None, &form).await?;
    assert_secure_session_cookie(&response)?;
    let cookie = session_cookie(&response)?;
    Ok((response, cookie))
}

#[sqlx::test]
async fn authentication_registration_login_logout_and_password_change(
    pool: PgPool,
) -> anyhow::Result<()> {
    let mut report = E2eReport::start();
    let step = report.step("admin_seed");
    // Exercise the real first-run administrator seed. No user exists in the
    // isolated database at this point.
    unsafe {
        std::env::set_var("VEIL_ADMIN_PASSWORD", ADMIN_PASSWORD);
    }
    let seed_result = veil_forum::auth::ensure_admin(&pool).await;
    unsafe {
        std::env::remove_var("VEIL_ADMIN_PASSWORD");
    }
    seed_result?;

    let admin_row: (i64, String, bool, bool, i64) = sqlx::query_as(
        "SELECT u.id, u.password_hash, u.is_admin, u.is_banned,
                (SELECT COUNT(*) FROM user_roles r WHERE r.user_id=u.id AND r.role_name='owner')
         FROM users u WHERE u.username='admin'",
    )
    .fetch_one(&pool)
    .await?;
    assert!(admin_row.2);
    assert!(!admin_row.3);
    assert_eq!(admin_row.4, 1);
    assert!(veil_forum::auth::verify_password(
        &admin_row.1,
        ADMIN_PASSWORD
    ));
    report.complete(step, &["admin seed and password hash"]);

    let step = report.step("application_and_config_setup");
    let (app, store) = app_with_store(&pool).await?;
    // Keep this journey focused on auth while still crossing every real handler.
    store.set_config("registration_pow_enabled", "0").await?;
    store.set_config("login_pow_enabled", "0").await?;
    store.set_config("totp_enabled", "0").await?;
    report.complete(step, &["application setup"]);
    let step = report.step("invite_and_registration");

    let (admin_response, admin_cookie) = login(&app, "admin", ADMIN_PASSWORD).await?;
    assert_eq!(admin_response.status(), StatusCode::SEE_OTHER);
    assert!(!cookie_value(&admin_cookie, "session_id")
        .context("admin session id missing")?
        .is_empty());

    // A forged form without CSRF must be rejected at the HTTP boundary.
    let forged = post_form(
        &app,
        "/admin/invite/create",
        Some(&admin_cookie),
        "count=1&max_uses=1",
    )
    .await?;
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);

    // A real administrator invite is created through HTTP, then used as the
    // registration journey's input.
    let before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_codes")
        .fetch_one(&pool)
        .await?;
    let admin_csrf = csrf(&app, "/admin/settings", Some(&admin_cookie)).await?;
    let create_invite = post_form(
        &app,
        "/admin/invite/create",
        Some(&admin_cookie),
        &format!("csrf_token={admin_csrf}&count=1&max_uses=1&expires_days=0&note=auth-e2e"),
    )
    .await?;
    assert_eq!(create_invite.status(), StatusCode::SEE_OTHER);
    let after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_codes")
        .fetch_one(&pool)
        .await?;
    assert_eq!(after.0, before.0 + 1);
    let (valid_invite,): (String,) = sqlx::query_as(
        "SELECT code FROM invite_codes WHERE note='auth-e2e' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO invite_codes(code,created_by,created_at,max_uses,use_count,expires_at,note)
         VALUES('EXPIRED-AUTH-E2E',$1,now(),1,0,now()-interval '1 minute','expired')",
    )
    .bind(admin_row.0)
    .execute(&pool)
    .await?;

    // Missing and expired invites are rejected without creating users.
    for invite in ["MISSING-AUTH-E2E", "EXPIRED-AUTH-E2E"] {
        let token = csrf(&app, "/register", None).await?;
        let response = post_form(
            &app,
            "/register",
            None,
            &format!(
                "csrf_token={token}&username=member_{invite}&password={MEMBER_PASSWORD}&invite_code={invite}"
            ),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    // Duplicate username is rejected atomically, and the valid invite remains
    // available for the actual registration.
    let token = csrf(&app, "/register", None).await?;
    let duplicate = post_form(
        &app,
        "/register",
        None,
        &format!(
            "csrf_token={token}&username=admin&password={MEMBER_PASSWORD}&invite_code={valid_invite}"
        ),
    )
    .await?;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    let invite_state: (i64, Option<i64>) =
        sqlx::query_as("SELECT use_count,used_by FROM invite_codes WHERE code=$1")
            .bind(&valid_invite)
            .fetch_one(&pool)
            .await?;
    assert_eq!(invite_state, (0, None));

    // A weak registration password is rejected before invite consumption, and
    // the submitted invitation remains available for the successful journey.
    let token = csrf(&app, "/register", None).await?;
    let weak_registration = post_form(
        &app,
        "/register",
        None,
        &format!(
            "csrf_token={token}&username=weak_member_e2e&password={WEAK_PASSWORD}&invite_code={valid_invite}"
        ),
    )
    .await?;
    assert_eq!(weak_registration.status(), StatusCode::BAD_REQUEST);
    assert!(weak_registration
        .headers()
        .get(header::SET_COOKIE)
        .is_none());
    let weak_user: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE username='weak_member_e2e'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(weak_user.0, 0);
    let weak_invite_state: (i64, Option<i64>) =
        sqlx::query_as("SELECT use_count,used_by FROM invite_codes WHERE code=$1")
            .bind(&valid_invite)
            .fetch_one(&pool)
            .await?;
    assert_eq!(weak_invite_state, (0, None));

    // Real successful registration, Set-Cookie, persisted user, and consumed
    // invite are all part of the same observable journey.
    let token = csrf(&app, "/register", None).await?;
    let registered = post_form(
        &app,
        "/register",
        None,
        &format!(
            "csrf_token={token}&username=member_e2e&password={MEMBER_PASSWORD}&invite_code={valid_invite}"
        ),
    )
    .await?;
    assert_eq!(registered.status(), StatusCode::SEE_OTHER);
    assert_secure_session_cookie(&registered)?;
    let member_cookie = session_cookie(&registered)?;
    let _ = cookie_value(&member_cookie, "session_id").context("member cookie missing")?;
    let member: (i64, bool, String) =
        sqlx::query_as("SELECT id,is_admin,password_hash FROM users WHERE username='member_e2e'")
            .fetch_one(&pool)
            .await?;
    assert!(!member.1);
    assert!(veil_forum::auth::verify_password(
        &member.2,
        MEMBER_PASSWORD
    ));
    let consumed: (i64, Option<i64>) =
        sqlx::query_as("SELECT use_count,used_by FROM invite_codes WHERE code=$1")
            .bind(&valid_invite)
            .fetch_one(&pool)
            .await?;
    assert_eq!(consumed, (1, Some(member.0)));

    // The consumed invite is single-use and cannot create a second account.
    let token = csrf(&app, "/register", None).await?;
    let reused = post_form(
        &app,
        "/register",
        None,
        &format!(
            "csrf_token={token}&username=second_member&password={MEMBER_PASSWORD}&invite_code={valid_invite}"
        ),
    )
    .await?;
    assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    let second_member: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE username='second_member'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(second_member.0, 0);
    report.complete(
        step,
        &[
            "CSRF and invite lifecycle",
            "registration atomicity and weak password rejection",
            "secure session cookie attributes",
        ],
    );

    let step = report.step("admin_weak_password");
    let admin_session = cookie_value(&admin_cookie, "session_id").unwrap();
    let admin_session_digest = veil_forum::auth::digest_token(admin_session);
    let admin_hash_before: (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE id=$1")
            .bind(admin_row.0)
            .fetch_one(&pool)
            .await?;
    let admin_csrf = csrf(&app, "/admin/settings", Some(&admin_cookie)).await?;
    let weak_admin = post_form(
        &app,
        "/admin/change-password",
        Some(&admin_cookie),
        &format!(
            "csrf_token={admin_csrf}&old_password={ADMIN_PASSWORD}&new_password={WEAK_PASSWORD}"
        ),
    )
    .await?;
    assert_eq!(weak_admin.status(), StatusCode::BAD_REQUEST);
    assert!(weak_admin.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        to_bytes(weak_admin.into_body(), usize::MAX).await?.as_ref(),
        b"weak password"
    );
    let admin_hash_after: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id=$1")
        .bind(admin_row.0)
        .fetch_one(&pool)
        .await?;
    assert_eq!(admin_hash_after, admin_hash_before);
    let admin_session_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&admin_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(admin_session_after.0, 1);
    report.complete(step, &["admin weak password rejection"]);

    let step = report.step("login_logout_and_ban");
    let account = get(&app, "/account", Some(&member_cookie)).await?;
    assert_eq!(account.status(), StatusCode::OK);

    // Unknown username and wrong password both fail and issue no cookie.
    let token = csrf(&app, "/login", None).await?;
    let unknown = post_form(
        &app,
        "/login",
        None,
        &format!("csrf_token={token}&username=absent_e2e&password={MEMBER_PASSWORD}"),
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::FORBIDDEN);
    assert!(unknown.headers().get(header::SET_COOKIE).is_none());

    let token = csrf(&app, "/login", None).await?;
    let wrong = post_form(
        &app,
        "/login",
        None,
        &format!("csrf_token={token}&username=member_e2e&password=incorrect"),
    )
    .await?;
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    assert!(wrong.headers().get(header::SET_COOKIE).is_none());
    let unknown_body = to_bytes(unknown.into_body(), usize::MAX).await?;
    let wrong_body = to_bytes(wrong.into_body(), usize::MAX).await?;
    assert_eq!(unknown_body, wrong_body);
    assert_eq!(unknown_body.as_ref(), b"invalid credentials");

    store.set_user_banned(member.0, true).await?;
    let token = csrf(&app, "/login", None).await?;
    let banned = post_form(
        &app,
        "/login",
        None,
        &format!("csrf_token={token}&username=member_e2e&password={MEMBER_PASSWORD}"),
    )
    .await?;
    assert_eq!(banned.status(), StatusCode::FORBIDDEN);
    assert!(banned.headers().get(header::SET_COOKIE).is_none());
    let banned_body = to_bytes(banned.into_body(), usize::MAX).await?;
    assert_eq!(banned_body, wrong_body);
    store.set_user_banned(member.0, false).await?;

    let (login_response, member_cookie) = login(&app, "member_e2e", MEMBER_PASSWORD).await?;
    assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
    let member_session = cookie_value(&member_cookie, "session_id").unwrap();
    let member_session_digest = veil_forum::auth::digest_token(member_session);
    let session_exists: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1 AND user_id=$2")
            .bind(&member_session_digest)
            .bind(member.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(session_exists.0, 1);

    // Logout removes the server-side session and expires the browser cookie.
    let logout_csrf = csrf(&app, "/account", Some(&member_cookie)).await?;
    let logout = post_form(
        &app,
        "/logout",
        Some(&member_cookie),
        &format!("csrf_token={logout_csrf}"),
    )
    .await?;
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    let expired_cookie = session_cookie(&logout)?;
    assert!(cookie_value(&expired_cookie, "session_id")
        .context("logout cookie missing")?
        .is_empty());
    let after_logout: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&member_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(after_logout.0, 0);
    report.complete(
        step,
        &[
            "login rejection and ban enforcement",
            "logout and session cleanup",
        ],
    );

    // Create genuine pre-change sessions, then change the password over HTTP.
    // Every old cookie must stop working, and the response must carry a new
    // session that represents the credential-change transaction.
    let (login_response, current_cookie) = login(&app, "member_e2e", MEMBER_PASSWORD).await?;
    assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
    let old_session = store.create_session(member.0).await?;
    let old_session_digest = veil_forum::auth::digest_token(&old_session);
    let old_cookie = format!("session_id={old_session}");
    let step = report.step("password_change");
    let old_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&old_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(old_before.0, 1);

    let current_session = cookie_value(&current_cookie, "session_id").unwrap();
    let current_session_digest = veil_forum::auth::digest_token(current_session);
    let current_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&current_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(current_before.0, 1);

    let account_csrf = csrf(&app, "/account", Some(&current_cookie)).await?;
    let hash_before: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id=$1")
        .bind(member.0)
        .fetch_one(&pool)
        .await?;
    let weak = post_form(
        &app,
        "/account/password",
        Some(&current_cookie),
        &format!(
            "csrf_token={account_csrf}&old_password={MEMBER_PASSWORD}&new_password={WEAK_PASSWORD}&repeat_password={WEAK_PASSWORD}"
        ),
    )
    .await?;
    assert_eq!(weak.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        weak.headers()[header::LOCATION],
        "/account?err=weak_password"
    );
    assert!(weak.headers().get(header::SET_COOKIE).is_none());
    let hash_after: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id=$1")
        .bind(member.0)
        .fetch_one(&pool)
        .await?;
    assert_eq!(hash_after, hash_before);
    assert!(veil_forum::auth::verify_password(
        &hash_after.0,
        MEMBER_PASSWORD
    ));
    assert!(!veil_forum::auth::verify_password(
        &hash_after.0,
        WEAK_PASSWORD
    ));
    let current_after_weak: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&current_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(current_after_weak.0, 1);
    let old_after_weak: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&old_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(old_after_weak.0, 1);

    let account_csrf = csrf(&app, "/account", Some(&current_cookie)).await?;
    let wrong_current = post_form(
        &app,
        "/account/password",
        Some(&current_cookie),
        &format!(
            "csrf_token={account_csrf}&old_password=wrong&new_password={NEW_PASSWORD}&repeat_password={NEW_PASSWORD}"
        ),
    )
    .await?;
    assert_eq!(wrong_current.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        wrong_current.headers()[header::LOCATION],
        "/account?err=bad_password"
    );
    let unchanged: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id=$1")
        .bind(member.0)
        .fetch_one(&pool)
        .await?;
    assert!(veil_forum::auth::verify_password(
        &unchanged.0,
        MEMBER_PASSWORD
    ));

    let account_csrf = csrf(&app, "/account", Some(&current_cookie)).await?;
    let changed = post_form(
        &app,
        "/account/password",
        Some(&current_cookie),
        &format!(
            "csrf_token={account_csrf}&old_password={MEMBER_PASSWORD}&new_password={NEW_PASSWORD}&repeat_password={NEW_PASSWORD}"
        ),
    )
    .await?;
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        changed.headers()[header::LOCATION],
        "/account?ok=password_changed"
    );
    let rotated_cookie = cookie_value(
        changed
            .headers()
            .get(header::SET_COOKIE)
            .context("password rotation cookie missing")?
            .to_str()?,
        "session_id",
    )
    .context("password rotation session_id missing")?
    .to_owned();
    assert!(!rotated_cookie.is_empty());
    let rotated_digest = veil_forum::auth::digest_token(&rotated_cookie);
    let rotated_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1 AND user_id=$2")
            .bind(&rotated_digest)
            .bind(member.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(rotated_count.0, 1);

    let hash: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id=$1")
        .bind(member.0)
        .fetch_one(&pool)
        .await?;
    assert!(veil_forum::auth::verify_password(&hash.0, NEW_PASSWORD));
    assert!(!veil_forum::auth::verify_password(&hash.0, MEMBER_PASSWORD));
    let old_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&old_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(old_after.0, 0);
    let current_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id=$1")
        .bind(&current_session_digest)
        .fetch_one(&pool)
        .await?;
    assert_eq!(current_after.0, 0);
    let old_http = get(&app, "/account", Some(&old_cookie)).await?;
    assert_eq!(old_http.status(), StatusCode::SEE_OTHER);
    assert_eq!(old_http.headers()[header::LOCATION], "/login");

    let current_http = get(
        &app,
        "/account",
        Some(&format!("session_id={rotated_cookie}")),
    )
    .await?;
    assert_eq!(current_http.status(), StatusCode::OK);
    let (_, new_cookie) = login(&app, "member_e2e", NEW_PASSWORD).await?;
    assert!(!cookie_value(&new_cookie, "session_id")
        .context("new login cookie missing")?
        .is_empty());
    report.complete(step, &["user weak password rejection and password change"]);

    report.succeed()?;
    Ok(())
}
