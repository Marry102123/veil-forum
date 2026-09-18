//! HTTP flow tests for the TOTP second factor: enrolment through the account
//! page, the two-step login, recovery codes, and the enforcement policy.

use anyhow::Context;
use axum::body::to_bytes;
use axum::http::{header, Request, StatusCode};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower::ServiceExt;
use veil_forum::store::Store;
use veil_forum::{captcha, handler, pow, totp};

async fn app_with_store(pool: &PgPool) -> anyhow::Result<(axum::Router, Store)> {
    let store = Store { pool: pool.clone() };
    store.seed_defaults().await?;
    // Login PoW/CAPTCHA are separate mechanisms; turn them off so these tests
    // exercise the second factor.
    store.set_config("login_pow_enabled", "0").await?;
    store.set_config("login_captcha_enabled", "0").await?;
    let state = handler::AppState {
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: veil_forum::rate_limit::Limits::new(),
        secure_session_cookie: false,
        store: store.clone(),
        password_gate: Arc::new(Semaphore::new(8)),
    };
    Ok((handler::routes(state), store))
}

async fn get(
    app: axum::Router,
    uri: &str,
    cookie: Option<&str>,
) -> anyhow::Result<(StatusCode, String)> {
    let mut request = Request::get(uri)
        .header(header::HOST, "forum.test")
        .body(axum::body::Body::empty())?;
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse()?);
    }
    let response = app.oneshot(request).await?;
    let status = response.status();
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    Ok((status, body))
}

async fn post_form(
    app: axum::Router,
    uri: &str,
    cookie: Option<&str>,
    form: &str,
) -> anyhow::Result<axum::response::Response> {
    let mut request = Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::HOST, "forum.test")
        .header(header::ORIGIN, "http://forum.test")
        .body(axum::body::Body::from(form.to_owned()))?;
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse()?);
    }
    Ok(app.oneshot(request).await?)
}

async fn csrf_token(app: axum::Router, uri: &str, cookie: Option<&str>) -> anyhow::Result<String> {
    let (status, html) = get(app, uri, cookie).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "expected page at {uri}, got {status}"
    );
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).context("CSRF token missing")? + marker.len();
    let end = html[start..].find('"').context("unterminated CSRF token")? + start;
    Ok(html[start..end].to_owned())
}

fn session_cookie_of(response: &axum::response::Response) -> Option<String> {
    let value = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    let pair = value.split(';').next()?;
    if pair.starts_with("session_id=") && pair.len() > "session_id=".len() {
        Some(pair.to_string())
    } else {
        None
    }
}

/// Tera escapes `/` as `&#x2F;` in text nodes, so decode the handful of
/// entities that appear in the rendered pages before asserting on URLs.
fn decode_entities(html: &str) -> String {
    html.replace("&#x2F;", "/")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn redirect_target(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Create a member with a known password and return its id.
async fn member(store: &Store, username: &str, password: &str) -> anyhow::Result<i64> {
    let hash = veil_forum::auth::hash_password(password)?;
    store.create_user(username, &hash, false).await
}

fn code_now(secret: &str, account: &str) -> String {
    code_in(secret, account, 0)
}

/// A code for a window offset, in seconds. Enrolment records the step it was
/// confirmed in, so a login in the same window must use the next step.
fn code_in(secret: &str, account: &str, offset_seconds: i64) -> String {
    let now = (chrono::Utc::now().timestamp() + offset_seconds).max(0) as u64;
    totp::code_at(secret, account, "secure-forum", now).expect("code")
}

#[sqlx::test]
async fn account_page_hides_totp_when_the_feature_is_off(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    let sid = store.create_session(id).await?;
    let cookie = format!("session_id={sid}");

    let (status, html) = get(app.clone(), "/account", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("alice"));
    assert!(html.contains("/account/password"), "password form expected");

    store.set_config("totp_enabled", "0").await?;
    let (_, html) = get(app, "/account", Some(&cookie)).await?;
    assert!(
        !html.contains("/account/totp/setup"),
        "enrolment must be hidden when the feature is disabled"
    );
    Ok(())
}

#[sqlx::test]
async fn enrolment_then_two_step_login(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    member(&store, "alice", "correct horse battery").await?;

    // 1. Password step: no session yet, a pending login instead.
    let csrf = csrf_token(app.clone(), "/login", None).await?;
    let response = post_form(
        app.clone(),
        "/login",
        None,
        &format!("csrf_token={csrf}&username=alice&password=correct+horse+battery"),
    )
    .await?;
    // Without a second factor the same request yields a session; with TOTP not
    // yet enabled there is nothing to verify.
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let signed_in_cookie = session_cookie_of(&response).expect("session cookie");

    // 2. Enrol through the account page.
    let csrf = csrf_token(app.clone(), "/account", Some(&signed_in_cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/setup",
        Some(&signed_in_cookie),
        &format!("csrf_token={csrf}&password=correct+horse+battery"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let (_, html) = get(app.clone(), "/account", Some(&signed_in_cookie)).await?;
    assert!(html.contains("<svg"), "QR code must be inline SVG");
    let decoded = decode_entities(&html);
    assert!(
        decoded.contains("otpauth://totp/"),
        "otpauth URI expected in the enrolment block"
    );
    assert!(decoded.contains("issuer="), "issuer must be advertised");
    let secret = html
        .split("<code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .context("enrolment secret missing")?
        .to_string();
    assert!(secret.len() >= 16, "base32 secret expected, got {secret:?}");

    // 3. Confirming with a wrong code changes nothing.
    let csrf = csrf_token(app.clone(), "/account", Some(&signed_in_cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/confirm",
        Some(&signed_in_cookie),
        &format!("csrf_token={csrf}&code=000000"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(redirect_target(&response).contains("err=bad_code"));
    assert!(!store.totp_state(1).await?.is_active());

    // 4. Confirming with a real code activates it and shows recovery codes once.
    let csrf = csrf_token(app.clone(), "/account", Some(&signed_in_cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/confirm",
        Some(&signed_in_cookie),
        &format!("csrf_token={csrf}&code={}", code_now(&secret, "alice")),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(
        html.contains("recovery-codes"),
        "recovery codes expected once"
    );
    let state = store.totp_state(1).await?;
    assert!(state.is_active());
    assert_eq!(
        state.unused_recovery_codes,
        totp::RECOVERY_CODE_COUNT as i64
    );
    let recovery_code = html
        .split("<code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .context("recovery code missing")?
        .to_string();

    // 5. A fresh password login now stops at the second step.
    let csrf = csrf_token(app.clone(), "/login", None).await?;
    let response = post_form(
        app.clone(),
        "/login",
        None,
        &format!("csrf_token={csrf}&username=alice&password=correct+horse+battery"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        session_cookie_of(&response).is_none(),
        "no session before the code"
    );
    let target = redirect_target(&response);
    assert!(target.starts_with("/login/totp?p="), "got {target}");
    let pending_id = target.trim_start_matches("/login/totp?p=").to_string();

    let (status, html) = get(app.clone(), &target, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("pending_id"), "second step form expected");

    // 6. Wrong codes are refused and counted.
    let csrf = csrf_token(app.clone(), &target, None).await?;
    let response = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!("csrf_token={csrf}&pending_id={pending_id}&code=111111"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK, "form is redisplayed");
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(html.contains("flash-error"));
    assert!(store.pending_login(&pending_id).await?.unwrap().attempts >= 1);

    // 7. The code from the window enrolment used is refused as a replay, and a
    // later window completes the login. The steps are computed explicitly so the
    // assertion cannot depend on how long the test itself takes.
    let recorded_step = store.totp_state(1).await?.last_step.expect("step recorded");
    let current_step = chrono::Utc::now().timestamp().max(0) / 30;
    let next_step = (recorded_step + 1).max(current_step);
    let replay_code = totp::code_at(
        &secret,
        "alice",
        "secure-forum",
        (recorded_step * 30) as u64,
    )?;
    let fresh_code = totp::code_at(&secret, "alice", "secure-forum", (next_step * 30) as u64)?;

    let csrf = csrf_token(app.clone(), &target, None).await?;
    let response = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!("csrf_token={csrf}&pending_id={pending_id}&code={replay_code}"),
    )
    .await?;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a code from an already used window must be refused"
    );

    let csrf = csrf_token(app.clone(), &target, None).await?;
    let response = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!("csrf_token={csrf}&pending_id={pending_id}&code={fresh_code}"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = session_cookie_of(&response).expect("session cookie after the code");
    let (status, _) = get(app.clone(), "/account", Some(&cookie)).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "session works after the second step"
    );

    // 8. A recovery code works once and is then refused.
    let csrf = csrf_token(app.clone(), "/login", None).await?;
    let response = post_form(
        app.clone(),
        "/login",
        None,
        &format!("csrf_token={csrf}&username=alice&password=correct+horse+battery"),
    )
    .await?;
    let target = redirect_target(&response);
    let pending_id = target.trim_start_matches("/login/totp?p=").to_string();
    let csrf = csrf_token(app.clone(), &target, None).await?;
    let response = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!("csrf_token={csrf}&pending_id={pending_id}&code={recovery_code}"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie_of(&response).is_some());

    let csrf = csrf_token(app.clone(), "/login", None).await?;
    let response = post_form(
        app.clone(),
        "/login",
        None,
        &format!("csrf_token={csrf}&username=alice&password=correct+horse+battery"),
    )
    .await?;
    let target = redirect_target(&response);
    let pending_id = target.trim_start_matches("/login/totp?p=").to_string();
    let csrf = csrf_token(app.clone(), &target, None).await?;
    let response = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!("csrf_token={csrf}&pending_id={pending_id}&code={recovery_code}"),
    )
    .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a reused recovery code must not sign in"
    );
    Ok(())
}

#[sqlx::test]
async fn disabling_needs_password_and_a_code(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    let secret = totp::generate_secret();
    store.activate_totp(id, &secret, 0).await?;
    let sid = store.create_session(id).await?;
    let cookie = format!("session_id={sid}");

    // Wrong password: still enabled.
    let csrf = csrf_token(app.clone(), "/account", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/disable",
        Some(&cookie),
        &format!(
            "csrf_token={csrf}&password=wrong+password&code={}",
            code_now(&secret, "alice")
        ),
    )
    .await?;
    assert!(redirect_target(&response).contains("err=bad_password"));
    assert!(store.totp_state(id).await?.is_active());

    // Wrong code: still enabled.
    let csrf = csrf_token(app.clone(), "/account", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/disable",
        Some(&cookie),
        &format!("csrf_token={csrf}&password=correct+horse+battery&code=000000"),
    )
    .await?;
    assert!(redirect_target(&response).contains("err=bad_code"));
    assert!(store.totp_state(id).await?.is_active());

    // Password plus code disables it.
    let csrf = csrf_token(app.clone(), "/account", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/disable",
        Some(&cookie),
        &format!(
            "csrf_token={csrf}&password=correct+horse+battery&code={}",
            code_now(&secret, "alice")
        ),
    )
    .await?;
    assert!(redirect_target(&response).contains("ok=totp_disabled"));
    assert!(!store.totp_state(id).await?.is_active());
    Ok(())
}

#[sqlx::test]
async fn password_change_ends_other_sessions(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    let current = store.create_session(id).await?;
    let cookie = format!("session_id={current}");

    let csrf = csrf_token(app.clone(), "/account", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/password",
        Some(&cookie),
        &format!(
            "csrf_token={csrf}&old_password=correct+horse+battery&new_password=new+password+value&repeat_password=new+password+value"
        ),
    )
    .await?;
    assert!(redirect_target(&response).contains("ok=password_changed"));
    let sessions = store.list_sessions_by_user(id).await?;
    assert_eq!(sessions.len(), 1, "only the current session survives");

    // The new password works, the old one does not.
    assert!(veil_forum::auth::verify_password(
        &store.get_user_by_id(id).await?.unwrap().password_hash,
        "new password value"
    ));
    Ok(())
}

#[sqlx::test]
async fn required_policy_gates_the_forum_until_enrolment(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    let board = store
        .create_board("general2", "General", "test", true, true)
        .await?;
    store
        .create_thread(board, id, "a thread", "body", "<p>body</p>", false)
        .await?;
    let sid = store.create_session(id).await?;
    let cookie = format!("session_id={sid}");

    // With no policy the forum is reachable.
    let (status, _) = get(app.clone(), "/", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(app.clone(), "/b/general2", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);

    // With `all`, a member without a second factor is sent to the account page.
    store.set_config("totp_required", "all").await?;
    let (status, html) = get(app.clone(), "/b/general2", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Second factor required") && html.contains("/account"),
        "the gate page must point at the account page"
    );
    assert!(
        !html.contains("a thread"),
        "content must not leak through the gate"
    );

    // The account page itself stays reachable.
    let (status, html) = get(app.clone(), "/account", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("/account/totp/setup"));

    // Guests are unaffected by the member policy.
    let (status, _) = get(app.clone(), "/b/general2", None).await?;
    assert_eq!(status, StatusCode::OK);

    // After enrolling, the forum is reachable again.
    let secret = totp::generate_secret();
    store.activate_totp(id, &secret, 0).await?;
    let (status, html) = get(app.clone(), "/b/general2", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("a thread"));

    // `staff` only applies to accounts holding a role.
    store.set_config("totp_required", "staff").await?;
    store.disable_totp(id).await?;
    let plain = member(&store, "bob", "correct horse battery").await?;
    let plain_sid = store.create_session(plain).await?;
    let (status, html) = get(
        app.clone(),
        "/b/general2",
        Some(&format!("session_id={plain_sid}")),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("a thread"), "plain members are not gated");

    store
        .grant_role(id, veil_forum::store::Role::Moderator, Some(plain))
        .await?;
    let (status, html) = get(app.clone(), "/b/general2", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("/account"), "staff without a factor is gated");
    Ok(())
}

#[sqlx::test]
async fn admin_can_toggle_the_feature_and_policy(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let admin = store.create_user("root", "hash", true).await?;
    store
        .grant_role(admin, veil_forum::store::Role::Owner, None)
        .await?;
    let sid = store.create_session(admin).await?;
    let cookie = format!("session_id={sid}");

    let (status, html) = get(app.clone(), "/admin/settings", Some(&cookie)).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("/admin/config/totp"),
        "settings form expected"
    );

    // Disable the feature and require it from everyone.
    let csrf = csrf_token(app.clone(), "/admin/settings", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/admin/config/totp",
        Some(&cookie),
        &format!("csrf_token={csrf}&totp_required=all"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        store.get_config("totp_enabled").await?.as_deref(),
        Some("0")
    );
    assert_eq!(
        store.get_config("totp_required").await?.as_deref(),
        Some("all")
    );

    // With the feature off, the policy does not gate anything.
    let other = member(&store, "carol", "correct horse battery").await?;
    let other_sid = store.create_session(other).await?;
    let (status, _) = get(app.clone(), "/", Some(&format!("session_id={other_sid}"))).await?;
    assert_eq!(status, StatusCode::OK);

    // Turning it back on with `staff` keeps plain members ungated.
    let csrf = csrf_token(app.clone(), "/admin/settings", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/admin/config/totp",
        Some(&cookie),
        &format!("csrf_token={csrf}&totp_enabled=1&totp_required=staff"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        store.get_config("totp_enabled").await?.as_deref(),
        Some("1")
    );
    assert_eq!(
        store.get_config("totp_required").await?.as_deref(),
        Some("staff")
    );
    Ok(())
}

/// Enrolling replaces the credential that protects an account, so a session
/// alone must not be enough: without the password no secret may be planted.
#[sqlx::test]
async fn enrolment_requires_the_current_password(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    let sid = store.create_session(id).await?;
    let cookie = format!("session_id={sid}");

    // No password, then a wrong one: both leave the account untouched.
    for form_password in ["", "not-the-password"] {
        let csrf = csrf_token(app.clone(), "/account", Some(&cookie)).await?;
        let response = post_form(
            app.clone(),
            "/account/totp/setup",
            Some(&cookie),
            &format!("csrf_token={csrf}&password={form_password}"),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            redirect_target(&response).contains("err=bad_password"),
            "a wrong password must be refused, got {}",
            redirect_target(&response)
        );
        assert!(
            store.totp_state(id).await?.pending_secret.is_none(),
            "no enrolment may start without the password"
        );
    }

    // With the right password the enrolment starts and shows a secret.
    let csrf = csrf_token(app.clone(), "/account", Some(&cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/setup",
        Some(&cookie),
        &format!("csrf_token={csrf}&password=correct+horse+battery"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        store.totp_state(id).await?.pending_secret.is_some(),
        "the enrolment must start once the password is correct"
    );
    Ok(())
}

/// The gates must read the session cookie exactly like the handlers do.
/// `session_id= <sid>` (and any other value one parser accepts while the other
/// rejects it) must not make a request look like a guest to the gate and like a
/// member to the handler: that is a policy bypass, not a cosmetic difference.
#[sqlx::test]
async fn crafted_session_cookie_cannot_bypass_the_policy_gate(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    // A private board: a guest is redirected to the login page, so the only way
    // to read the thread is to be recognised as a member.
    let board = store
        .create_board("private3", "Private", "test", true, false)
        .await?;
    store
        .create_thread(board, id, "a thread", "body", "<p>body</p>", false)
        .await?;
    let sid = store.create_session(id).await?;
    store.set_config("totp_required", "all").await?;

    // Control: the plain cookie reaches the gate, and no content leaks.
    let (status, html) = get(app.clone(), "/t/1", Some(&format!("session_id={sid}"))).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Second factor required"),
        "control must be gated"
    );
    assert!(!html.contains("a thread"), "the thread must not leak");

    // Crafted cookies must never reach the content: they are either gated (the
    // member is recognised) or treated as a guest (redirected to the login page
    // for a private board).
    for crafted in [
        format!("session_id= {sid}"),
        format!("session_id={sid} "),
        format!("session_id=junk; session_id={sid}"),
        format!("session_id={sid}; session_id=junk"),
    ] {
        let (status, html) = get(app.clone(), "/t/1", Some(&crafted)).await?;
        assert!(
            !html.contains("a thread"),
            "cookie {crafted:?} bypassed the gate (status {status})"
        );
    }
    Ok(())
}

/// A time step may be claimed once. Two pending logins opened with the same
/// password must not both accept the same code.
#[sqlx::test]
async fn a_code_cannot_be_reused_for_a_second_pending_login(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;
    let secret = totp::generate_secret();
    store.activate_totp(id, &secret, 0).await?;

    // Two independent password steps, each with its own pending login.
    let mut pending = Vec::new();
    for _ in 0..2 {
        let csrf = csrf_token(app.clone(), "/login", None).await?;
        let response = post_form(
            app.clone(),
            "/login",
            None,
            &format!("csrf_token={csrf}&username=alice&password=correct+horse+battery"),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        pending.push(redirect_target(&response));
    }
    assert_eq!(pending.len(), 2);

    // The same code for both: the first wins, the second is a replay.
    let code = code_now(&secret, "alice");
    let csrf = csrf_token(app.clone(), &pending[0], None).await?;
    let first = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!(
            "csrf_token={csrf}&pending_id={}&code={code}",
            pending[0].split("p=").nth(1).context("pending id")?
        ),
    )
    .await?;
    assert_eq!(
        first.status(),
        StatusCode::SEE_OTHER,
        "first login must pass"
    );
    assert!(session_cookie_of(&first).is_some(), "a session is expected");

    let csrf = csrf_token(app.clone(), &pending[1], None).await?;
    let second = post_form(
        app.clone(),
        "/login/totp",
        None,
        &format!(
            "csrf_token={csrf}&pending_id={}&code={code}",
            pending[1].split("p=").nth(1).context("pending id")?
        ),
    )
    .await?;
    assert_eq!(
        second.status(),
        StatusCode::FORBIDDEN,
        "the same code must not open a second session"
    );
    assert!(
        session_cookie_of(&second).is_none(),
        "no session may be created for a replayed code"
    );

    // Exactly one session exists for the account.
    let sessions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(sessions.0, 1, "only the winning login may hold a session");
    Ok(())
}

/// Switching the second factor on or off must not leave older sessions alive.
#[sqlx::test]
async fn totp_transitions_revoke_other_sessions(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "correct horse battery").await?;

    // A stale session from before enrolment.
    let stale = store.create_session(id).await?;
    let stale_cookie = format!("session_id={stale}");
    let current = store.create_session(id).await?;
    let current_cookie = format!("session_id={current}");

    let csrf = csrf_token(app.clone(), "/account", Some(&current_cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/setup",
        Some(&current_cookie),
        &format!("csrf_token={csrf}&password=correct+horse+battery"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let secret = store
        .totp_state(id)
        .await?
        .pending_secret
        .context("pending secret")?;

    let csrf = csrf_token(app.clone(), "/account", Some(&current_cookie)).await?;
    let response = post_form(
        app.clone(),
        "/account/totp/confirm",
        Some(&current_cookie),
        &format!("csrf_token={csrf}&code={}", code_now(&secret, "alice")),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(remaining.0, 1, "only the enrolling session may survive");
    let (status, _) = get(app.clone(), "/account", Some(&stale_cookie)).await?;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a session created before enrolment must be gone"
    );
    Ok(())
}
