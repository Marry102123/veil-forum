//! HTTP flow tests for the TOTP second factor: enrolment through the account
//! page, the two-step login, recovery codes, and the enforcement policy.

use anyhow::Context;
use axum::body::to_bytes;
use axum::http::{header, Request, StatusCode};
use sqlx::postgres::PgConnection;
use sqlx::{AssertSqlSafe, Connection, PgPool};
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
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
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
    member(&store, "alice", "Glacier-Maple7-Raven").await?;

    // 1. Password step: no session yet, a pending login instead.
    let csrf = csrf_token(app.clone(), "/login", None).await?;
    let response = post_form(
        app.clone(),
        "/login",
        None,
        &format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven"),
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
        &format!("csrf_token={csrf}&password=Glacier-Maple7-Raven"),
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
        &format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven"),
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
        &format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven"),
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
        &format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven"),
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
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
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
        &format!("csrf_token={csrf}&password=Glacier-Maple7-Raven&code=000000"),
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
            "csrf_token={csrf}&password=Glacier-Maple7-Raven&code={}",
            code_now(&secret, "alice")
        ),
    )
    .await?;
    assert!(redirect_target(&response).contains("ok=totp_disabled"));
    assert!(!store.totp_state(id).await?.is_active());
    Ok(())
}

#[sqlx::test]
async fn required_policy_gates_the_forum_until_enrolment(pool: PgPool) -> anyhow::Result<()> {
    let (app, store) = app_with_store(&pool).await?;
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
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
    let plain = member(&store, "bob", "Glacier-Maple7-Raven").await?;
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
    let other = member(&store, "carol", "Glacier-Maple7-Raven").await?;
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
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
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
        &format!("csrf_token={csrf}&password=Glacier-Maple7-Raven"),
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
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
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
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
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
            &format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven"),
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
    let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;

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
        &format!("csrf_token={csrf}&password=Glacier-Maple7-Raven"),
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

// ---------------------------------------------------------------------------
// Reproducible E2E report artifact
// ---------------------------------------------------------------------------
//
// The artifact is `target/totp-http-e2e-report.json`. It is written on success,
// on error and on panic, by a guard that lives across the whole sequential
// section below. The section is deliberately ONE `sqlx::test` case rather than
// twelve parallel ones: the checks run one after another, so the artifact is
// written exactly once with a deterministic list, and no other case in this
// binary can write a partial version over it. `sqlx::test` still gives this case
// its own isolated database; each check that needs a different fault builds its
// own fresh database, because a closed pool or an altered column cannot be
// undone inside a single database.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Artifact path, relative to the crate root.
const REPORT_PATH: &str = "target/totp-http-e2e-report.json";
const REPRODUCE_COMMAND: &str =
    "DATABASE_URL=<test-postgres-url> cargo test --test totp_http_tests -- --nocapture";
const REPORT_TEST_NAME: &str = "totp_http_second_factor_and_fail_closed_paths";

struct E2eReport {
    path: std::path::PathBuf,
    started_at: String,
    expected_checks: Vec<&'static str>,
    completed_checks: Vec<&'static str>,
    failed_checks: Vec<&'static str>,
    written: bool,
}

impl E2eReport {
    fn start() -> Self {
        Self {
            path: std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(REPORT_PATH),
            started_at: utc_now(),
            expected_checks: Vec::new(),
            completed_checks: Vec::new(),
            failed_checks: Vec::new(),
            written: false,
        }
    }

    /// Declare the checks this run is expected to complete. The report is only
    /// green when every declared check completed and none failed, so a
    /// truncated or filtered run cannot produce a passing artifact.
    fn expect(&mut self, checks: &[&'static str]) {
        self.expected_checks = checks.to_vec();
    }

    fn record(&mut self, check: &'static str, outcome: anyhow::Result<()>) -> anyhow::Result<()> {
        match outcome {
            Ok(()) => {
                if !self.completed_checks.contains(&check) {
                    self.completed_checks.push(check);
                }
                Ok(())
            }
            Err(error) => {
                if !self.failed_checks.contains(&check) {
                    self.failed_checks.push(check);
                }
                Err(error)
            }
        }
    }

    /// Seal the run. Any check that did not complete is an outright failure.
    fn succeed(mut self) -> anyhow::Result<()> {
        if self.completed_checks.len() != self.expected_checks.len()
            || !self.failed_checks.is_empty()
        {
            let failure = self
                .write_failed("verdict_mismatch")
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("not every declared check completed"));
            return Err(failure);
        }
        self.write("passed", serde_json::Value::Null)
    }

    /// Write the artifact for an error outcome. Never masks the original error.
    fn write_failed(&mut self, step: &str) -> anyhow::Result<()> {
        self.write("failed", serde_json::json!(step))
    }

    fn write(&mut self, result: &str, failed_step: serde_json::Value) -> anyhow::Result<()> {
        let report = serde_json::json!({
            "schema_version": 1,
            "test": REPORT_TEST_NAME,
            "suite": "tests/totp_http_tests.rs",
            "started_at_utc": self.started_at,
            "ended_at_utc": utc_now(),
            "input_summary": {
                "database": "sqlx isolated PostgreSQL databases, one per fault variant",
                "transport": "real axum router, in-process over tower oneshot",
                "fault_injection": "the real pool is closed, a privilege is revoked from the scratch database's own role, or one config key is made unreadable by a row-level-security policy, so exactly the intended statement fails",
                "fixtures": [
                    "member account with a known password",
                    "board and thread",
                    "active second factor",
                    "session cookie"
                ],
                "secrets": "test-only values are not recorded"
            },
            "result": result,
            "failed_step": failed_step,
            "key_checks": {
                "expected": self.expected_checks,
                "expected_count": self.expected_checks.len(),
                "completed": self.completed_checks,
                "completed_count": self.completed_checks.len(),
                "failed": self.failed_checks
            },
            "artifacts": {
                // Deliberately the crate-relative path, never the absolute one:
                // this artifact is committed nowhere but still must not carry a
                // developer's local home directory.
                "report_path": REPORT_PATH,
                "log_path": serde_json::Value::Null,
                "log_policy": "no logs captured; raw cargo output is intentionally excluded"
            },
            "reproduce_command": REPRODUCE_COMMAND,
            "verify_command": format!(
                "jq -e '.result == \"passed\" and .key_checks.completed_count == .key_checks.expected_count' {REPORT_PATH}"
            ),
            "cleanup_command": "drop the throwaway test databases; reports live in target/ and are not versioned",
            "credentials_included": false
        });
        let Some(parent) = self.path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(parent)?;
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        let temporary = self.path.with_extension("json.tmp");
        // Write-then-rename, so a reader never observes a half-written artifact.
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

/// Success, error and panic all end here: the guard writes whatever state the
/// run reached. It never fails the run, so a reporting problem cannot mask the
/// check result, and it is idempotent so it cannot overwrite a sealed verdict.
impl Drop for E2eReport {
    fn drop(&mut self) {
        if !self.written && SEALED.swap(true, Ordering::SeqCst) {
            let complete = self.completed_checks.len() == self.expected_checks.len()
                && self.failed_checks.is_empty();
            let _ = self.write(
                if complete { "passed" } else { "failed" },
                if complete {
                    serde_json::Value::Null
                } else {
                    serde_json::json!({
                        "failed": self.failed_checks,
                        "not_completed": self
                            .expected_checks
                            .iter()
                            .filter(|check| !self.completed_checks.contains(check))
                            .collect::<Vec<_>>()
                    })
                },
            );
        }
    }
}

/// Guards against a second write in the same process, so the artifact always
/// describes one coherent run.
static SEALED: AtomicBool = AtomicBool::new(false);
/// Serialises the writes, so concurrent test binaries cannot interleave them.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ---------------------------------------------------------------------------
// Fault-injection helpers
// ---------------------------------------------------------------------------

/// A throwaway database with the schema and defaults applied, plus a
/// `sqlx::test`-style name so a crash leaves a recognisable leftover.
struct Scratch {
    name: String,
    admin_url: String,
    url: String,
    pool: Option<PgPool>,
}

impl Scratch {
    /// The administrative URL: `DATABASE_URL` first, so CI and a developer's
    /// own configuration are honoured, then the documented local socket.
    fn admin_url() -> String {
        // The administrative database is `postgres`; a test database URL names a
        // database the role may not be allowed to connect to as a second time.
        let base = std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| {
                "postgres://user@%2Fvar%2Frun%2Fpostgresql/veil_forum_test".to_string()
            });
        let base = base.split('?').next().unwrap_or_default().to_string();
        let authority = base.rsplit_once('/').map(|(head, _)| head).unwrap_or(&base);
        format!("{authority}/postgres")
    }

    /// Replace the database name in an administrative URL.
    fn url_for(&self) -> String {
        let base = self
            .admin_url
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string();
        let query = match self.admin_url.split_once('?') {
            Some((_, query)) => format!("?{query}"),
            None => String::new(),
        };
        let authority = base.rsplit_once('/').map(|(head, _)| head).unwrap_or(&base);
        format!("{authority}/{}{query}", self.name)
    }

    async fn create(tag: &str) -> anyhow::Result<Self> {
        let admin_url = Self::admin_url();
        // One raw connection, not a pool: `CREATE DATABASE` cannot run inside a
        // transaction, and a pool would hold connections that block the DROP.
        let mut admin = PgConnection::connect(&admin_url).await.with_context(|| {
            format!(
                "no administrative PostgreSQL connection at the configured socket ({admin_url})"
            )
        })?;
        let suffix: u64 = rand::random();
        let name = format!("veil_fc_{tag}_{suffix}");
        // The name is generated here, never taken from input.
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&mut admin)
            .await
            .with_context(|| format!("could not create scratch database {name}"))?;
        admin.close().await.ok();
        let scratch = Self {
            name: name.clone(),
            admin_url,
            url: String::new(),
            pool: None,
        };
        let scratch = Self {
            url: scratch.url_for(),
            ..scratch
        };
        let outcome = async {
            let pool = PgPool::connect(&scratch.url)
                .await
                .with_context(|| format!("could not connect to scratch database {name}"))?;
            // The same embedded migrations the server applies. This is also the
            // check that migration 0005 (`CREATE INDEX CONCURRENTLY`, which needs
            // the `-- no-transaction` directive) applies cleanly outside a
            // transaction.
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .with_context(|| format!("migrations did not apply cleanly to {name}"))?;
            Ok(pool)
        }
        .await;
        match outcome {
            Ok(pool) => Ok(Self {
                pool: Some(pool),
                ..scratch
            }),
            // The database was already created, so a failure here would leave it
            // behind; drop it before returning.
            Err(error) => {
                let _ = scratch.destroy().await;
                Err(error)
            }
        }
    }

    /// Close every connection to the scratch database and drop it, so a run
    /// leaves nothing behind even when a check failed.
    async fn destroy(self) -> anyhow::Result<()> {
        if let Some(pool) = self.pool {
            pool.close().await;
        }
        let name = self.name.clone();
        let mut admin = match PgConnection::connect(&self.admin_url).await {
            Ok(admin) => admin,
            Err(error) => {
                eprintln!("could not reconnect to drop scratch database {name}: {error}");
                return Ok(());
            }
        };
        // Retry once: a backend that is still shutting down refuses the DROP.
        let mut last = None;
        for _ in 0..5 {
            match sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS \"{name}\"")))
                .execute(&mut admin)
                .await
            {
                Ok(_) => {
                    admin.close().await.ok();
                    return Ok(());
                }
                Err(error) => {
                    last = Some(error);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
        Err(anyhow::anyhow!(
            "could not drop scratch database {name}: {}",
            last.map(|e| e.to_string()).unwrap_or_default()
        ))
    }
}

async fn scratch_app(scratch: &Scratch) -> anyhow::Result<(axum::Router, Store)> {
    let pool = scratch
        .pool
        .clone()
        .context("the scratch database was already destroyed")?;
    let store = Store { pool };
    store.seed_defaults().await?;
    store.set_config("login_pow_enabled", "0").await?;
    store.set_config("login_captcha_enabled", "0").await?;
    let state = handler::AppState {
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: veil_forum::rate_limit::Limits::new(),
        secure_session_cookie: false,
        store: store.clone(),
    };
    Ok((handler::routes(state), store))
}

fn assert_service_unavailable(response: &axum::response::Response) -> anyhow::Result<()> {
    anyhow::ensure!(
        response.status() == StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 on a database failure, got {}",
        response.status()
    );
    Ok(())
}

/// Close the pool behind the router's store, so the very next statement the
/// handler issues fails. The request then travels through the real router and
/// real middleware stack. Used for the checks whose failure mode is a whole
/// request outage, where the point is that *no* storage answer is invented.
async fn broken_request(
    app: axum::Router,
    store: &Store,
    method: axum::http::Method,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> anyhow::Result<axum::response::Response> {
    store.pool.close().await;
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "forum.test")
        .header(header::ORIGIN, "http://forum.test");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let body = form.unwrap_or_default();
    if !body.is_empty() {
        request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let request = request.body(axum::body::Body::from(body.to_owned()))?;
    Ok(app.oneshot(request).await?)
}

/// Name the role the scratch pool authenticates as, so privileges can be
/// revoked from exactly that role.
async fn current_role(pool: &PgPool) -> anyhow::Result<String> {
    let (role,): (String,) = sqlx::query_as("SELECT current_user")
        .fetch_one(pool)
        .await?;
    // A superuser bypasses privilege checks, so a revoked privilege would not
    // produce a failure and the check would silently prove nothing.
    let (superuser,): (bool,) =
        sqlx::query_as("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(pool)
            .await?;
    anyhow::ensure!(
        !superuser,
        "the test role is a superuser, so a revoked privilege is not enforced; \
         run the E2E suite as a non-superuser role"
    );
    Ok(role)
}

/// Revoke a privilege so exactly the statements that need it fail, while every
/// read the handler performs *before* the decision under test still succeeds.
/// This is what makes each check attributable to one decision point instead of
/// to a whole-request outage.
async fn revoke(pool: &PgPool, table: &str, privileges: &str) -> anyhow::Result<()> {
    let role = current_role(pool).await?;
    // The table name is a literal at every call site; the role comes from the
    // server and is a bare identifier.
    sqlx::query(AssertSqlSafe(format!(
        "REVOKE {privileges} ON TABLE {table} FROM \"{role}\""
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// Read one configuration value, so a check can confirm a fault landed on the
/// key it intended.
async fn fetch_config(pool: &PgPool, key: &str) -> anyhow::Result<Option<String>> {
    // The key is a literal at every call site.
    use sqlx::Row;
    Ok(sqlx::query(AssertSqlSafe(format!(
        "SELECT value FROM configs WHERE key='{key}'"
    )))
    .fetch_optional(pool)
    .await?
    .and_then(|row| row.try_get::<String, _>("value").ok()))
}

/// A function whose only job is to raise a database error, so a statement that
/// consults it fails exactly the way an unavailable dependency fails.
const FAULT_FUNCTION: &str = "veil_fc_read_fault";

async fn create_fault_function(pool: &PgPool) -> anyhow::Result<()> {
    // The function name is a constant; no input reaches this statement.
    sqlx::query(AssertSqlSafe(format!(
        "CREATE OR REPLACE FUNCTION {FAULT_FUNCTION}() RETURNS boolean \
         LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''injected read failure''; END'"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// Make reads of exactly one configuration key fail, and leave every other key
/// readable, so a handler that treats "cannot read" as "off" is caught. A wrong
/// value would be read successfully and would answer as a deliberate setting.
///
/// This is a per-key, per-scratch-database mechanism: `configs` is a key/value
/// table, so the fault is expressed as a row-level-security policy that keeps
/// every row visible *except* the target key, whose predicate raises. Note that
/// a plain RLS policy would not do: it either bypasses the owning role or
/// filters the target row out, and a missing row reads as "key absent" rather
/// than "the database failed". Raising from the policy expression is what turns
/// the row decision into the SQL error these checks need. Nothing here touches a
/// role, so no other check running in parallel can be affected.
async fn make_config_read_fail(pool: &PgPool, key: &str) -> anyhow::Result<()> {
    let role = current_role(pool).await?;
    create_fault_function(pool).await?;
    // The role is a bare identifier from the server, the key is a literal at
    // every call site, and the policy name is generated here.
    sqlx::query("ALTER TABLE configs ENABLE ROW LEVEL SECURITY")
        .execute(pool)
        .await?;
    // The owner is exempt from its own policies unless they are forced, and the
    // pool authenticates as that owner.
    sqlx::query("ALTER TABLE configs FORCE ROW LEVEL SECURITY")
        .execute(pool)
        .await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE POLICY veil_fc_config_fault ON configs FOR SELECT \
         TO \"{role}\" USING (key <> '{key}' OR {FAULT_FUNCTION}())"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// Confirm a fault landed on the configuration key it intended, and only there.
/// The other keys must still read normally, otherwise the fault has not been
/// isolated and the check would 503 for an unrelated early read.
async fn assert_config_read_fault_is_isolated(pool: &PgPool, key: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        fetch_config(pool, key).await.is_err(),
        "the fault must land on the {key} key"
    );
    anyhow::ensure!(
        fetch_config(pool, "login_pow_enabled").await.is_ok(),
        "the fault must not reach any other configuration key"
    );
    Ok(())
}

/// The two account pages take their CSRF token from a form that embeds the
/// member name, which is the one thing that still proves the session resolved.
fn csrf_token_of(html: &str) -> anyhow::Result<String> {
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).context("CSRF token missing")? + marker.len();
    let end = html[start..].find('"').context("unterminated CSRF token")? + start;
    Ok(html[start..end].to_owned())
}

// ---------------------------------------------------------------------------
// The fail-closed checks
// ---------------------------------------------------------------------------

/// `middleware.rs` exempts `/login` from the maintenance gate, so a real login
/// submission is the only way to reach the handler's own maintenance read, and
/// the gate itself has to be probed on a path it does not exempt.
async fn check_maintenance_gate_answers_503_on_config_read_error() -> anyhow::Result<()> {
    let scratch = Scratch::create("maint").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        store.set_config("maintenance_enabled", "0").await?;
        let (status, _) = get(app.clone(), "/", None).await?;
        anyhow::ensure!(status == StatusCode::OK, "control must be reachable");

        // `/b/general` is not exempt from the gate, so the gate itself runs.
        let response = broken_request(
            app,
            &store,
            axum::http::Method::GET,
            "/b/general",
            None,
            None,
        )
        .await?;
        assert_service_unavailable(&response)
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// A storage error in the policy gate must not read as "no session", i.e. as a
/// guest that a member-only policy does not apply to. `/b/general` is not
/// exempt from the gate, so the gate itself runs.
async fn check_totp_policy_gate_answers_503_on_session_read_error() -> anyhow::Result<()> {
    let scratch = Scratch::create("gate").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
        let sid = store.create_session(id).await?;
        store.set_config("totp_required", "all").await?;
        let cookie = format!("session_id={sid}");

        let response = broken_request(
            app,
            &store,
            axum::http::Method::GET,
            "/b/general",
            Some(&cookie),
            None,
        )
        .await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "a storage failure must not issue a session"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// `login_post` reads the account before checking the password. A read failure
/// must answer 503, not the 403 that "unknown account" produces, so a client can
/// tell a dependency outage from a wrong password.
async fn check_login_account_lookup_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("acct").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        member(&store, "alice", "Glacier-Maple7-Raven").await?;
        let csrf = csrf_token(app.clone(), "/login", None).await?;
        let form = format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven");
        // Control A: with the pool intact, the same submission signs the member
        // in. This is what proves the account, the password and the challenge
        // keys are all healthy before anything is broken.
        let healthy = post_form(app.clone(), "/login", None, &form).await?;
        anyhow::ensure!(
            healthy.status() == StatusCode::SEE_OTHER,
            "control must be 303, got {}",
            healthy.status()
        );
        let signed_in =
            session_cookie_of(&healthy).context("the control must sign the member in")?;

        // A second submission carries the same account and password, with a
        // CSRF token minted for the session the broken request will present. A
        // CSRF token is a MAC over that session, so the token cannot be reused
        // across cookie jars.
        let csrf = csrf_token(app.clone(), "/account", Some(&signed_in)).await?;
        let form = format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven");

        // The pool must not simply be closed here. `challenge_enabled`
        // deliberately fails *open* to "proof of work required" when its config
        // read errors, so a closed pool never reaches the account lookup at all
        // and answers the 403 that a missing PoW produces. Failing open is the
        // safe direction for an anti-abuse challenge, so it is not the behaviour
        // under test, and this file may not change it.
        //
        // Revoking `users` instead leaves the challenge configuration readable,
        // so the challenge resolves normally and the account lookup becomes the
        // first statement to touch the broken store.
        revoke(&store.pool, "users", "SELECT").await?;
        anyhow::ensure!(
            store.get_user_by_username("alice").await.is_err(),
            "the fault must land on the account lookup"
        );
        anyhow::ensure!(
            fetch_config(&store.pool, "login_pow_enabled").await.is_ok(),
            "the fault must not reach the challenge configuration read that \
             precedes the account lookup"
        );
        let response = post_form(app, "/login", Some(&signed_in), &form).await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            session_cookie_of(&response).is_none(),
            "a failed lookup must not sign anyone in"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// After the password verifies, `login_post` reads the maintenance key. A read
/// failure must not be taken for "maintenance is off", which would admit
/// ordinary members while the gate answers 503 for the same key.
async fn check_login_maintenance_state_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("logmaint").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        member(&store, "alice", "Glacier-Maple7-Raven").await?;
        store.set_config("maintenance_enabled", "0").await?;
        let csrf = csrf_token(app.clone(), "/login", None).await?;
        let form = format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven");

        // Only the maintenance read fails, so the 503 can only come from it: the
        // account lookup, the password check and the session write are all
        // still available.
        make_config_read_fail(&store.pool, "maintenance_enabled").await?;
        assert_config_read_fault_is_isolated(&store.pool, "maintenance_enabled").await?;
        let response = post_form(app, "/login", None, &form).await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            session_cookie_of(&response).is_none(),
            "an unreadable maintenance flag must not sign anyone in"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// The second-factor state read must fail closed too: reading a storage error
/// as "no factor configured" downgrades a two-step login to a password-only
/// login. The same broken column makes `feature_enabled` false, so the
/// maintenance read before it is the control that proves the account and the
/// password check still ran.
async fn check_login_totp_state_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("logtotp").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
        let secret = totp::generate_secret();
        store.activate_totp(id, &secret, 0).await?;
        store.set_config("maintenance_enabled", "0").await?;
        store.set_config("totp_enabled", "1").await?;
        let csrf = csrf_token(app.clone(), "/login", None).await?;
        let form = format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven");

        // Control: the healthy submission stops at the second step.
        let response = post_form(app.clone(), "/login", None, &form).await?;
        anyhow::ensure!(
            redirect_target(&response).starts_with("/login/totp?p="),
            "control must require a code, got {}",
            redirect_target(&response)
        );
        anyhow::ensure!(
            session_cookie_of(&response).is_none(),
            "no session may exist before the code"
        );

        // `store::totp_state` reads `users` and, in the same statement, counts
        // the unused recovery codes. Revoking only that subquery's table breaks
        // the state read while the account lookup, the password check and the
        // session lookup all keep working, so the 503 is attributable to the
        // second-factor read alone. `users` keeps its SELECT privilege on
        // purpose: that is what makes the fault narrow instead of a whole-pool
        // outage that would pass for the wrong reason.
        revoke(&store.pool, "totp_recovery_codes", "SELECT").await?;
        anyhow::ensure!(
            store.totp_state(id).await.is_err(),
            "the fault must land on the second-factor state read"
        );
        anyhow::ensure!(
            store.get_user_by_id(id).await.is_ok(),
            "the fault must not reach the account lookup"
        );
        let response = post_form(app, "/login", None, &form).await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            session_cookie_of(&response).is_none(),
            "an unreadable second-factor state must not sign anyone in"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// The pending-login window is a write. If it cannot be opened the handler must
/// not fall through to `complete_login`, which would hand out a session without
/// ever checking the second factor.
async fn check_login_pending_window_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("pendwin").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
        let secret = totp::generate_secret();
        store.activate_totp(id, &secret, 0).await?;
        store.set_config("maintenance_enabled", "0").await?;
        store.set_config("totp_enabled", "1").await?;
        let csrf = csrf_token(app.clone(), "/login", None).await?;
        let form = format!("csrf_token={csrf}&username=alice&password=Glacier-Maple7-Raven");

        // The window insert and its housekeeping delete both touch
        // pending_logins, so breaking that table breaks the write while the
        // reads before it still succeed. The account lookup still proves the
        // password was accepted, so only the write can have produced the 503.
        revoke(
            &store.pool,
            "pending_logins",
            "SELECT, INSERT, DELETE, UPDATE",
        )
        .await?;
        let response = post_form(app, "/login", None, &form).await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            session_cookie_of(&response).is_none(),
            "a window that could not be opened must not become a session"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// The reporting feature state is read from the database on every submission. A
/// read failure must answer 503, not the 403 that "reporting disabled" produces:
/// the reporter must be able to tell an outage from a policy decision.
async fn check_report_config_read_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("repconf").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let (cookie, thread) = member_with_thread(&store, "alice").await?;
        let csrf = csrf_token(app.clone(), "/t/1", Some(&cookie)).await?;
        let form = format!("csrf_token={csrf}&reason=spam");
        let response = broken_request(
            app,
            &store,
            axum::http::Method::POST,
            &format!("/report/thread/{thread}"),
            Some(&cookie),
            Some(&form),
        )
        .await?;
        assert_service_unavailable(&response)
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// Reporting a target that is gone must answer 404 while a storage error
/// answers 503, so a reporter can tell "deleted" from "try again later".
async fn check_report_target_lookup_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("reptgt").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let (cookie, thread) = member_with_thread(&store, "alice").await?;
        let csrf = csrf_token(app.clone(), "/t/1", Some(&cookie)).await?;

        // Control: a missing target is a 404, not a 503.
        let response = post_form(
            app.clone(),
            &format!("/report/thread/{}", thread + 1000),
            Some(&cookie),
            &format!("csrf_token={csrf}&reason=spam"),
        )
        .await?;
        anyhow::ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "a missing target must be 404, got {}",
            response.status()
        );

        // Break only the thread read: the config read and the session lookup
        // still succeed, so a 503 can only come from the target lookup.
        revoke(&store.pool, "threads", "SELECT").await?;
        let response = post_form(
            app,
            &format!("/report/thread/{thread}"),
            Some(&cookie),
            &format!("csrf_token={csrf}&reason=spam"),
        )
        .await?;
        assert_service_unavailable(&response)
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// A report whose insert fails must not be redirected as if it had been filed:
/// that silently drops a moderation report while telling the reporter it was
/// received. The control proves the healthy path still stores a row and
/// redirects, so the 503 is specific to the failed write.
async fn check_report_create_write_answers_503_instead_of_redirecting() -> anyhow::Result<()> {
    let scratch = Scratch::create("repwrite").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let (cookie, thread) = member_with_thread(&store, "alice").await?;
        let csrf = csrf_token(app.clone(), "/t/1", Some(&cookie)).await?;

        let response = post_form(
            app.clone(),
            &format!("/report/thread/{thread}"),
            Some(&cookie),
            &format!("csrf_token={csrf}&reason=spam"),
        )
        .await?;
        anyhow::ensure!(
            response.status() == StatusCode::SEE_OTHER,
            "control must redirect, got {}",
            response.status()
        );
        let stored: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM reports")
            .fetch_one(&store.pool)
            .await?;
        anyhow::ensure!(stored.0 == 1, "the control report must be stored");

        // Only the insert is broken, so the config read, the session lookup and
        // the target lookup all succeed and the write is what fails.
        revoke(&store.pool, "reports", "INSERT").await?;
        let response = post_form(
            app,
            &format!("/report/thread/{thread}"),
            Some(&cookie),
            &format!("csrf_token={csrf}&reason=spam again"),
        )
        .await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            response.headers().get(header::LOCATION).is_none(),
            "a dropped report must not redirect as if it were filed"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// The thread page must not offer a report action it cannot honour. The
/// `reports_enabled` read is fail-closed, so an outage answers 503 instead of a
/// page whose report form will be rejected.
async fn check_thread_view_reports_enabled_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("threadview").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let (cookie, _) = member_with_thread(&store, "alice").await?;
        store.set_config("reports_enabled", "1").await?;

        let (status, html) = get(app.clone(), "/t/1", Some(&cookie)).await?;
        anyhow::ensure!(status == StatusCode::OK, "control view must render");
        anyhow::ensure!(
            html.contains("/report/thread/"),
            "control must offer the report action"
        );

        // Only the value is unreadable, so the 503 can only come from that read:
        // everything else the page needs is still readable.
        make_config_read_fail(&store.pool, "reports_enabled").await?;
        assert_config_read_fault_is_isolated(&store.pool, "reports_enabled").await?;
        let (status, html) = get(app, "/t/1", Some(&cookie)).await?;
        anyhow::ensure!(
            status == StatusCode::SERVICE_UNAVAILABLE,
            "expected 503, got {status}"
        );
        anyhow::ensure!(
            !html.contains("/report/thread/"),
            "no report action may be offered when the state is unknown"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// Turning the second factor off replaces the credential protecting the
/// account. A failed state read must not read as "no factor configured", which
/// would let a session alone switch it off.
async fn check_totp_disable_state_read_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("totpoff").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
        let secret = totp::generate_secret();
        store.activate_totp(id, &secret, 0).await?;
        let sid = store.create_session(id).await?;
        let cookie = format!("session_id={sid}");
        let (status, html) = get(app.clone(), "/account", Some(&cookie)).await?;
        anyhow::ensure!(
            status == StatusCode::OK && html.contains("alice"),
            "the account page must render before the fault, proving the session \
             still resolves through the impersonation"
        );
        let csrf = csrf_token_of(&html)?;
        let form = format!("csrf_token={csrf}&password=Glacier-Maple7-Raven&code=000000");

        // `store::totp_state` is the first statement after the password check,
        // and it counts the unused recovery codes in a subquery. Revoking only
        // that table breaks the state read while the session lookup, the
        // password check and the `users` half of the state read all still work,
        // so the 503 is attributable to that one read.
        revoke(&store.pool, "totp_recovery_codes", "SELECT").await?;
        anyhow::ensure!(
            store.totp_state(id).await.is_err(),
            "the fault must land on the second-factor state read"
        );
        anyhow::ensure!(
            store.get_user_by_id(id).await.is_ok(),
            "the fault must not reach the password check"
        );
        let response = post_form(app, "/account/totp/disable", Some(&cookie), &form).await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            !redirect_target(&response).contains("ok=totp_disabled"),
            "a failed state read must not disable the factor"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// Reissuing recovery codes replaces the codes protecting the account. A failed
/// state read must answer 503, not the "feature off" redirect that would tell a
/// member with an active factor that they have none.
async fn check_account_recovery_regenerate_state_read_answers_503() -> anyhow::Result<()> {
    let scratch = Scratch::create("recovery").await?;
    let outcome = async {
        let (app, store) = scratch_app(&scratch).await?;
        let id = member(&store, "alice", "Glacier-Maple7-Raven").await?;
        let secret = totp::generate_secret();
        store.activate_totp(id, &secret, 0).await?;
        let sid = store.create_session(id).await?;
        let cookie = format!("session_id={sid}");
        let (status, html) = get(app.clone(), "/account", Some(&cookie)).await?;
        anyhow::ensure!(
            status == StatusCode::OK && html.contains("alice"),
            "the account page must render before the fault, proving the session \
             still resolves through the impersonation"
        );
        let csrf = csrf_token_of(&html)?;
        let form = format!("csrf_token={csrf}&password=Glacier-Maple7-Raven");

        // Same mechanism as the disable check: the recovery-code subquery inside
        // `store::totp_state` is the only statement broken, so the session
        // lookup and the password check still succeed and the 503 cannot have
        // come from either of them.
        revoke(&store.pool, "totp_recovery_codes", "SELECT").await?;
        anyhow::ensure!(
            store.totp_state(id).await.is_err(),
            "the fault must land on the second-factor state read"
        );
        anyhow::ensure!(
            store.get_user_by_id(id).await.is_ok(),
            "the fault must not reach the password check"
        );
        let response = post_form(app, "/account/recovery", Some(&cookie), &form).await?;
        assert_service_unavailable(&response)?;
        anyhow::ensure!(
            !redirect_target(&response).contains("err=feature_off"),
            "a failed state read must not claim the feature is off"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    scratch.destroy().await?;
    outcome
}

/// A member with a board thread, returning the session cookie and thread id.
async fn member_with_thread(store: &Store, username: &str) -> anyhow::Result<(String, i64)> {
    let id = member(store, username, "Glacier-Maple7-Raven").await?;
    let board = store
        .create_board("general2", "General", "test", true, true)
        .await?;
    let thread = store
        .create_thread(board, id, "a thread", "body", "<p>body</p>", false)
        .await?;
    let sid = store.create_session(id).await?;
    Ok((format!("session_id={sid}"), thread))
}

/// One fail-closed check, boxed so the table can mix async bodies of
/// different concrete types.
type FailClosedCheck =
    fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;

const FAIL_CLOSED_CHECKS: &[(&str, FailClosedCheck)] = &[
    ("maintenance_gate_answers_503_on_config_read_error", || {
        Box::pin(check_maintenance_gate_answers_503_on_config_read_error())
    }),
    ("totp_policy_gate_answers_503_on_session_read_error", || {
        Box::pin(check_totp_policy_gate_answers_503_on_session_read_error())
    }),
    ("login_account_lookup_answers_503", || {
        Box::pin(check_login_account_lookup_answers_503())
    }),
    ("login_maintenance_state_answers_503", || {
        Box::pin(check_login_maintenance_state_answers_503())
    }),
    ("login_totp_state_answers_503", || {
        Box::pin(check_login_totp_state_answers_503())
    }),
    ("login_pending_window_answers_503", || {
        Box::pin(check_login_pending_window_answers_503())
    }),
    ("report_config_read_answers_503", || {
        Box::pin(check_report_config_read_answers_503())
    }),
    ("report_target_lookup_answers_503", || {
        Box::pin(check_report_target_lookup_answers_503())
    }),
    (
        "report_create_write_answers_503_instead_of_redirecting",
        || Box::pin(check_report_create_write_answers_503_instead_of_redirecting()),
    ),
    ("thread_view_reports_enabled_answers_503", || {
        Box::pin(check_thread_view_reports_enabled_answers_503())
    }),
    ("totp_disable_state_read_answers_503", || {
        Box::pin(check_totp_disable_state_read_answers_503())
    }),
    ("account_recovery_regenerate_state_read_answers_503", || {
        Box::pin(check_account_recovery_regenerate_state_read_answers_503())
    }),
];

/// The one entry point that runs every fail-closed check in order and seals the
/// artifact. It is a single case so the report describes a whole run, and so
/// exactly one write happens per process.
#[sqlx::test]
async fn fail_closed_paths_answer_503_and_report_artifact_is_written(
    pool: PgPool,
) -> anyhow::Result<()> {
    let mut report = E2eReport::start();
    report.expect(
        &FAIL_CLOSED_CHECKS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
    );
    // The injected database is unused: every check builds its own scratch
    // database, because a closed pool or an altered column cannot be undone.
    let _ = &pool;
    for (name, check) in FAIL_CLOSED_CHECKS {
        let outcome = check().await;
        if let Err(error) = report.record(name, outcome) {
            // Keep going: the artifact must list every failing check, not just
            // the first one.
            eprintln!("fail-closed check {name} failed: {error:#}");
        }
    }
    let path = report.path.clone();
    let result = report.succeed();
    let contents = std::fs::read_to_string(&path).context("artifact missing")?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).context("artifact is not JSON")?;
    anyhow::ensure!(value["schema_version"] == 1);
    anyhow::ensure!(value["test"] == REPORT_TEST_NAME);
    anyhow::ensure!(value["started_at_utc"].is_string());
    anyhow::ensure!(value["ended_at_utc"].is_string());
    anyhow::ensure!(value["input_summary"]["database"].is_string());
    anyhow::ensure!(value["reproduce_command"].is_string());
    anyhow::ensure!(value["credentials_included"] == false);
    anyhow::ensure!(value["key_checks"]["expected_count"] == FAIL_CLOSED_CHECKS.len() as u64);
    // The verdict must follow the checks, not the other way round.
    let passed = value["result"] == "passed";
    let complete = value["key_checks"]["completed_count"] == value["key_checks"]["expected_count"];
    let none_failed = value["key_checks"]["failed"]
        .as_array()
        .map(|v| v.is_empty())
        .unwrap_or(false);
    anyhow::ensure!(
        passed == (complete && none_failed),
        "the verdict must follow the checks: {value}"
    );
    for forbidden in ["postgres://", "session_id=", "/home/", "Glacier-Maple7"] {
        anyhow::ensure!(
            !contents.contains(forbidden),
            "the artifact must not contain {forbidden}"
        );
    }
    // Draining the lock proves the writer released it, and a second write cannot
    // happen because the guard is sealed.
    drop(lock(&WRITE_LOCK));
    result
}
