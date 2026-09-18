//! HTTP contract tests for the no-JavaScript forum surface.
//!
//! These tests exercise the router in-process, so they do not bind a port or
//! touch a deployed/VPS instance.

use anyhow::Context;
use axum::{
    body::to_bytes,
    http::{header, Request, StatusCode},
};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower::ServiceExt;
use veil_forum::{captcha, handler, pow, store::Store};

/// Build the router against a `sqlx::test` database. Migrations are applied by
/// the harness; first-run defaults and a general board are seeded here so the
/// rendered pages match a real first start.
async fn app_with_store(pool: &PgPool) -> anyhow::Result<(axum::Router, Store)> {
    let store = Store { pool: pool.clone() };
    store.seed_defaults().await?;
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

/// Return the database to a freshly seeded state so repeated scenarios in one
/// test do not observe each other's rows.
async fn reset_store(store: &Store) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "TRUNCATE users, boards, configs, invite_codes, threads, posts, sessions, \
         audit_logs, user_roles, board_moderators, reports RESTART IDENTITY CASCADE",
    )
    .execute(&store.pool)
    .await?;
    store.seed_defaults().await?;
    Ok(())
}

async fn app(pool: &PgPool) -> anyhow::Result<axum::Router> {
    Ok(app_with_store(pool).await?.0)
}

async fn get(app: axum::Router, uri: &str) -> anyhow::Result<axum::response::Response> {
    Ok(app
        .oneshot(Request::get(uri).body(axum::body::Body::empty())?)
        .await?)
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
    let mut request = Request::get(uri).body(axum::body::Body::empty())?;
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse()?);
    }
    let response = app.oneshot(request).await?;
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).context("CSRF token missing")? + marker.len();
    let end = html[start..].find('"').context("unterminated CSRF token")? + start;
    Ok(html[start..end].to_owned())
}

#[sqlx::test]
async fn healthz_reports_ready_and_security_headers(pool: PgPool) -> anyhow::Result<()> {
    let response = get(app(&pool).await?, "/healthz").await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; child-src 'self'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'self'");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "same-origin");
    assert_eq!(to_bytes(response.into_body(), usize::MAX).await?, "ok");
    Ok(())
}

#[sqlx::test]
async fn pow_endpoint_validates_scope_and_returns_challenge_contract(
    pool: PgPool,
) -> anyhow::Result<()> {
    let application = app(&pool).await?;
    let response = get(application.clone(), "/api/pow/challenge?scope=login").await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    for key in [
        "challenge",
        "salt",
        "difficulty",
        "expires_at",
        "hmac",
        "scope",
    ] {
        assert!(body.get(key).is_some(), "missing PoW field {key}");
    }
    assert_eq!(body["scope"], "login");
    assert!(body["difficulty"].as_u64().unwrap() >= 4);

    let invalid = get(application, "/api/pow/challenge?scope=bogus").await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        to_bytes(invalid.into_body(), usize::MAX).await?,
        "invalid PoW scope"
    );
    Ok(())
}

#[sqlx::test]
async fn login_pow_fallback_is_present_in_server_rendered_html(pool: PgPool) -> anyhow::Result<()> {
    let application = app(&pool).await?;
    let response = get(application, "/login").await?;
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(html.contains(r#"class="pow-fallback""#));
    assert!(html.contains(r#"name="pow_nonce""#));
    assert!(html.contains("Python standard library only"));
    assert!(html.contains("JavaScript disabled: manual PoW"));
    assert!(html.contains("Run this locally when JavaScript is unavailable."));
    assert!(html.contains(r#"src="/static/pow.js?v=2""#));
    // The Python snippet is auto-escaped once by Tera. Escaping it before
    // rendering would leave HTML entities in code users need to copy.
    assert!(!html.contains("&amp;quot;"));
    assert!(!html.contains("&amp;gt;"));
    Ok(())
}

#[sqlx::test]
async fn theme_query_is_rendered_without_javascript_and_toggle_is_safe(
    pool: PgPool,
) -> anyhow::Result<()> {
    let application = app(&pool).await?;
    let response = get(application.clone(), "/?theme=light").await?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(html.contains(r#"data-theme="light""#));

    let mut request = Request::get("/theme?to=light").body(axum::body::Body::empty())?;
    request
        .headers_mut()
        .insert(header::REFERER, "/?page=2&theme=dark".parse()?);
    let response = application.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/?page=2&theme=light");
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()?
        .starts_with("theme=light;"));
    Ok(())
}

#[sqlx::test]
async fn maintenance_mode_blocks_public_pages_but_keeps_login_and_admin_accessible(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (application, store) = app_with_store(&pool).await?;
    store.set_config("maintenance_enabled", "1").await?;
    store
        .set_config("maintenance_title", "Planned maintenance")
        .await?;
    store
        .set_config("maintenance_message", "Database upgrade in progress")
        .await?;
    store.set_config("maintenance_eta", "tomorrow").await?;

    let response = get(application.clone(), "/").await?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(html.contains("Planned maintenance"));
    assert!(html.contains("Database upgrade in progress"));
    assert!(html.contains("tomorrow"));
    assert!(!html.contains("General discussion"));

    assert_eq!(
        get(application.clone(), "/login").await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(application, "/admin").await?.status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[sqlx::test]
async fn configured_palette_is_rendered_on_public_pages(pool: PgPool) -> anyhow::Result<()> {
    let (application, store) = app_with_store(&pool).await?;
    store.set_config("theme_palette", "terminal").await?;
    let response = get(application, "/").await?;
    let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(html.contains(r#"data-palette="terminal""#));
    Ok(())
}

#[sqlx::test]
async fn static_assets_are_served_and_traversal_is_not(pool: PgPool) -> anyhow::Result<()> {
    let application = app(&pool).await?;
    let response = get(application.clone(), "/static/style.css").await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    assert!(response.headers().get(header::ETAG).is_some());
    assert!(!to_bytes(response.into_body(), usize::MAX).await?.is_empty());

    for uri in [
        "/static/../Cargo.toml",
        "/static/%2e%2e/Cargo.toml",
        "/static/no-such-file",
    ] {
        let response = get(application.clone(), uri).await?;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "unsafe/missing URI {uri}"
        );
        assert_eq!(response.headers()["x-frame-options"], "DENY");
    }
    Ok(())
}

#[sqlx::test]
async fn registration_policy_switches_control_rendered_fields_and_server_pow_gate(
    pool: PgPool,
) -> anyhow::Result<()> {
    for pow_enabled in [false, true] {
        for invite_enabled in [false, true] {
            let (application, store) = app_with_store(&pool).await?;
            store
                .set_config(
                    "registration_pow_enabled",
                    if pow_enabled { "1" } else { "0" },
                )
                .await?;
            store
                .set_config(
                    "registration_invite_enabled",
                    if invite_enabled { "1" } else { "0" },
                )
                .await?;
            store.set_config("registration_mode", "open").await?;

            let response = get(application.clone(), "/register").await?;
            let html =
                String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
            assert_eq!(html.contains("name=\"invite_code\""), invite_enabled);
            assert_eq!(html.contains("name=\"pow_nonce\""), pow_enabled);

            let csrf = csrf_token(application.clone(), "/register", None).await?;
            let response = post_form(
                application.clone(),
                "/register",
                None,
                &format!("csrf_token={csrf}&username=bad&password=short"),
            )
            .await?;
            assert_eq!(
                response.status(),
                if pow_enabled {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::BAD_REQUEST
                },
                "PoW setting must be enforced before registration input is accepted"
            );

            if !pow_enabled {
                reset_store(&store).await?;
                store
                    .set_config(
                        "registration_invite_enabled",
                        if invite_enabled { "1" } else { "0" },
                    )
                    .await?;
                store.set_config("registration_pow_enabled", "0").await?;
                store.set_config("registration_mode", "open").await?;
                let csrf = csrf_token(application.clone(), "/register", None).await?;
                let response = post_form(
                    application,
                    "/register",
                    None,
                    &format!("csrf_token={csrf}&username=valid_user&password=long-enough"),
                )
                .await?;
                assert_eq!(
                    response.status(),
                    if invite_enabled {
                        StatusCode::BAD_REQUEST
                    } else {
                        StatusCode::SEE_OTHER
                    },
                    "invite setting must be enforced by the registration POST"
                );
            }
        }
    }

    let (application, store) = app_with_store(&pool).await?;
    store.set_config("registration_mode", "closed").await?;
    let response = get(application.clone(), "/register").await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let csrf = csrf_token(application.clone(), "/login", None).await?;
    let response = post_form(
        application,
        "/register",
        None,
        &format!("csrf_token={csrf}&username=valid_user&password=long-enough"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[sqlx::test]
async fn report_policy_hides_entry_and_rejects_direct_submission(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (application, store) = app_with_store(&pool).await?;
    let user_id = store.create_user("reporter", "hash", false).await?;
    let session_id = store.create_session(user_id).await?;
    let board_id = store
        .create_board("reports", "Reports", "test board", false, true)
        .await?;
    let thread_id = store
        .create_thread(
            board_id,
            user_id,
            "Report target",
            "content",
            "<p>content</p>",
            false,
        )
        .await?;
    let cookie = format!("session_id={session_id}");

    for enabled in [false, true] {
        store
            .set_config("reports_enabled", if enabled { "1" } else { "0" })
            .await?;
        let response = get(application.clone(), &format!("/t/{thread_id}")).await?;
        let html = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
        // An unauthenticated view cannot render a report form, so exercise it with the session.
        let request = Request::get(format!("/t/{thread_id}"))
            .header(header::COOKIE, &cookie)
            .body(axum::body::Body::empty())?;
        let response = application.clone().oneshot(request).await?;
        let authenticated_html =
            String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
        assert_eq!(
            authenticated_html.contains(&format!("/report/thread/{thread_id}")),
            enabled
        );
        assert!(!html.contains(&format!("/report/thread/{thread_id}")));

        let csrf = csrf_token(
            application.clone(),
            &format!("/t/{thread_id}"),
            Some(&cookie),
        )
        .await?;
        let response = post_form(
            application.clone(),
            &format!("/report/thread/{thread_id}"),
            Some(&cookie),
            &format!("csrf_token={csrf}&reason=policy-test"),
        )
        .await?;
        assert_eq!(
            response.status(),
            if enabled {
                StatusCode::SEE_OTHER
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }

    store.set_config("reports_enabled", "1").await?;
    let csrf = csrf_token(
        application.clone(),
        &format!("/t/{thread_id}"),
        Some(&cookie),
    )
    .await?;
    let response = post_form(
        application,
        "/report/thread/999999",
        Some(&cookie),
        &format!("csrf_token={csrf}&reason=missing-target"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}
