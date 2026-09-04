//! HTTP contract tests for the no-JavaScript forum surface.
//!
//! These tests exercise the router in-process, so they do not bind a port or
//! touch a deployed/VPS instance.

use anyhow::Context;
use axum::{
    body::to_bytes,
    http::{header, Request, StatusCode},
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower::ServiceExt;
use veil_forum::{captcha, handler, pow, store::Store};

async fn app_with_store() -> anyhow::Result<(axum::Router, Store)> {
    // Keep trigger bodies intact. Store::open's compatibility migration path
    // splits legacy SQL on semicolons, which is unsuitable for this schema.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    for migration in [
        include_str!("../migrations/001_init.sql"),
        include_str!("../migrations/002_i18n.sql"),
        include_str!("../migrations/003_parent.sql"),
        include_str!("../migrations/004_security.sql"),
        include_str!("../migrations/005_default_english.sql"),
        include_str!("../migrations/006_default_board_english.sql"),
        include_str!("../migrations/007_search_trigram.sql"),
        include_str!("../migrations/009_thread_listing_order.sql"),
        include_str!("../migrations/010_moderation_data_layer.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await?;
    }
    let store = Store { pool };
    let state = handler::AppState {
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: veil_forum::rate_limit::Limits::new(),
        store: store.clone(),
        password_gate: Arc::new(Semaphore::new(8)),
    };
    Ok((handler::routes(state), store))
}

async fn app() -> anyhow::Result<axum::Router> {
    Ok(app_with_store().await?.0)
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

#[tokio::test]
async fn healthz_reports_ready_and_security_headers() -> anyhow::Result<()> {
    let response = get(app().await?, "/healthz").await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; child-src 'self'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'self'");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(to_bytes(response.into_body(), usize::MAX).await?, "ok");
    Ok(())
}

#[tokio::test]
async fn pow_endpoint_validates_scope_and_returns_challenge_contract() -> anyhow::Result<()> {
    let application = app().await?;
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

#[tokio::test]
async fn login_pow_fallback_is_present_in_server_rendered_html() -> anyhow::Result<()> {
    let application = app().await?;
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

#[tokio::test]
async fn theme_query_is_rendered_without_javascript_and_toggle_is_safe() -> anyhow::Result<()> {
    let application = app().await?;
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

#[tokio::test]
async fn static_assets_are_served_and_traversal_is_not() -> anyhow::Result<()> {
    let application = app().await?;
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

#[tokio::test]
async fn registration_policy_switches_control_rendered_fields_and_server_pow_gate(
) -> anyhow::Result<()> {
    for pow_enabled in [false, true] {
        for invite_enabled in [false, true] {
            let (application, store) = app_with_store().await?;
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
                application,
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
                let (application, store) = app_with_store().await?;
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

    let (application, store) = app_with_store().await?;
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

#[tokio::test]
async fn report_policy_hides_entry_and_rejects_direct_submission() -> anyhow::Result<()> {
    let (application, store) = app_with_store().await?;
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
