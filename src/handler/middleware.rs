use axum::{
    extract::State,
    http::header,
    response::{Html, IntoResponse, Response},
};

use super::{apply_sec, html_escape, session_id};

pub async fn maintenance_gate(
    State(store): State<crate::store::Store>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    let exempt = path == "/healthz"
        || path == "/login"
        || path == "/logout"
        || path.starts_with("/static/")
        || path == "/api/pow/challenge"
        || path == "/theme"
        // Members still need their account page (and a way out) while the
        // forum itself is closed.
        || path.starts_with("/account")
        || path.starts_with("/admin")
        || path.starts_with("/governance");
    if exempt || store.get_config_opt("maintenance_enabled").await.as_deref() != Some("1") {
        return next.run(request).await;
    }
    let is_admin = match session_id(request.headers()) {
        Some(sid) => store
            .get_user_by_session(&sid)
            .await
            .ok()
            .flatten()
            .map(|u| u.is_admin)
            .unwrap_or(false),
        None => false,
    };
    if is_admin {
        return next.run(request).await;
    }
    // A machine client cannot read a maintenance page: answer 503 so retries
    // and health checks behave, and keep the HTML page for navigation requests.
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) {
        return apply_sec(
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "forum is under maintenance",
            )
                .into_response(),
        );
    }
    let title = html_escape(
        &store
            .get_config_opt("maintenance_title")
            .await
            .unwrap_or_else(|| "Under maintenance".into()),
    );
    let body = html_escape(
        &store
            .get_config_opt("maintenance_message")
            .await
            .unwrap_or_else(|| "The forum is temporarily unavailable.".into()),
    );
    let eta = html_escape(
        &store
            .get_config_opt("maintenance_eta")
            .await
            .unwrap_or_default(),
    );
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="maintenance-page"><section class="card"><h1>{title}</h1><p>{body}</p>{}</section></main></body></html>"#,
        if eta.is_empty() {
            String::new()
        } else {
            format!("<p class=\"muted\">Expected completion: {eta}</p>")
        }
    );
    apply_sec(Html(html).into_response())
}

pub async fn theme_query_cookie(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let theme = request.uri().query().and_then(|query| {
        query.split('&').find_map(|part| {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("theme"), Some("light")) => Some("light"),
                (Some("theme"), Some("dark")) => Some("dark"),
                _ => None,
            }
        })
    });
    if let Some(theme) = theme {
        let mut cookies = request
            .headers()
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .filter(|part| !part.trim_start().starts_with("theme="))
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        cookies.push(if theme == "light" {
            "theme=light"
        } else {
            "theme=dark"
        });
        if let Ok(value) = cookies.join("; ").parse() {
            request.headers_mut().insert(header::COOKIE, value);
        }
    }
    next.run(request).await
}
