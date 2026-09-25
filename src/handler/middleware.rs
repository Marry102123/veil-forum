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
        Some(sid) => match store.get_user_by_session(&sid).await.ok().flatten() {
            Some(user) => {
                user.is_admin
                    || store
                        .user_has_role(user.id, crate::store::Role::Admin)
                        .await
                        .unwrap_or(false)
                    || store
                        .user_has_role(user.id, crate::store::Role::Owner)
                        .await
                        .unwrap_or(false)
            }
            None => false,
        },
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

/// Policy gate: when TOTP is required, unactivated non-staff sessions are
/// confined to account/TOTP recovery, logout, static assets, and health.
pub async fn totp_gate(
    State(store): State<crate::store::Store>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Resolve the exempt paths first: they are most of the traffic (static
    // assets) and none of them can be gated, so they cost no query.
    let path = request.uri().path();
    let exempt = path == "/healthz"
        || path == "/login"
        || path == "/login/totp"
        || path == "/logout"
        || path == "/theme"
        || path == "/api/pow/challenge"
        || path.starts_with("/static/")
        || path.starts_with("/account");
    if exempt {
        return next.run(request).await;
    }
    let policy = store
        .get_config_opt("totp_required")
        .await
        .unwrap_or_default();
    if policy != "staff" && policy != "all" {
        return next.run(request).await;
    }
    // The session cookie must be read exactly the way the handlers read it,
    // otherwise a request can look signed out to this gate and signed in to the
    // handler it guards.
    let Some(user) = (match session_id(request.headers()) {
        Some(sid) => store.get_user_by_session(&sid).await.ok().flatten(),
        None => None,
    }) else {
        // Guests are handled by the individual handlers.
        return next.run(request).await;
    };
    if !crate::handler::account::policy_applies(&store, &user).await {
        return next.run(request).await;
    }
    if store
        .totp_state(user.id)
        .await
        .map(|state| state.is_active())
        .unwrap_or(false)
    {
        return next.run(request).await;
    }
    if path.starts_with("/admin") || path.starts_with("/governance") {
        return apply_sec(
            (
                axum::http::StatusCode::FORBIDDEN,
                "TOTP enrollment required",
            )
                .into_response(),
        );
    }

    let locale = store
        .get_config_opt("default_locale")
        .await
        .unwrap_or_else(|| "en".to_string());
    let ui = |en: &str, zh: &str, ru: &str| crate::i18n::ui(&locale, en, zh, ru);
    let title = ui(
        "Second factor required",
        "需要先绑定动态口令",
        "Требуется второй фактор",
    );
    let body = ui(
        "This forum requires two-step verification. Open your account page to set it up, then continue.",
        "本站要求使用二步验证。请到账号页完成绑定后继续浏览。",
        "На этом форуме требуется двухшаговая проверка. Настройте её на странице аккаунта и продолжите.",
    );
    let link = ui("Go to account", "前往账号页", "Перейти в аккаунт");
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="maintenance-page"><section class="card"><h1>{title}</h1><p>{body}</p><p><a class="btn-link" href="/account">{link}</a></p></section></main></body></html>"#
    );
    apply_sec(Html(html).into_response())
}
