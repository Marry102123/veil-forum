use axum::middleware;
use axum::{
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use hmac::Mac;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tera::Context;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState {
    pub store: crate::store::Store,
    pub pow: crate::pow::Manager,
    pub password_gate: Arc<Semaphore>,
}

#[derive(Deserialize)]
struct PowQuery {
    scope: String,
}

const CSP: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; child-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'";
const MAX_FORM_BYTES: usize = 64 * 1024;

fn csrf_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    })
}
fn csrf_token(headers: &HeaderMap) -> String {
    let session = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let mut kv = part.trim().splitn(2, '=');
                (kv.next()? == "session_id").then(|| kv.next().unwrap_or("").to_string())
            })
        })
        .unwrap_or_else(|| "anonymous".to_string());
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(csrf_key()).expect("fixed-size HMAC key");
    mac.update(session.as_bytes());
    mac.update(nonce_hex.as_bytes());
    format!("{}{}", nonce_hex, hex::encode(mac.finalize().into_bytes()))
}
fn csrf_field(headers: &HeaderMap) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
        html_escape(&csrf_token(headers))
    )
}
fn valid_csrf(headers: &HeaderMap, form: &HashMap<String, String>) -> bool {
    let supplied = form.get("csrf_token").map(String::as_str).unwrap_or("");
    if supplied.len() != 128 || !supplied.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let session = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let mut kv = part.trim().splitn(2, '=');
                (kv.next()? == "session_id").then(|| kv.next().unwrap_or("").to_string())
            })
        })
        .unwrap_or_else(|| "anonymous".to_string());
    let nonce = &supplied[..64];
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(csrf_key()).expect("fixed-size HMAC key");
    mac.update(session.as_bytes());
    mac.update(nonce.as_bytes());
    mac.verify_slice(&hex::decode(&supplied[64..]).unwrap_or_default())
        .is_ok()
}
fn valid_origin(headers: &HeaderMap) -> bool {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    origin
        .map(|v| {
            if v == "null" {
                return true;
            }
            v.strip_prefix("https://")
                .or_else(|| v.strip_prefix("http://"))
                .and_then(|rest| rest.split('/').next())
                == Some(host)
        })
        .unwrap_or(true)
}
fn require_form_security(headers: &HeaderMap, form: &HashMap<String, String>) -> bool {
    valid_csrf(headers, form) && valid_origin(headers)
}

fn registration_error_response(error: anyhow::Error) -> Response {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("unique constraint failed: users.username")
        || message.contains("users.username") && message.contains("unique")
    {
        return apply_sec((StatusCode::CONFLICT, "username taken").into_response());
    }
    if message.contains("invite invalid or already used") {
        return apply_sec(
            (StatusCode::BAD_REQUEST, "invite invalid or already used").into_response(),
        );
    }
    apply_sec(
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "registration temporarily unavailable",
        )
            .into_response(),
    )
}

#[cfg(test)]
mod security_tests {
    use super::*;

    fn valid_pow_form() -> HashMap<String, String> {
        HashMap::from([
            ("pow_challenge".into(), "a".repeat(32)),
            ("pow_salt".into(), "b".repeat(16)),
            ("pow_difficulty".into(), "4".into()),
            (
                "pow_expires_at".into(),
                (chrono::Utc::now().timestamp() + 60).to_string(),
            ),
            ("pow_hmac".into(), "c".repeat(64)),
            ("pow_nonce".into(), "0".into()),
        ])
    }

    #[test]
    fn pow_form_rejects_oversized_or_invalid_values() {
        let mut form = valid_pow_form();
        assert!(verify_pow_form(&form, crate::pow::Scope::Post).is_ok());
        form.insert("pow_nonce".into(), "n".repeat(65));
        assert!(verify_pow_form(&form, crate::pow::Scope::Post).is_err());

        let mut form = valid_pow_form();
        form.insert("pow_difficulty".into(), "25".into());
        assert!(verify_pow_form(&form, crate::pow::Scope::Post).is_err());

        let mut form = valid_pow_form();
        form.insert(
            "pow_expires_at".into(),
            (chrono::Utc::now().timestamp() + 301).to_string(),
        );
        assert!(verify_pow_form(&form, crate::pow::Scope::Post).is_err());
    }

    #[test]
    fn origin_must_match_host_except_null_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "forum.test".parse().unwrap());
        headers.insert(header::ORIGIN, "https://forum.test".parse().unwrap());
        assert!(valid_origin(&headers));

        headers.insert(header::ORIGIN, "https://attacker.test".parse().unwrap());
        assert!(!valid_origin(&headers));

        headers.insert(header::ORIGIN, "null".parse().unwrap());
        assert!(valid_origin(&headers));
    }

    #[test]
    fn registration_errors_do_not_mislabel_non_conflicts() {
        assert_eq!(
            registration_error_response(anyhow::anyhow!("invite invalid or already used")).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            registration_error_response(anyhow::anyhow!("database is locked")).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            registration_error_response(anyhow::anyhow!(
                "UNIQUE constraint failed: users.username"
            ))
            .status(),
            StatusCode::CONFLICT
        );
    }
}

fn sec_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_SECURITY_POLICY, CSP.parse().unwrap());
    h.insert("X-Frame-Options", "DENY".parse().unwrap());
    h.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    h.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    h.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
            .parse()
            .unwrap(),
    );
    h.insert("Cross-Origin-Opener-Policy", "same-origin".parse().unwrap());
    h.insert(
        "Cross-Origin-Resource-Policy",
        "same-origin".parse().unwrap(),
    );
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h
}
fn apply_sec(mut resp: axum::response::Response) -> axum::response::Response {
    let hdrs = sec_headers();
    for (k, v) in hdrs.iter() {
        resp.headers_mut().insert(k.clone(), v.clone());
    }
    resp
}
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn get_theme(headers: &HeaderMap) -> &'static str {
    if let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
            if kv.len() == 2 && kv[0].trim() == "theme" {
                if kv[1].trim() == "light" {
                    return "light";
                }
                if kv[1].trim() == "dark" {
                    return "dark";
                }
            }
        }
    }
    "dark"
}
async fn get_site_name(store: &crate::store::Store) -> String {
    store
        .get_config("site_name")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "secure-forum".to_string())
}
async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<crate::store::User> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
        if kv.len() == 2 && kv[0].trim() == "session_id" {
            let sid = kv[1].trim();
            if let Ok(Some(u)) = state.store.get_user_by_session(sid).await {
                return Some(u);
            }
        }
    }
    None
}
async fn sidebar_data(
    store: &crate::store::Store,
) -> (
    Vec<crate::store::Board>,
    String,
    i64,
    i64,
    i64,
    Vec<crate::store::Thread>,
    String,
) {
    let boards = store.list_boards().await.unwrap_or_default();
    let pow_min = store
        .get_config("pow_post_minutes")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "0.02".to_string());
    let pool = &store.pool;
    let mut stats_threads: i64 = 0;
    let mut stats_posts: i64 = 0;
    let mut stats_users: i64 = 0;
    if let Ok(row) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM threads")
        .fetch_one(pool)
        .await
    {
        stats_threads = row.0;
    }
    // Each thread has one opening post. The sidebar label is "Replies", so
    // exclude those opening posts instead of reporting the total post count.
    if let Ok(row) = sqlx::query_as::<_, (i64,)>(
        "SELECT COUNT(*) FROM posts p WHERE p.id != (SELECT MIN(op.id) FROM posts op WHERE op.thread_id = p.thread_id)",
    )
        .fetch_one(pool)
        .await
    {
        stats_posts = row.0;
    }
    if let Ok(row) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
    {
        stats_users = row.0;
    }
    // recent 5 threads
    let recent = {
        let mut v = Vec::new();
        if let Ok(rows) = sqlx::query("SELECT id, board_id, title, author_id, is_pinned, is_locked, reply_count, last_reply_at, created_at FROM threads ORDER BY last_reply_at DESC LIMIT 5").fetch_all(pool).await {
            for r in rows {
                use sqlx::Row;
                let last: String = r.get("last_reply_at");
                let created: String = r.get("created_at");
                // fetch author_name and slug crudely
                let tid: i64 = r.get("id");
                let th = store.get_thread(tid).await.ok().flatten();
                if let Some(t) = th { v.push(t); } else {
                    v.push(crate::store::Thread{
                        id: r.get("id"), board_id: r.get("board_id"), title: r.get("title"),
                        author_id: r.get("author_id"), is_pinned: r.get::<i64,_>("is_pinned")==1, is_locked: r.get::<i64,_>("is_locked")==1,
                        reply_count: r.get("reply_count"), last_reply_at: crate::store::parse_time(&last), created_at: crate::store::parse_time(&created),
                        author_name: "".to_string(), board_slug: "".to_string(),
                    });
                }
            }
        }
        v
    };
    let announcement = store
        .get_config("announcement")
        .await
        .unwrap_or(None)
        .unwrap_or_default();
    (
        boards,
        pow_min,
        stats_threads,
        stats_posts,
        stats_users,
        recent,
        announcement,
    )
}

#[allow(clippy::too_many_arguments)]
fn layout_html(
    title: &str,
    site_name: &str,
    user: Option<&crate::store::User>,
    boards: &[crate::store::Board],
    pow_minutes: &str,
    stats_threads: i64,
    stats_posts: i64,
    stats_users: i64,
    recent: &[crate::store::Thread],
    announcement: &str,
    content: &str,
    need_pow: bool,
    flash: Option<(&str, &str)>,
    theme: &str,
    locale: &str,
    headers: &HeaderMap,
) -> String {
    let ui = |en, zh, ru| crate::i18n::ui(locale, en, zh, ru);
    let account_html = if let Some(u) = user {
        let admin_link = if u.is_admin {
            format!(
                r#"<a href="/admin">{}</a>"#,
                crate::i18n::translate(locale, "nav.admin")
            )
        } else {
            String::new()
        };
        format!(
            r#"<div class="account-name">{}</div><div class="account-links">{}<form method="POST" action="/logout">{}<button class="btn-sm" aria-label="{}">{}</button></form></div>"#,
            html_escape(&u.username),
            admin_link,
            csrf_field(headers),
            crate::i18n::translate(locale, "nav.logout"),
            crate::i18n::translate(locale, "nav.logout")
        )
    } else {
        format!(
            r#"<div class="account-links"><a class="btn-link" href="/login">{}</a><a class="btn-link" href="/register">{}</a></div><div class="muted account-note">{}</div>"#,
            crate::i18n::translate(locale, "nav.login"),
            crate::i18n::translate(locale, "nav.register"),
            crate::i18n::translate(locale, "account.login_hint")
        )
    };
    let flash_html = if let Some((msg, kind)) = flash {
        format!(
            r#"<div class="flash flash-{}" role="alert" aria-live="polite">{}</div>"#,
            html_escape(kind),
            html_escape(msg)
        )
    } else {
        "".to_string()
    };
    let boards_html = if boards.is_empty() {
        format!(
            r#"<div class="muted">{}</div>"#,
            ui("No boards", "暂无版块", "Нет разделов")
        )
    } else {
        let mut s = String::new();
        for b in boards {
            s.push_str(&format!(r#"<div class="board-list-item"><a href="/b/{}" title="{}">{}</a> <span class="muted">/{}</span></div>"#, html_escape(&b.slug), html_escape(&b.description), html_escape(&b.name), html_escape(&b.slug)));
        }
        s
    };
    let recent_html = if recent.is_empty() {
        format!(
            r#"<div class="muted" style="padding:6px 0">{}</div>"#,
            ui("None", "暂无", "Нет")
        )
    } else {
        let mut s = String::new();
        for t in recent {
            s.push_str(&format!(
                r#"<div class="recent-item"><a href="/t/{}" title="{}">{}</a></div>"#,
                t.id,
                html_escape(&t.title),
                html_escape(&t.title)
            ));
        }
        s
    };
    // Always emit an explicit theme. Without data-theme="dark", the CSS
    // prefers-color-scheme fallback can override a NoScript dark selection.
    let search_label = crate::i18n::translate(locale, "nav.search");
    let boards_label = crate::i18n::translate(locale, "nav.boards");
    let account_label = crate::i18n::translate(locale, "account.title");
    let board_count = ui("boards", "版", "разделов");
    let all_boards = ui("All", "全部", "Все");
    let announcement_label = ui("Announcement", "公告", "Объявление");
    let announcement_body = if announcement.trim().is_empty() {
        format!(
            r#"<span class="muted">{}</span>"#,
            ui("No announcement", "暂无公告", "Нет объявлений")
        )
    } else {
        html_escape(announcement)
    };
    let display_label = ui("Display", "显示设置", "Отображение");
    let light_label = ui("Light", "白天", "Светлая");
    let dark_label = ui("Dark", "夜间", "Тёмная");
    let stats_label = ui("Stats", "统计", "Статистика");
    let threads_label = ui("Threads", "主题", "Темы");
    let replies_label = ui("Replies", "回帖", "Ответы");
    let users_label = ui("Users", "用户", "Пользователи");
    let recent_label = ui("Recent", "最新", "Последнее");
    let loopback_label = ui(
        "loopback only",
        "仅 127.0.0.1:8001",
        "только 127.0.0.1:8001",
    );
    let mut context = tera::Context::new();
    context.insert("title", title);
    context.insert("site_name", site_name);
    context.insert("locale", locale);
    context.insert("theme", if theme == "light" { "light" } else { "dark" });
    context.insert("need_pow", &need_pow);
    context.insert("flash_html", &flash_html);
    context.insert("account_html", &account_html);
    context.insert("boards_html", &boards_html);
    context.insert("boards_len", &boards.len());
    context.insert("content", &content);
    context.insert("pow_minutes", pow_minutes);
    context.insert("stats_threads", &stats_threads);
    context.insert("stats_posts", &stats_posts);
    context.insert("stats_users", &stats_users);
    context.insert("recent_html", &recent_html);
    context.insert("announcement_body", &announcement_body);
    for (key, value) in [
        ("search_label", search_label),
        ("account_label", account_label),
        ("boards_label", boards_label),
        ("board_count", board_count),
        ("all_boards", all_boards),
        ("announcement_label", announcement_label),
        ("display_label", display_label),
        ("light_label", light_label),
        ("dark_label", dark_label),
        ("stats_label", stats_label),
        ("threads_label", threads_label),
        ("replies_label", replies_label),
        ("users_label", users_label),
        ("recent_label", recent_label),
        ("loopback_label", loopback_label),
    ] {
        context.insert(key, &value);
    }
    crate::templates::render_layout(&context).expect("embedded layout template must render")
}

fn verify_pow_form(
    form: &HashMap<String, String>,
    _scope: crate::pow::Scope,
) -> Result<(String, String, u32, i64, String, String), String> {
    let chal = form.get("pow_challenge").cloned().unwrap_or_default();
    let salt = form.get("pow_salt").cloned().unwrap_or_default();
    let diff_s = form.get("pow_difficulty").cloned().unwrap_or_default();
    let exp_s = form.get("pow_expires_at").cloned().unwrap_or_default();
    let hmac = form.get("pow_hmac").cloned().unwrap_or_default();
    let nonce = form.get("pow_nonce").cloned().unwrap_or_default();
    if chal.is_empty()
        || salt.is_empty()
        || diff_s.is_empty()
        || exp_s.is_empty()
        || hmac.is_empty()
        || nonce.is_empty()
    {
        return Err("missing pow fields".to_string());
    }
    if chal.len() > 128 || salt.len() > 64 || hmac.len() > 128 || nonce.len() > 64 {
        return Err("pow field too long".to_string());
    }
    let diff: u32 = diff_s.parse().map_err(|_| "bad difficulty")?;
    if !(4..=24).contains(&diff) {
        return Err("difficulty out of range".to_string());
    }
    let exp: i64 = exp_s.parse().map_err(|_| "bad expires")?;
    let now = chrono::Utc::now().timestamp();
    if exp < now || exp > now + 300 {
        return Err("expires out of range".to_string());
    }
    Ok((chal, salt, diff, exp, hmac, nonce))
}
fn pow_fallback_html(ch: &crate::pow::Challenge, locale: &str) -> String {
    let ui = |en, zh, ru| crate::i18n::ui(locale, en, zh, ru);
    let py = format!(
        r#"# Python standard library only
import hashlib
def has_leading_zeros(h, bits):
    full = bits//8
    rem = bits%8
    for i in range(full):
        if h[i]!=0:
            return False
    if rem>0 and h[full] >> (8-rem) !=0:
        return False
    return True
challenge = "{ch}"
salt = "{salt}"
difficulty = {diff}
for nonce in range(20000000):
    secret = f"veil-forum-pow-v2{{salt}}{{challenge}}{{nonce}}".encode()
    out = hashlib.sha256(secret).digest()
    if has_leading_zeros(out, difficulty):
        print(f"found nonce={{nonce}}")
        break
# Paste the resulting nonce into pow_nonce before submitting.
# Difficulty {diff}; expected work: approximately {exp} attempts.
"#,
        ch = ch.challenge,
        salt = ch.salt,
        diff = ch.difficulty,
        exp = 1u64 << ch.difficulty
    );
    let mut context = Context::new();
    // Tera auto-escapes these ordinary template fields. Escaping them here as
    // well turns the displayed Python fallback into invalid source code.
    context.insert("challenge", &ch.challenge);
    context.insert("salt", &ch.salt);
    context.insert("difficulty", &ch.difficulty);
    context.insert("expires_at", &ch.expires_at);
    context.insert("hmac", &ch.hmac);
    context.insert("scope", &ch.scope);
    context.insert("python", &py);
    context.insert("nonce_label", &ui("PoW nonce", "PoW nonce", "PoW nonce"));
    context.insert(
        "nonce_hint",
        &ui("Paste nonce", "粘贴 nonce", "Вставьте nonce"),
    );
    context.insert(
        "manual_title",
        &ui(
            "JavaScript disabled: manual PoW",
            "JS 已禁用 - 手动 PoW",
            "JavaScript отключён: ручной PoW",
        ),
    );
    context.insert("manual_help", &ui("This form requires a SHA-256 proof of work. Run this locally when JavaScript is unavailable.", "本表单需要 SHA-256 工作量证明。无 JavaScript 环境请在本地运行。", "Для формы требуется SHA-256 proof of work. Выполните локально без JavaScript."));
    context.insert("difficulty_label", &ui("difficulty", "难度", "сложность"));
    context.insert("expires_label", &ui("expires", "过期", "истекает"));
    crate::templates::render_pow_fallback(&context).expect("PoW fallback template must render")
}

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(healthz))
        .route("/api/pow/challenge", get(pow_challenge))
        .route("/theme", get(theme_toggle))
        .route("/static/*path", get(handle_static))
        .route("/b/:slug", get(board))
        .route("/t/:id", get(thread))
        .route("/search", get(search))
        .route("/register", get(register_get).post(register_post))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", post(logout))
        .route("/b/:slug/new", post(new_thread))
        .route("/t/:id/reply", post(reply))
        .route("/admin", get(admin))
        .route("/admin/config/site", post(admin_site))
        .route("/admin/config/announcement", post(admin_announcement))
        .route("/admin/config/pow", post(admin_pow))
        .route("/admin/config/registration", post(admin_regmode))
        .route("/admin/config/locale", post(admin_locale))
        .route("/admin/board/create", post(board_create))
        .route("/admin/board/:id/update", post(board_update))
        .route("/admin/board/:id/delete", post(board_delete))
        .route("/admin/invite/create", post(invite_create))
        .route("/admin/invite/:code/delete", post(invite_delete))
        .route("/admin/user/:id/ban", post(ban))
        .route("/admin/user/:id/unban", post(unban))
        .route("/admin/thread/:id/pin", post(pin))
        .route("/admin/thread/:id/lock", post(lock))
        .route("/admin/thread/:id/delete", post(thread_delete))
        .route("/admin/post/:id/delete", post(post_delete))
        .route("/admin/change-password", post(change_password))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_FORM_BYTES))
        .layer(middleware::from_fn(theme_query_cookie))
        .with_state(state)
}

async fn pow_challenge(State(s): State<AppState>, Query(q): Query<PowQuery>) -> impl IntoResponse {
    let scope = match q.scope.as_str() {
        "register" => crate::pow::Scope::Register,
        "login" => crate::pow::Scope::Login,
        "post" => crate::pow::Scope::Post,
        _ => return (StatusCode::BAD_REQUEST, "invalid PoW scope").into_response(),
    };
    apply_sec(axum::Json(s.pow.generate(scope).await).into_response())
}

async fn healthz(State(s): State<AppState>) -> impl IntoResponse {
    let status = match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&s.store.pool)
        .await
    {
        Ok(1) => (StatusCode::OK, "ok"),
        Ok(_) | Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable"),
    };
    let resp = status.into_response();
    apply_sec(resp)
}

async fn site_locale(store: &crate::store::Store) -> String {
    let value = store
        .get_config("default_locale")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "en".to_string());
    if crate::i18n::I18n::supported().contains(&value.as_str()) {
        value
    } else {
        "en".to_string()
    }
}

async fn handle_static(Path(path): Path<String>, _headers: HeaderMap) -> impl IntoResponse {
    let rel = path.trim_start_matches('/');
    // prevent traversal
    if rel.contains("..") || rel.contains("//") || rel.starts_with('/') {
        let resp = (StatusCode::NOT_FOUND, "not found").into_response();
        return apply_sec(resp);
    }
    // primary: manifest_dir/static, fallback: exe-relative for docker
    let manifest_static = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
    let primary = std::path::Path::new(manifest_static).join(rel);
    let mut candidates = vec![primary];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("static").join(rel));
            candidates.push(dir.join("../static").join(rel));
        }
    }
    // also allow /app/static for container
    candidates.push(std::path::PathBuf::from("/app/static").join(rel));
    let mut bytes: Option<Vec<u8>> = None;
    let mut etag: Option<String> = None;
    for c in candidates {
        if let Ok(b) = std::fs::read(&c) {
            // simple etag from length+mtime
            if let Ok(meta) = std::fs::metadata(&c) {
                if let Ok(mtime) = meta.modified() {
                    if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
                        etag = Some(format!("\"{:x}-{:x}\"", b.len(), dur.as_secs()));
                    }
                }
            }
            bytes = Some(b);
            break;
        }
    }
    if let Some(b) = bytes {
        let ct = if rel.ends_with(".js") {
            "application/javascript; charset=utf-8"
        } else if rel.ends_with(".wasm") {
            "application/wasm"
        } else if rel.ends_with(".css") {
            "text/css; charset=utf-8"
        } else if rel.ends_with(".json") {
            "application/json"
        } else {
            "application/octet-stream"
        };
        let mut resp = (StatusCode::OK, [(header::CONTENT_TYPE, ct)], b).into_response();
        for (k, v) in sec_headers().iter() {
            resp.headers_mut().insert(k.clone(), v.clone());
        }
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if let Some(e) = etag {
            resp.headers_mut().insert(header::ETAG, e.parse().unwrap());
        }
        return resp;
    }
    let resp = (StatusCode::NOT_FOUND, "not found").into_response();
    apply_sec(resp)
}

// ---------- Home ----------
async fn theme_toggle(
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let theme = match q.get("to").map(String::as_str) {
        Some("light") => "light",
        _ => "dark",
    };
    let location = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|referer| {
            let path = if referer.starts_with('/') {
                referer.to_string()
            } else {
                referer
                    .find("://")
                    .and_then(|scheme| {
                        referer[scheme + 3..]
                            .find('/')
                            .map(|p| &referer[scheme + 3 + p..])
                    })
                    .unwrap_or("/")
                    .to_string()
            };
            let clean = path.split('#').next().unwrap_or("/");
            (!clean.starts_with("//") && clean.starts_with('/')).then(|| clean.to_string())
        })
        .unwrap_or_else(|| "/".to_string());
    let mut parts = location.splitn(2, '?');
    let path = parts.next().unwrap_or("/");
    let query = parts.next().unwrap_or("");
    let query = query
        .split('&')
        .filter(|part| !part.starts_with("theme=") && !part.is_empty())
        .chain(std::iter::once(if theme == "light" {
            "theme=light"
        } else {
            "theme=dark"
        }))
        .collect::<Vec<_>>()
        .join("&");
    let location = format!("{}?{}", path, query);
    let mut response = Redirect::to(&location).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("theme={theme}; Path=/; Max-Age=31536000; SameSite=Lax")
            .parse()
            .expect("valid theme cookie"),
    );
    apply_sec(response)
}

// URL theme state is the no-cookie fallback used by NoScript and hardened
// browsers. Inject it as a synthetic request cookie so all existing handlers
// use the same rendering path without changing every handler signature.
async fn theme_query_cookie(
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

async fn home(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = current_user(&s, &headers).await;
    let site = get_site_name(&s.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let visible: Vec<_> = boards
        .iter()
        .filter(|b| b.guest_readable || user.is_some())
        .cloned()
        .collect();
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let rendered_boards: Vec<_> = visible.iter().map(|b| serde_json::json!({
        "slug": b.slug, "name": b.name, "description": b.description,
        "anonymous_label": ui(if b.allow_anonymous { "Anonymous" } else { "Named" }, if b.allow_anonymous { "匿名" } else { "实名" }, if b.allow_anonymous { "Анонимно" } else { "С именем" }),
        "access_label": ui(if b.guest_readable { "Public" } else { "Login required" }, if b.guest_readable { "公开" } else { "需登录" }, if b.guest_readable { "Публичный" } else { "Требуется вход" }),
    })).collect();
    let mut context = Context::new();
    context.insert("boards", &rendered_boards);
    context.insert("boards_label", &ui("Boards", "版块", "Разделы"));
    context.insert(
        "empty_label",
        &ui(
            "No boards yet",
            "暂无版块 · 等待管理员创建",
            "Разделов пока нет",
        ),
    );
    let content = crate::templates::render_page("home", &context)
        .expect("embedded home template must render");
    let full = layout_html(
        &ui("Home", "首页", "Главная"),
        &site,
        user.as_ref(),
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        false,
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}

// ---------- Board ----------
#[derive(Deserialize)]
struct PageQ {
    page: Option<i64>,
    reply_to: Option<i64>,
}
async fn board(
    State(s): State<AppState>,
    Path(slug): Path<String>,
    Query(q): Query<PageQ>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let board = match s.store.get_board_by_slug(&slug).await.unwrap_or(None) {
        Some(board) => board,
        None => return apply_sec((StatusCode::NOT_FOUND, "board not found").into_response()),
    };
    let user = current_user(&s, &headers).await;
    if !board.guest_readable && user.is_none() {
        return apply_sec(Redirect::to("/login").into_response());
    }
    let page = q.page.unwrap_or(1).max(1);
    let page_size = 20;
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let (threads, total) = s
        .store
        .list_threads(board.id, page, page_size)
        .await
        .unwrap_or((Vec::new(), 0));
    let total_pages = ((total + page_size - 1) / page_size).max(1);
    let pow_min = s
        .store
        .get_config("pow_post_minutes")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "0.02".to_string());
    let (boards, _, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let mut context = Context::new();
    let rendered_threads: Vec<_>=threads.iter().map(|t| serde_json::json!({"id":t.id,"title":t.title,"author_name":t.author_name,"reply_count":t.reply_count,"last_reply_at":t.last_reply_at.format("%m-%d %H:%M").to_string(),"is_pinned":t.is_pinned,"is_locked":t.is_locked})).collect();
    context.insert("board",&serde_json::json!({"slug":board.slug,"name":board.name,"description":board.description,"allow_anonymous":board.allow_anonymous}));
    context.insert("threads", &rendered_threads);
    context.insert("page", &page);
    context.insert("total_pages", &total_pages);
    context.insert("total", &total);
    context.insert("can_post", &user.is_some());
    context.insert("csrf_field", &csrf_field(&headers));
    if user.is_some() {
        let ch = s.pow.generate(crate::pow::Scope::Post).await;
        context.insert("pow_fallback", &pow_fallback_html(&ch, &locale));
    }
    for (key, value) in [
        ("boards_label", ui("Boards", "版块", "Разделы")),
        ("page_label", ui("Page", "页", "Страница")),
        ("posts_label", ui("posts", "帖", "сообщений")),
        ("new_thread_label", ui("New thread", "发新帖", "Новая тема")),
        (
            "title_hint",
            ui(
                "Title, 5-120 characters",
                "标题 5-120字",
                "Заголовок, 5-120 символов",
            ),
        ),
        (
            "markdown_hint",
            ui(
                "Markdown supported. Images are disabled.",
                "正文 Markdown 支持 基础+代码块+表格 · 禁图",
                "Поддерживается Markdown. Изображения отключены.",
            ),
        ),
        ("anonymous_label", ui("Anonymous", "匿名", "Анонимно")),
        ("post_label", ui("Post", "发帖", "Опубликовать")),
        (
            "login_to_post_label",
            ui(
                "Log in to post",
                "登录后发帖",
                "Войдите, чтобы создать тему",
            ),
        ),
        (
            "empty_label",
            ui("No threads yet", "暂无主题 · 抢沙发", "Тем пока нет"),
        ),
        ("pinned_label", ui("pinned", "置顶", "закреплено")),
        ("locked_label", ui("locked", "锁定", "закрыто")),
        (
            "pow_title",
            crate::i18n::translate(&locale, "pow.post_title"),
        ),
        (
            "pow_description",
            crate::i18n::translate(&locale, "pow.description"),
        ),
        (
            "pow_computing",
            crate::i18n::translate(&locale, "pow.computing"),
        ),
        ("pow_done", crate::i18n::translate(&locale, "pow.done")),
        ("pow_failed", crate::i18n::translate(&locale, "pow.failed")),
        (
            "pow_submitting",
            crate::i18n::translate(&locale, "pow.submitting"),
        ),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("board", &context)
        .expect("embedded board template must render");
    let full = layout_html(
        &board.name,
        &get_site_name(&s.store).await,
        user.as_ref(),
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        user.is_some(),
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}

// ---------- Thread ----------
async fn thread(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<PageQ>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let th = match s.store.get_thread(id).await.unwrap_or(None) {
        Some(t) => t,
        None => return apply_sec((StatusCode::NOT_FOUND, "thread not found").into_response()),
    };
    let board = s.store.get_board_by_id(th.board_id).await.unwrap_or(None);
    let user = current_user(&s, &headers).await;
    if board.as_ref().is_some_and(|b| !b.guest_readable) && user.is_none() {
        return apply_sec(Redirect::to("/login").into_response());
    }
    let page = q.page.unwrap_or(1).max(1);
    let page_size = 50;
    let (posts, total) = s
        .store
        .list_posts(th.id, page, page_size)
        .await
        .unwrap_or((Vec::new(), 0));
    let total_pages = ((total + page_size - 1) / page_size).max(1);
    let is_admin = user.as_ref().is_some_and(|u| u.is_admin);
    let pow_min = s
        .store
        .get_config("pow_post_minutes")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "0.02".to_string());
    let (boards, _, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let names: HashMap<i64, String> = posts
        .iter()
        .map(|p| {
            (
                p.id,
                if p.is_anonymous {
                    ui("Anonymous", "匿名", "Аноним")
                } else {
                    p.author_name.clone()
                },
            )
        })
        .collect();
    let rendered_posts:Vec<_>=posts.iter().enumerate().map(|(idx,p)|{let quote=p.parent_post_id.and_then(|pid|posts.iter().find(|parent|parent.id==pid)).map(|parent|serde_json::json!({"author_name":names.get(&parent.id).cloned().unwrap_or_else(||ui("deleted","已删除","удалён")),"text":parent.content_md.chars().take(120).collect::<String>()}));serde_json::json!({"id":p.id,"author_name":names.get(&p.id).cloned().unwrap_or_default(),"is_anonymous":p.is_anonymous,"created_at":p.created_at.format("%m-%d %H:%M:%S").to_string(),"content_html":p.content_html,"reply_to":p.parent_post_id.map(|pid|serde_json::json!({"id":pid,"author_name":names.get(&pid).cloned().unwrap_or_else(||ui("deleted","已删除","удалён"))})),"quote":quote,"floor":(page-1)*page_size+idx as i64+1} )}).collect();
    let mut context = Context::new();
    context.insert("thread",&serde_json::json!({"id":th.id,"board_slug":th.board_slug,"title":th.title,"author_name":th.author_name,"created_at":th.created_at.format("%Y-%m-%d %H:%M").to_string(),"is_pinned":th.is_pinned,"is_locked":th.is_locked}));
    context.insert("posts", &rendered_posts);
    context.insert("can_reply", &user.is_some());
    context.insert("is_admin", &is_admin);
    context.insert(
        "allow_anonymous",
        &board.as_ref().is_some_and(|b| b.allow_anonymous),
    );
    context.insert("page", &page);
    context.insert("total_pages", &total_pages);
    context.insert("csrf_field", &csrf_field(&headers));
    if user.is_some() && !th.is_locked {
        let ch = s.pow.generate(crate::pow::Scope::Post).await;
        context.insert("pow_fallback", &pow_fallback_html(&ch, &locale));
        let reply_post = match q.reply_to.filter(|post_id| *post_id > 0) {
            Some(post_id) => s
                .store
                .get_post(post_id)
                .await
                .ok()
                .flatten()
                .filter(|post| post.thread_id == th.id),
            None => None,
        };
        context.insert("reply_to_id", &reply_post.as_ref().map(|post| post.id));
        let hint = reply_post
            .as_ref()
            .map(|post| {
                let author = if post.is_anonymous {
                    ui("Anonymous", "匿名", "Аноним")
                } else {
                    post.author_name.clone()
                };
                format!(
                    r#"<div class="reply-target"><b>{} @{}</b><span>“{}”</span><a href="/t/{}#reply-card">{}</a></div>"#,
                    ui("Reply to", "回复", "Ответить"),
                    html_escape(&author),
                    html_escape(&post.content_md.chars().take(120).collect::<String>()),
                    th.id,
                    ui("Cancel", "取消", "Отмена")
                )
            })
            .unwrap_or_default();
        context.insert("reply_hint", &hint);
    }
    for (key, value) in [
        ("thread_label", ui("Thread", "主题", "Тема")),
        ("pinned_label", ui("pinned", "置顶", "закреплено")),
        ("locked_label", ui("locked", "锁定", "закрыто")),
        ("anonymous_label", ui("Anonymous", "匿名", "Аноним")),
        ("replying_label", ui("Replying to", "回复", "Ответ на")),
        ("reply_label", ui("Reply", "回帖", "Ответить")),
        ("delete_label", ui("Delete", "删除", "Удалить")),
        (
            "empty_label",
            ui("No replies yet", "暂无回帖", "Ответов пока нет"),
        ),
        (
            "locked_notice",
            ui(
                "This thread is locked.",
                "已锁定，禁止回帖",
                "Эта тема закрыта.",
            ),
        ),
        (
            "login_to_reply_label",
            ui("Log in to reply", "登录后回帖", "Войдите, чтобы ответить"),
        ),
        (
            "moderator_actions_label",
            ui("Moderator actions", "管理员操作", "Действия модератора"),
        ),
        (
            "pin_label",
            if th.is_pinned {
                ui("Unpin", "取消置顶", "Открепить")
            } else {
                ui("Pin", "置顶", "Закрепить")
            },
        ),
        (
            "lock_label",
            if th.is_locked {
                ui("Unlock", "解锁", "Открыть")
            } else {
                ui("Lock", "锁定", "Закрыть")
            },
        ),
        (
            "delete_thread_label",
            ui("Delete thread", "删主题", "Удалить тему"),
        ),
        (
            "markdown_hint",
            ui(
                "Markdown supported.",
                "Markdown 支持 基础+代码块+表格",
                "Поддерживается Markdown.",
            ),
        ),
        ("page_label", ui("Page", "页", "Страница")),
        (
            "pow_title",
            crate::i18n::translate(&locale, "pow.reply_title"),
        ),
        (
            "pow_description",
            crate::i18n::translate(&locale, "pow.description"),
        ),
        (
            "pow_computing",
            crate::i18n::translate(&locale, "pow.computing"),
        ),
        ("pow_done", crate::i18n::translate(&locale, "pow.done")),
        ("pow_failed", crate::i18n::translate(&locale, "pow.failed")),
        (
            "pow_submitting",
            crate::i18n::translate(&locale, "pow.submitting"),
        ),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("thread", &context)
        .expect("embedded thread template must render");
    let full = layout_html(
        &th.title,
        &get_site_name(&s.store).await,
        user.as_ref(),
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        user.is_some(),
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}

// ---------- Search ----------
async fn search(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let query = q.get("q").cloned().unwrap_or_default().trim().to_string();
    let page = q
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let user = current_user(&s, &headers).await;
    let site = get_site_name(&s.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let mut context = Context::new();
    context.insert("query", &query);
    context.insert("page", &page);
    let mut total = 0;
    let mut total_pages = 1;
    let mut results = Vec::new();
    if !query.is_empty() {
        let page_size = 20;
        let (posts, _, count) = s
            .store
            .search_posts(&query, page, page_size)
            .await
            .unwrap_or((Vec::new(), Vec::new(), 0));
        total = count;
        total_pages = ((total + page_size - 1) / page_size).max(1);
        for post in posts {
            let title = s
                .store
                .get_thread(post.thread_id)
                .await
                .unwrap_or(None)
                .map(|t| t.title)
                .unwrap_or_else(|| query.clone());
            let raw = post.content_md.chars().take(200).collect::<String>();
            let snippet_source = if post.content_md.chars().count() > 200 {
                format!("{raw}...")
            } else {
                raw
            };
            let snippet = crate::markdown::render(&snippet_source);
            results.push(serde_json::json!({"thread_id":post.thread_id,"id":post.id,"title":title,"author_name":if post.is_anonymous {ui("Anonymous","匿名","Аноним")} else {post.author_name},"created_at":post.created_at.format("%m-%d").to_string(),"snippet":snippet}));
        }
    }
    context.insert("results", &results);
    context.insert("total", &total);
    context.insert("total_pages", &total_pages);
    for (key, value) in [
        ("search_label", ui("Search", "搜索", "Поиск")),
        (
            "search_hint",
            ui("Search terms", "关键词", "Поисковый запрос"),
        ),
        ("search_button", ui("Search", "搜", "Найти")),
        ("results_label", ui("results", "条结果", "результатов")),
        ("page_label", ui("Page", "页", "Страница")),
        (
            "empty_label",
            ui("No results", "无结果 · 换词再试", "Ничего не найдено"),
        ),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("search", &context)
        .expect("embedded search template must render");
    let full = layout_html(
        &ui("Search", "搜索", "Поиск"),
        &site,
        user.as_ref(),
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        false,
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}

// ---------- Register ----------
async fn register_get(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if current_user(&s, &headers).await.is_some() {
        return apply_sec(Redirect::to("/").into_response());
    }
    let reg_mode = s
        .store
        .get_config("registration_mode")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "invite".to_string());
    let need_invite = reg_mode == "invite";
    let pow_min = s
        .store
        .get_config("pow_register_minutes")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "0.02".to_string());
    let site = get_site_name(&s.store).await;
    let (boards, _, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let mut context = Context::new();
    let ch = s.pow.generate(crate::pow::Scope::Register).await;
    context.insert("csrf_field", &csrf_field(&headers));
    context.insert("pow_fallback", &pow_fallback_html(&ch, &locale));
    context.insert("need_invite", &need_invite);
    context.insert(
        "registration_mode",
        &ui("Registration mode", "注册模式", "Режим регистрации"),
    );
    context.insert("reg_mode", &reg_mode);
    context.insert(
        "recovery_hint",
        &ui(
            "No email recovery. Keep your password safe.",
            "无邮箱找回，丢密即丢号",
            "Восстановления по email нет. Сохраните пароль.",
        ),
    );
    for (key, value) in [
        (
            "username_label",
            crate::i18n::translate(&locale, "auth.username"),
        ),
        (
            "password_label",
            crate::i18n::translate(&locale, "auth.password"),
        ),
        (
            "register_label",
            crate::i18n::translate(&locale, "nav.register"),
        ),
        ("login_label", crate::i18n::translate(&locale, "nav.login")),
        (
            "register_button",
            crate::i18n::format(
                crate::i18n::translate(&locale, "auth.register_pow"),
                "minutes",
                &pow_min,
            ),
        ),
        (
            "pow_title",
            crate::i18n::translate(&locale, "pow.register_title"),
        ),
        (
            "pow_description",
            crate::i18n::translate(&locale, "pow.description"),
        ),
        (
            "pow_computing",
            crate::i18n::translate(&locale, "pow.computing"),
        ),
        ("pow_done", crate::i18n::translate(&locale, "pow.done")),
        ("pow_failed", crate::i18n::translate(&locale, "pow.failed")),
        (
            "pow_submitting",
            crate::i18n::translate(&locale, "pow.submitting"),
        ),
        (
            "invite_label",
            ui("Invite code", "邀请码", "Код приглашения"),
        ),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("register", &context)
        .expect("embedded register template must render");
    let full = layout_html(
        &crate::i18n::translate(&locale, "nav.register"),
        &site,
        None,
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        true,
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}
async fn register_post(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    // verify pow
    let pow_fields = match verify_pow_form(&form, crate::pow::Scope::Register) {
        Ok(v) => v,
        Err(e) => {
            let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
            return apply_sec(resp);
        }
    };
    if let Err(e) = s
        .pow
        .verify(
            crate::pow::Scope::Register,
            &pow_fields.0,
            &pow_fields.1,
            pow_fields.2,
            pow_fields.3,
            &pow_fields.4,
            &pow_fields.5,
        )
        .await
    {
        let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
        return apply_sec(resp);
    }
    let reg_mode = s
        .store
        .get_config("registration_mode")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "invite".to_string());
    if reg_mode == "closed" {
        let resp = (StatusCode::FORBIDDEN, "registration closed").into_response();
        return apply_sec(resp);
    }
    let username = form
        .get("username")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();
    let invite = form
        .get("invite_code")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    // validate username 3-20 alnum_
    if username.len() < 3
        || username.len() > 20
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        let resp = (StatusCode::BAD_REQUEST, "invalid username").into_response();
        return apply_sec(resp);
    }
    if password.len() < 6 || password.len() > 72 {
        let resp = (StatusCode::BAD_REQUEST, "password length").into_response();
        return apply_sec(resp);
    }
    if reg_mode == "invite" && invite.is_empty() {
        let resp = (StatusCode::BAD_REQUEST, "invite required").into_response();
        return apply_sec(resp);
    }
    let _permit = match s.password_gate.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return apply_sec(
                (StatusCode::SERVICE_UNAVAILABLE, "authentication busy").into_response(),
            )
        }
    };
    let hash_result =
        match tokio::task::spawn_blocking(move || crate::auth::hash_password(&password)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("password hashing failed")),
        };
    let hash = match hash_result {
        Ok(h) => h,
        Err(e) => {
            let resp =
                (StatusCode::INTERNAL_SERVER_ERROR, format!("hash err {}", e)).into_response();
            return apply_sec(resp);
        }
    };
    let uid = match if reg_mode == "invite" {
        s.store
            .register_with_invite(&username, &hash, &invite)
            .await
    } else {
        s.store.create_user(&username, &hash, false).await
    } {
        Ok(id) => id,
        Err(error) => return registration_error_response(error),
    };
    let _ = s.store.delete_sessions_by_user(uid).await;
    let sid = match s.store.create_session(uid).await {
        Ok(sid) => sid,
        Err(_) => {
            return apply_sec(
                (StatusCode::INTERNAL_SERVER_ERROR, "session creation failed").into_response(),
            )
        }
    };
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "session_id={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            sid,
            12 * 3600
        )
        .parse()
        .unwrap(),
    );
    apply_sec(resp)
}
// ---------- Login ----------
async fn login_get(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if current_user(&s, &headers).await.is_some() {
        return apply_sec(Redirect::to("/").into_response());
    }
    let site = get_site_name(&s.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let locale = site_locale(&s.store).await;
    let mut context = Context::new();
    let ch = s.pow.generate(crate::pow::Scope::Login).await;
    context.insert("csrf_field", &csrf_field(&headers));
    context.insert("pow_fallback", &pow_fallback_html(&ch, &locale));
    for (key, value) in [
        (
            "username_label",
            crate::i18n::translate(&locale, "auth.username"),
        ),
        (
            "password_label",
            crate::i18n::translate(&locale, "auth.password"),
        ),
        (
            "register_label",
            crate::i18n::translate(&locale, "nav.register"),
        ),
        ("login_label", crate::i18n::translate(&locale, "nav.login")),
        (
            "pow_title",
            crate::i18n::translate(&locale, "pow.login_title"),
        ),
        (
            "pow_description",
            crate::i18n::translate(&locale, "pow.description"),
        ),
        (
            "pow_computing",
            crate::i18n::translate(&locale, "pow.computing"),
        ),
        ("pow_done", crate::i18n::translate(&locale, "pow.done")),
        ("pow_failed", crate::i18n::translate(&locale, "pow.failed")),
        (
            "pow_submitting",
            crate::i18n::translate(&locale, "pow.submitting"),
        ),
        (
            "email_hint",
            crate::i18n::ui(
                &locale,
                "no email required",
                "无需邮箱",
                "email не требуется",
            ),
        ),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("login", &context)
        .expect("embedded login template must render");
    let full = layout_html(
        &crate::i18n::translate(&locale, "nav.login"),
        &site,
        None,
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        true,
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}
async fn login_post(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let pow_fields = match verify_pow_form(&form, crate::pow::Scope::Login) {
        Ok(v) => v,
        Err(e) => {
            return apply_sec((StatusCode::FORBIDDEN, format!("PoW failed: {e}")).into_response())
        }
    };
    if let Err(e) = s
        .pow
        .verify(
            crate::pow::Scope::Login,
            &pow_fields.0,
            &pow_fields.1,
            pow_fields.2,
            pow_fields.3,
            &pow_fields.4,
            &pow_fields.5,
        )
        .await
    {
        return apply_sec((StatusCode::FORBIDDEN, format!("PoW failed: {e}")).into_response());
    }
    let username = form
        .get("username")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();
    let u_opt = s
        .store
        .get_user_by_username(&username)
        .await
        .unwrap_or(None);
    let u = match u_opt {
        Some(u) => u,
        None => {
            let resp = (StatusCode::FORBIDDEN, "invalid credentials").into_response();
            return apply_sec(resp);
        }
    };
    if u.is_banned {
        let resp = (StatusCode::FORBIDDEN, "banned").into_response();
        return apply_sec(resp);
    }
    let _permit = match s.password_gate.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return apply_sec(
                (StatusCode::SERVICE_UNAVAILABLE, "authentication busy").into_response(),
            )
        }
    };
    let hash = u.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || crate::auth::verify_password(&hash, &password))
        .await
        .unwrap_or(false);
    if !valid {
        let resp = (StatusCode::FORBIDDEN, "invalid credentials").into_response();
        return apply_sec(resp);
    }
    let _ = s.store.delete_sessions_by_user(u.id).await;
    let sid = match s.store.create_session(u.id).await {
        Ok(sid) => sid,
        Err(_) => {
            return apply_sec(
                (StatusCode::INTERNAL_SERVER_ERROR, "session creation failed").into_response(),
            )
        }
    };
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "session_id={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            sid,
            12 * 3600
        )
        .parse()
        .unwrap(),
    );
    apply_sec(resp)
}
async fn logout(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let mut sid_opt: Option<String> = None;
    if let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
            if kv.len() == 2 && kv[0].trim() == "session_id" {
                sid_opt = Some(kv[1].trim().to_string());
            }
        }
    }
    if let Some(sid) = sid_opt {
        let _ = s.store.delete_session(&sid).await;
    }
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        "session_id=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    apply_sec(resp)
}

// ---------- New Thread ----------
async fn new_thread(
    State(s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let user = current_user(&s, &headers).await;
    let u = match user {
        Some(u) => u,
        None => {
            let resp = Redirect::to("/login").into_response();
            return apply_sec(resp);
        }
    };
    if u.is_banned {
        let resp = (StatusCode::FORBIDDEN, "banned").into_response();
        return apply_sec(resp);
    }
    let board_opt = s.store.get_board_by_slug(&slug).await.unwrap_or(None);
    let board = match board_opt {
        Some(b) => b,
        None => {
            let resp = (StatusCode::NOT_FOUND, "board not found").into_response();
            return apply_sec(resp);
        }
    };
    let pow_fields = match verify_pow_form(&form, crate::pow::Scope::Post) {
        Ok(v) => v,
        Err(e) => {
            let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
            return apply_sec(resp);
        }
    };
    if let Err(e) = s
        .pow
        .verify(
            crate::pow::Scope::Post,
            &pow_fields.0,
            &pow_fields.1,
            pow_fields.2,
            pow_fields.3,
            &pow_fields.4,
            &pow_fields.5,
        )
        .await
    {
        let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
        return apply_sec(resp);
    }
    let title = form
        .get("title")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let content = form
        .get("content")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let anon = form.get("anonymous").map(|x| x == "on").unwrap_or(false);
    if title.len() < 5 || title.len() > 120 {
        let resp = (StatusCode::BAD_REQUEST, "title 5-120").into_response();
        return apply_sec(resp);
    }
    if content.is_empty() || content.len() > 20000 {
        let resp = (StatusCode::BAD_REQUEST, "content length").into_response();
        return apply_sec(resp);
    }
    if anon && !board.allow_anonymous {
        let resp = (StatusCode::FORBIDDEN, "anonymous not allowed").into_response();
        return apply_sec(resp);
    }
    let html = crate::markdown::render(&content);
    match s
        .store
        .create_thread(board.id, u.id, &title, &content, &html, anon)
        .await
    {
        Ok(tid) => {
            let resp = Redirect::to(&format!("/t/{}", tid)).into_response();
            apply_sec(resp)
        }
        Err(e) => {
            let resp = (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            apply_sec(resp)
        }
    }
}

// ---------- Reply ----------
async fn reply(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let user = current_user(&s, &headers).await;
    let u = match user {
        Some(u) => u,
        None => {
            let resp = Redirect::to("/login").into_response();
            return apply_sec(resp);
        }
    };
    if u.is_banned {
        let resp = (StatusCode::FORBIDDEN, "banned").into_response();
        return apply_sec(resp);
    }
    let th_opt = s.store.get_thread(id).await.unwrap_or(None);
    let th = match th_opt {
        Some(t) => t,
        None => {
            let resp = (StatusCode::NOT_FOUND, "thread not found").into_response();
            return apply_sec(resp);
        }
    };
    if th.is_locked {
        let resp = (StatusCode::FORBIDDEN, "thread locked").into_response();
        return apply_sec(resp);
    }
    let board = s.store.get_board_by_id(th.board_id).await.unwrap_or(None);
    let pow_fields = match verify_pow_form(&form, crate::pow::Scope::Post) {
        Ok(v) => v,
        Err(e) => {
            let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
            return apply_sec(resp);
        }
    };
    if let Err(e) = s
        .pow
        .verify(
            crate::pow::Scope::Post,
            &pow_fields.0,
            &pow_fields.1,
            pow_fields.2,
            pow_fields.3,
            &pow_fields.4,
            &pow_fields.5,
        )
        .await
    {
        let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
        return apply_sec(resp);
    }
    let content = form
        .get("content")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let anon = form.get("anonymous").map(|x| x == "on").unwrap_or(false);
    if content.is_empty() || content.len() > 20000 {
        let resp = (StatusCode::BAD_REQUEST, "content length").into_response();
        return apply_sec(resp);
    }
    if anon && board.as_ref().map(|b| !b.allow_anonymous).unwrap_or(false) {
        let resp = (StatusCode::FORBIDDEN, "anonymous not allowed").into_response();
        return apply_sec(resp);
    }
    // 楼中楼：解析 parent_post_id（可选）
    let parent_post_id: Option<i64> = form
        .get("parent_post_id")
        .and_then(|v| {
            let s = v.trim();
            if s.is_empty() {
                return None;
            }
            s.parse::<i64>().ok()
        })
        .filter(|&pid| pid > 0);
    // 若提供了 parent，校验其存在且属于同一 thread
    let parent_validated: Option<i64> = if let Some(pid) = parent_post_id {
        match s.store.get_post(pid).await.unwrap_or(None) {
            Some(p) if p.thread_id == th.id => Some(pid),
            _ => None, // 无效 parent 则退化为回楼主
        }
    } else {
        None
    };
    let html = crate::markdown::render(&content);
    let create_res = if let Some(pid) = parent_validated {
        s.store
            .create_post_with_parent(th.id, th.board_id, u.id, anon, &content, &html, Some(pid))
            .await
    } else {
        s.store
            .create_post(th.id, th.board_id, u.id, anon, &content, &html)
            .await
    };
    match create_res {
        Ok(_) => {
            let resp = Redirect::to(&format!("/t/{}", th.id)).into_response();
            apply_sec(resp)
        }
        Err(e) => {
            let resp = (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            apply_sec(resp)
        }
    }
}

// ---------- Admin Helpers ----------
async fn require_admin_state(state: &AppState, headers: &HeaderMap) -> Option<crate::store::User> {
    let u = current_user(state, headers).await?;
    if u.is_admin {
        Some(u)
    } else {
        None
    }
}
async fn audit_admin(
    state: &AppState,
    headers: &HeaderMap,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<i64>,
    success: bool,
) {
    let actor = current_user(state, headers).await.map(|u| u.id);
    let _ = state
        .store
        .audit(actor, action, target_type, target_id, success)
        .await;
}
async fn admin(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = match require_admin_state(&s, &headers).await {
        Some(u) => u,
        None => return apply_sec((StatusCode::FORBIDDEN, "forbidden").into_response()),
    };
    let boards = s.store.list_boards().await.unwrap_or_default();
    let users = s.store.list_users(100).await.unwrap_or_default();
    let configs = s.store.get_all_configs().await.unwrap_or_default();
    let invites = s.store.list_invites().await.unwrap_or_default();
    let site = get_site_name(&s.store).await;
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let (sboards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let mut context = Context::new();
    context.insert("csrf_field", &csrf_field(&headers));
    context.insert("username", &user.username);
    context.insert(
        "site_name_value",
        configs
            .get("site_name")
            .map(String::as_str)
            .unwrap_or("secure-forum"),
    );
    context.insert(
        "default_locale",
        configs
            .get("default_locale")
            .map(String::as_str)
            .unwrap_or("en"),
    );
    context.insert(
        "announcement",
        configs
            .get("announcement")
            .map(String::as_str)
            .unwrap_or(""),
    );
    context.insert(
        "pow_register_minutes",
        configs
            .get("pow_register_minutes")
            .map(String::as_str)
            .unwrap_or("0.02"),
    );
    context.insert(
        "pow_login_minutes",
        configs
            .get("pow_login_minutes")
            .map(String::as_str)
            .unwrap_or("0.02"),
    );
    context.insert(
        "pow_post_minutes",
        configs
            .get("pow_post_minutes")
            .map(String::as_str)
            .unwrap_or("0.02"),
    );
    context.insert(
        "registration_mode",
        configs
            .get("registration_mode")
            .map(String::as_str)
            .unwrap_or("invite"),
    );
    let rendered_invites: Vec<_> = invites
        .iter()
        .map(|invite| serde_json::json!({"code": invite.code, "used_by": invite.used_by}))
        .collect();
    let rendered_users: Vec<_> = users
        .iter()
        .map(|user| serde_json::json!({"id": user.id, "username": user.username, "is_admin": user.is_admin, "is_banned": user.is_banned}))
        .collect();
    context.insert("invites", &rendered_invites);
    context.insert("users", &rendered_users);
    let render_boards:Vec<_>=boards.iter().map(|b|serde_json::json!({"id":b.id,"slug":b.slug,"name":b.name,"description":b.description,"allow_anonymous":b.allow_anonymous,"guest_readable":b.guest_readable,"allow_anonymous_label":ui(if b.allow_anonymous{"Yes"}else{"No"},if b.allow_anonymous{"是"}else{"否"},if b.allow_anonymous{"Да"}else{"Нет"}),"guest_readable_label":ui(if b.guest_readable{"Yes"}else{"No"},if b.guest_readable{"是"}else{"否"},if b.guest_readable{"Да"}else{"Нет"})})).collect();
    context.insert("boards", &render_boards);
    for (key, value) in [
        (
            "admin_label",
            ui("Administration", "管理后台", "Администрирование"),
        ),
        (
            "site_settings_label",
            ui("Site settings", "站点配置", "Настройки сайта"),
        ),
        (
            "site_name_label",
            ui("Site name", "站点名", "Название сайта"),
        ),
        ("save_label", crate::i18n::translate(&locale, "admin.save")),
        (
            "locale_label",
            crate::i18n::translate(&locale, "admin.default_locale"),
        ),
        (
            "announcement_label",
            ui("Announcement", "公告", "Объявление"),
        ),
        (
            "announcement_hint",
            ui(
                "Leave blank to hide",
                "留空则不显示",
                "Оставьте пустым, чтобы скрыть",
            ),
        ),
        (
            "announcement_help",
            ui(
                "Shown on every page.",
                "显示在所有页面右侧。",
                "Показывается на каждой странице.",
            ),
        ),
        (
            "save_announcement_label",
            ui("Save announcement", "保存公告", "Сохранить объявление"),
        ),
        (
            "register_pow_label",
            ui(
                "Registration PoW minutes",
                "注册 PoW 分钟",
                "Минуты PoW регистрации",
            ),
        ),
        (
            "login_pow_label",
            ui("Login PoW minutes", "登录 PoW 分钟", "Минуты PoW входа"),
        ),
        (
            "post_pow_label",
            ui(
                "Posting PoW minutes",
                "发帖 PoW 分钟",
                "Минуты PoW публикации",
            ),
        ),
        (
            "pow_help",
            ui(
                "SHA-256 PoW minutes, from 0.005 to 10.",
                "SHA-256 PoW 小数分钟 0.005~10",
                "Минуты SHA-256 PoW, от 0.005 до 10.",
            ),
        ),
        ("save_pow_label", ui("Save PoW", "保存PoW", "Сохранить PoW")),
        (
            "registration_mode_label",
            ui("Registration mode", "注册模式", "Режим регистрации"),
        ),
        ("open_label", ui("Open", "开放", "Открытая")),
        (
            "invite_label",
            ui("Invite only", "需邀请码", "Только по приглашению"),
        ),
        ("closed_label", ui("Closed", "关闭", "Закрыта")),
        (
            "change_password_label",
            ui("Change password", "改密", "Сменить пароль"),
        ),
        (
            "current_password_label",
            ui("Current password", "旧密码", "Текущий пароль"),
        ),
        (
            "new_password_label",
            ui("New password", "新密码", "Новый пароль"),
        ),
        (
            "invite_codes_label",
            ui("Invite codes", "生成邀请码", "Коды приглашений"),
        ),
        (
            "create_code_label",
            ui("Create code", "生成1枚", "Создать код"),
        ),
        ("used_label", ui("used by", "已用 by", "использован")),
        ("unused_label", ui("unused", "未用", "не использован")),
        ("revoke_label", ui("Revoke", "作废", "Отозвать")),
        (
            "no_invites_label",
            ui("No invite codes", "无邀请码", "Нет кодов приглашения"),
        ),
        (
            "board_management_label",
            ui("Board management", "版块管理", "Управление разделами"),
        ),
        ("name_label", ui("Name", "名称", "Название")),
        ("description_label", ui("Description", "描述", "Описание")),
        ("anonymous_label", ui("Anonymous", "匿名", "Анонимно")),
        (
            "guest_readable_label",
            ui("Guest readable", "游客可读", "Доступно гостям"),
        ),
        ("readable_label", ui("Readable", "可读", "Чтение")),
        (
            "create_board_label",
            ui("Create board", "创建版块", "Создать раздел"),
        ),
        ("actions_label", ui("Actions", "操作", "Действия")),
        ("update_label", ui("Update", "更新", "Обновить")),
        ("delete_label", ui("Delete", "删", "Удалить")),
        (
            "user_management_label",
            ui(
                "User management (latest 100)",
                "用户管理 (近100)",
                "Управление пользователями (100 последних)",
            ),
        ),
        ("user_label", ui("User", "用户", "Пользователь")),
        ("banned_label", ui("Banned", "banned", "Заблокирован")),
        ("ban_label", ui("Ban", "封禁", "Заблокировать")),
        ("unban_label", ui("Unban", "解封", "Разблокировать")),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("admin", &context)
        .expect("embedded admin template must render");
    let full = layout_html(
        &ui("Administration", "管理后台", "Администрирование"),
        &site,
        Some(&user),
        &sboards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &content,
        false,
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    apply_sec(Html(full).into_response())
}
async fn admin_site(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let mut name = form
        .get("site_name")
        .map(|x| x.trim().to_string())
        .unwrap_or_else(|| "secure-forum".to_string());
    if name.is_empty() {
        name = "secure-forum".to_string();
    }
    if name.chars().count() > 50 {
        name = name.chars().take(50).collect();
    }
    let ok = s.store.set_config("site_name", &name).await.is_ok();
    audit_admin(&s, &headers, "config.site", Some("config"), None, ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn admin_announcement(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        return apply_sec((StatusCode::FORBIDDEN, "forbidden").into_response());
    }
    let mut announcement = form
        .get("announcement")
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string();
    if announcement.chars().count() > 1000 {
        announcement = announcement.chars().take(1000).collect();
    }
    let ok = s
        .store
        .set_config("announcement", &announcement)
        .await
        .is_ok();
    audit_admin(
        &s,
        &headers,
        "config.announcement",
        Some("config"),
        None,
        ok,
    )
    .await;
    apply_sec(Redirect::to("/admin").into_response())
}
async fn admin_pow(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let mut ok = true;
    for k in [
        "pow_register_minutes",
        "pow_login_minutes",
        "pow_post_minutes",
    ] {
        let v = form
            .get(k)
            .map(|x| x.trim().to_string())
            .unwrap_or_else(|| "0.02".to_string());
        let mut f: f64 = v.parse().unwrap_or(0.005);
        if f <= 0.0 {
            f = 0.005;
        }
        if f > 10.0 {
            f = 10.0;
        }
        let val = format!("{:.5}", f);
        ok &= s.store.set_config(k, &val).await.is_ok();
    }
    audit_admin(&s, &headers, "config.pow", Some("config"), None, ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn admin_regmode(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let mut mode = form
        .get("registration_mode")
        .cloned()
        .unwrap_or_else(|| "open".to_string());
    if mode != "open" && mode != "invite" && mode != "closed" {
        mode = "open".to_string();
    }
    let ok = s.store.set_config("registration_mode", &mode).await.is_ok();
    audit_admin(
        &s,
        &headers,
        "config.registration",
        Some("config"),
        None,
        ok,
    )
    .await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn admin_locale(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        return apply_sec((StatusCode::FORBIDDEN, "forbidden").into_response());
    }
    let locale = form
        .get("default_locale")
        .map(String::as_str)
        .unwrap_or("en");
    let ok = crate::i18n::I18n::supported().contains(&locale)
        && s.store.set_config("default_locale", locale).await.is_ok();
    audit_admin(&s, &headers, "config.locale", Some("config"), None, ok).await;
    apply_sec(Redirect::to("/admin").into_response())
}
async fn board_create(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let slug = form
        .get("slug")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let name = form
        .get("name")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let desc = form
        .get("description")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let allow_anon = form
        .get("allow_anonymous")
        .map(|x| x == "on")
        .unwrap_or(false);
    let guest_readable = form
        .get("guest_readable")
        .map(|x| x == "on")
        .unwrap_or(false);
    if slug.is_empty() || name.is_empty() {
        let resp = (StatusCode::BAD_REQUEST, "slug and name required").into_response();
        return apply_sec(resp);
    }
    if let Err(e) = s
        .store
        .create_board(&slug, &name, &desc, allow_anon, guest_readable)
        .await
    {
        let resp = (StatusCode::BAD_REQUEST, format!("{}", e)).into_response();
        return apply_sec(resp);
    }
    audit_admin(&s, &headers, "board.create", Some("board"), None, true).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn board_update(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let b_opt = s.store.get_board_by_id(id).await.unwrap_or(None);
    let b = match b_opt {
        Some(b) => b,
        None => {
            let resp = (StatusCode::NOT_FOUND, "board not found").into_response();
            return apply_sec(resp);
        }
    };
    let mut name = form
        .get("name")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let desc = form
        .get("description")
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let allow_anon = form
        .get("allow_anonymous")
        .map(|x| x == "on")
        .unwrap_or(false);
    let guest_readable = form
        .get("guest_readable")
        .map(|x| x == "on")
        .unwrap_or(false);
    if name.is_empty() {
        name = b.name;
    }
    let ok = s
        .store
        .update_board(id, &name, &desc, allow_anon, guest_readable)
        .await
        .is_ok();
    audit_admin(&s, &headers, "board.update", Some("board"), Some(id), ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn board_delete(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let ok = s.store.delete_board(id).await.is_ok();
    audit_admin(&s, &headers, "board.delete", Some("board"), Some(id), ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn invite_create(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let user = match require_admin_state(&s, &headers).await {
        Some(u) => u,
        None => {
            let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
            return apply_sec(resp);
        }
    };
    let code = random_code(12);
    let ok = s.store.create_invite(&code, user.id).await.is_ok();
    audit_admin(&s, &headers, "invite.create", Some("invite"), None, ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn invite_delete(
    State(s): State<AppState>,
    Path(code): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let ok = s.store.delete_invite(&code).await.is_ok();
    audit_admin(&s, &headers, "invite.delete", Some("invite"), None, ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn ban(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let ok = s.store.set_user_banned(id, true).await.is_ok()
        && s.store.delete_sessions_by_user(id).await.is_ok();
    audit_admin(&s, &headers, "user.ban", Some("user"), Some(id), ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn unban(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let ok = s.store.set_user_banned(id, false).await.is_ok();
    audit_admin(&s, &headers, "user.unban", Some("user"), Some(id), ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn pin(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    if let Some(th) = s.store.get_thread(id).await.unwrap_or(None) {
        let ok = s.store.set_thread_pinned(id, !th.is_pinned).await.is_ok();
        audit_admin(&s, &headers, "thread.pin", Some("thread"), Some(id), ok).await;
    }
    let resp = Redirect::to(&format!("/t/{}", id)).into_response();
    apply_sec(resp)
}
async fn lock(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    if let Some(th) = s.store.get_thread(id).await.unwrap_or(None) {
        let ok = s.store.set_thread_locked(id, !th.is_locked).await.is_ok();
        audit_admin(&s, &headers, "thread.lock", Some("thread"), Some(id), ok).await;
    }
    let resp = Redirect::to(&format!("/t/{}", id)).into_response();
    apply_sec(resp)
}
async fn thread_delete(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let ok = s.store.delete_thread(id).await.is_ok();
    audit_admin(&s, &headers, "thread.delete", Some("thread"), Some(id), ok).await;
    let resp = Redirect::to("/").into_response();
    apply_sec(resp)
}
async fn post_delete(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    if require_admin_state(&s, &headers).await.is_none() {
        let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
        return apply_sec(resp);
    }
    let ok = s.store.delete_post(id).await.is_ok();
    audit_admin(&s, &headers, "post.delete", Some("post"), Some(id), ok).await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
async fn change_password(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let user = match require_admin_state(&s, &headers).await {
        Some(u) => u,
        None => {
            let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
            return apply_sec(resp);
        }
    };
    let old = form.get("old_password").cloned().unwrap_or_default();
    let newp = form.get("new_password").cloned().unwrap_or_default();
    if newp.len() < 6 || newp.len() > 72 {
        let resp = (StatusCode::BAD_REQUEST, "new password length").into_response();
        return apply_sec(resp);
    }
    let db_user = match s.store.get_user_by_id(user.id).await.unwrap_or(None) {
        Some(u) => u,
        None => {
            let resp = (StatusCode::INTERNAL_SERVER_ERROR, "user not found").into_response();
            return apply_sec(resp);
        }
    };
    let old_hash = db_user.password_hash.clone();
    let old_password = old.clone();
    let valid_old =
        tokio::task::spawn_blocking(move || crate::auth::verify_password(&old_hash, &old_password))
            .await
            .unwrap_or(false);
    if !valid_old {
        let resp = (StatusCode::FORBIDDEN, "old password wrong").into_response();
        return apply_sec(resp);
    }
    let hash_result = tokio::task::spawn_blocking(move || crate::auth::hash_password(&newp))
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("password hashing failed")));
    let hash = match hash_result {
        Ok(h) => h,
        Err(e) => {
            let resp = (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            return apply_sec(resp);
        }
    };
    let ok = s.store.update_password(user.id, &hash).await.is_ok();
    audit_admin(
        &s,
        &headers,
        "admin.change_password",
        Some("user"),
        Some(user.id),
        ok,
    )
    .await;
    let resp = Redirect::to("/admin").into_response();
    apply_sec(resp)
}
fn random_code(n: usize) -> String {
    const LETTERS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rb = vec![0u8; n];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut rb);
    let mut out = Vec::with_capacity(n);
    for v in rb {
        out.push(LETTERS[(v as usize) % LETTERS.len()]);
    }
    String::from_utf8(out).unwrap()
}
