use axum::{
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use hmac::Mac;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState {
    pub store: crate::store::Store,
    pub pow: crate::pow::Manager,
    pub password_gate: Arc<Semaphore>,
    pub pow_challenge_gate: Arc<Semaphore>,
    pub pow_challenge_times: Arc<std::sync::Mutex<VecDeque<Instant>>>,
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
fn inject_csrf_fields(mut html: String, headers: &HeaderMap) -> String {
    let field = csrf_field(headers);
    let mut search_from = 0;
    while let Some(start_rel) = html[search_from..].find("<form method=\"POST\"") {
        let start = search_from + start_rel;
        let Some(end_rel) = html[start..].find('>') else {
            break;
        };
        let end = start + end_rel + 1;
        html.insert_str(end, &field);
        search_from = end + field.len();
    }
    html
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

fn render_flat_posts(
    posts: &[crate::store::Post],
    thread_id: i64,
    page: i64,
    is_admin: bool,
    can_reply: bool,
    locked: bool,
    locale: &str,
) -> String {
    let ui = |en, zh, ru| crate::i18n::ui(locale, en, zh, ru);
    let names: HashMap<i64, String> = posts
        .iter()
        .map(|p| {
            (
                p.id,
                if p.is_anonymous {
                    ui("Anonymous", "匿名", "Аноним")
                } else {
                    html_escape(&p.author_name)
                },
            )
        })
        .collect();
    let mut out = String::new();
    for (idx, p) in posts.iter().enumerate() {
        let author = if p.is_anonymous {
            ui("Anonymous", "匿名", "Аноним")
        } else {
            html_escape(&p.author_name)
        };
        let reply_to = p.parent_post_id.map(|pid| format!(r##"<span class="reply-context"><span class="reply-label">{}</span> <a href="#p{}">@{}</a></span>"##, ui("Replying to", "回复", "Ответ на"), pid, names.get(&pid).cloned().unwrap_or_else(|| ui("deleted", "已删除", "удалён")))).unwrap_or_default();
        let reply = if can_reply && !locked {
            format!(
                r#"<a class="btn-link btn-sm" href="/t/{}?page={}&reply_to={}#reply-card">{}</a>"#,
                thread_id,
                page,
                p.id,
                ui("Reply", "回复", "Ответить")
            )
        } else {
            String::new()
        };
        let admin = if is_admin {
            format!(
                r#"<form method="POST" action="/admin/post/{}/delete" style="display:inline"><button class="btn-sm">{}</button></form>"#,
                p.id,
                ui("Delete", "删除", "Удалить")
            )
        } else {
            String::new()
        };
        let quote = p
            .parent_post_id
            .and_then(|pid| posts.iter().find(|parent| parent.id == pid))
            .map(|parent| {
                let text = parent.content_md.chars().take(120).collect::<String>();
                format!(
                    r#"<div class="reply-quote">@{}：{}</div>"#,
                    names.get(&parent.id).cloned().unwrap_or_else(|| ui(
                        "deleted",
                        "已删除",
                        "удалён"
                    )),
                    html_escape(&text)
                )
            })
            .unwrap_or_default();
        out.push_str(&format!(r#"<article class="social-post" id="p{id}">
<div class="post-head"><span class="floor">#{floor}</span><span class="author">{author}</span>{reply_to}<span class="post-time">{time}</span><span class="post-actions">{reply}{admin}</span></div>
{quote}<div class="post-body">{html}</div>
</article>"#, id=p.id, floor=idx+1, author=author, reply_to=reply_to, time=p.created_at.format("%m-%d %H:%M:%S"), reply=reply, admin=admin, quote=quote, html=p.content_html));
    }
    out
}
fn get_theme(headers: &HeaderMap) -> &'static str {
    if let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
            if kv.len() == 2 && kv[0].trim() == "theme" {
                let v = kv[1].trim();
                if v == "light" {
                    return "light";
                }
                if v == "dark" {
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
    if let Ok(row) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM posts")
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
    let pow_scripts = if need_pow {
        r#"<script src="/static/argon2-bundled.min.js"></script><script src="/static/pow.js"></script>"#
    } else {
        ""
    };
    let theme_attr = if theme == "light" {
        r#" data-theme="light""#
    } else {
        ""
    };
    let content = inject_csrf_fields(content.to_string(), headers);
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
    format!(
        r#"<!DOCTYPE html>
<html lang="{locale}"{theme_attr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title} - {site_name2}</title>
<script src="/static/theme.js"></script>
<link rel="stylesheet" href="/static/style.css">
<script src="/static/app.js"></script>
{pow_scripts}
</head>
<body>
{flash_html}
<div class="layout">
<aside class="side">
<div class="card brand-card"><a href="/" class="brand-name">{site_name}</a></div>
<div class="card search-card"><b>{search_label}</b><form method="GET" action="/search" role="search"><input name="q" placeholder="{search_label}" aria-label="{search_label}"><button>{search_label}</button></form></div>
<div class="card account-card"><b>{account_label}</b>{account_html}</div>
<div class="card board-card-side"><b>{boards_label}</b>
{boards_html}
<div class="muted" style="margin-top:6px;font-size:11px">{boards_len} {board_count} · <a href="/" style="font-size:11px">{all_boards}</a></div>
</div>
</aside>
<main>{content}</main>
<aside class="side">
<div class="card announcement-card"><b>{announcement_label}</b><div class="announcement-body">{announcement_body}</div></div>
<div class="card display-card"><b>{display_label}</b><button id="theme-toggle" type="button" aria-label="{display_label}">☼</button><noscript><style>#theme-toggle{{display:none}}</style><span class="noscript-themes"><a href="/theme?to=light" aria-label="{light_label}">☼ {light_label}</a><a href="/theme?to=dark" aria-label="{dark_label}">☾ {dark_label}</a></span></noscript></div>
<div class="card"><b>{stats_label}</b><div class="muted" style="margin-top:6px;font-size:11.5px;line-height:1.6">PoW {pow_minutes} min<br>{threads_label} {stats_threads} · {replies_label} {stats_posts}<br>{users_label} {stats_users}</div></div>
<div class="card"><b>{recent_label}</b><div style="margin-top:4px">{recent_html}</div></div>
</aside>
</div>
<footer><span>no log / no ip / csp default-src 'none' · veil-forum</span><span class="foot-right">{site_name} · {loopback_label} · <a href="https://github.com/Marry102123/veil-forum">Source</a></span>
</footer>
</body>
</html>"#,
        title = html_escape(title),
        site_name2 = html_escape(site_name),
        site_name = html_escape(site_name),
        pow_scripts = pow_scripts,
        account_html = account_html,
        flash_html = flash_html,
        boards_html = boards_html,
        boards_len = boards.len(),
        content = content,
        pow_minutes = html_escape(pow_minutes),
        stats_threads = stats_threads,
        stats_posts = stats_posts,
        stats_users = stats_users,
        recent_html = recent_html,
        announcement_body = announcement_body,
        theme_attr = theme_attr,
        locale = html_escape(locale),
        search_label = html_escape(&search_label),
        account_label = html_escape(&account_label),
        boards_label = html_escape(&boards_label),
    )
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
        r#"# pip install argon2-cffi
import argon2.low_level
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
    secret = f"{{salt}}{{challenge}}{{nonce}}".encode()
    out = argon2.low_level.hash_secret_raw(secret, b"secure-forum-argon2-salt", 1, 16384, 1, 32, argon2.low_level.Type.ID)
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
    let py_esc = html_escape(&py);
    format!(
        r#"<noscript>
<div class="pow-fallback">
<input type="hidden" name="pow_challenge" value="{ch}">
<input type="hidden" name="pow_salt" value="{salt}">
<input type="hidden" name="pow_difficulty" value="{diff}">
<input type="hidden" name="pow_expires_at" value="{exp}">
<input type="hidden" name="pow_hmac" value="{hmac}">
<input type="hidden" name="pow_scope" value="{scope}">
<label style="font-size:12px">{nonce_label}: <input name="pow_nonce" placeholder="{nonce_hint}" required style="width:55%"></label>
<div style="border:1px solid var(--border);padding:6px;margin-top:6px;font-size:11.5px;background:var(--input);border-radius:var(--radius-sm)">
<b>{manual_title}</b><br>
{manual_help}<br>
<pre style="white-space:pre-wrap">{py_esc}</pre>
<small class="muted">pip install argon2-cffi | {difficulty_label} {diff} | {expires_label} {exp} | curl /api/pow/challenge?scope={scope}</small>
</div>
</div>
</noscript>"#,
        ch = html_escape(&ch.challenge),
        salt = html_escape(&ch.salt),
        diff = ch.difficulty,
        exp = ch.expires_at,
        hmac = html_escape(&ch.hmac),
        scope = html_escape(&ch.scope),
        py_esc = py_esc,
        nonce_label = ui("PoW nonce (manual when JavaScript is disabled)", "PoW Nonce（Tor 无JS请手算）", "PoW nonce (вручную без JavaScript)"),
        nonce_hint = ui("Paste nonce", "粘贴 nonce", "Вставьте nonce"),
        manual_title = ui("JavaScript disabled: manual PoW", "JS 已禁用 - 手动 PoW", "JavaScript отключён: ручной PoW"),
        manual_help = ui("This form requires Argon2id 16 MB proof of work. Run this locally when JavaScript is unavailable.", "本表单需 Argon2id 16MB PoW，JS 自动完成；Tor 最高安全级请本地运行：", "Для формы требуется Argon2id proof of work на 16 МБ. Выполните локально без JavaScript."),
        difficulty_label = ui("difficulty", "难度", "сложность"),
        expires_label = ui("expires", "过期", "истекает")
    )
}

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(healthz))
        .route("/api/pow/challenge", get(pow_challenge))
        .route("/static/*path", get(handle_static))
        .route("/theme", get(theme_toggle))
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
        .with_state(state)
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

async fn pow_challenge(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let _permit = match s.pow_challenge_gate.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return apply_sec(
                (StatusCode::TOO_MANY_REQUESTS, "too many PoW challenges").into_response(),
            )
        }
    };
    {
        let now = Instant::now();
        let mut times = s.pow_challenge_times.lock().unwrap();
        while times
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(60))
        {
            times.pop_front();
        }
        if times.len() >= 60 {
            return apply_sec(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "PoW challenge rate limit exceeded",
                )
                    .into_response(),
            );
        }
        times.push_back(now);
    }
    let scope_str = q.get("scope").map(|x| x.as_str()).unwrap_or("post");
    let scope = crate::pow::Scope::from_str(scope_str);
    let ch = s.pow.generate(scope).await;
    let body = format!(
        r#"{{"challenge":"{}","salt":"{}","difficulty":{},"expires_at":{},"hmac":"{}","scope":"{}"}}"#,
        ch.challenge, ch.salt, ch.difficulty, ch.expires_at, ch.hmac, ch.scope
    );
    let mut resp = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response();
    for (k, v) in sec_headers().iter() {
        resp.headers_mut().insert(k.clone(), v.clone());
    }
    resp
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
    let to = q.get("to").map(|s| s.as_str()).unwrap_or("dark");
    let val = if to == "light" { "light" } else { "dark" };
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");
    let loc = if referer.starts_with("/") {
        referer.to_string()
    } else if referer.contains("://") {
        referer
            .parse::<axum::http::Uri>()
            .ok()
            .map(|u| u.path().to_string())
            .unwrap_or_else(|| "/".to_string())
    } else {
        "/".to_string()
    };
    let loc = if loc.is_empty() { "/".to_string() } else { loc };
    let mut resp = Redirect::to(&loc).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!("theme={}; Path=/; Max-Age=31536000; SameSite=Lax", val)
            .parse()
            .unwrap(),
    );
    apply_sec(resp)
}

async fn home(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = current_user(&s, &headers).await;
    let site = get_site_name(&s.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    // visible filter
    let visible: Vec<_> = boards
        .iter()
        .filter(|b| b.guest_readable || user.is_some())
        .cloned()
        .collect();
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let mut content = String::new();
    content.push_str(&format!("<h2>{}</h2>\n", ui("Boards", "版块", "Разделы")));
    if visible.is_empty() {
        content.push_str(&format!(
            r#"<div class="empty">{}</div>"#,
            ui(
                "No boards yet",
                "暂无版块 · 等待管理员创建",
                "Разделов пока нет"
            )
        ));
    } else {
        for b in &visible {
            let anon = if b.allow_anonymous {
                ui("Anonymous", "匿名", "Анонимно")
            } else {
                ui("Named", "实名", "С именем")
            };
            let guest = if b.guest_readable {
                ui("Public", "公开", "Публичный")
            } else {
                ui("Login required", "需登录", "Требуется вход")
            };
            content.push_str(&format!(r#"<div class="card board-card">
<div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap"><a href="/b/{}" class="board-link">{}</a> <span class="slug">/{}</span> <span class="muted" style="font-size:11px">· {} · {}</span></div>
<p class="desc">{}</p>
</div>"#, html_escape(&b.slug), html_escape(&b.name), html_escape(&b.slug), anon, guest, html_escape(&b.description)));
        }
    }
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
    let resp = Html(full).into_response();
    apply_sec(resp)
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
    let board_opt = s.store.get_board_by_slug(&slug).await.unwrap_or(None);
    let board = match board_opt {
        Some(b) => b,
        None => {
            let resp = (StatusCode::NOT_FOUND, "board not found").into_response();
            return apply_sec(resp);
        }
    };
    let user = current_user(&s, &headers).await;
    if !board.guest_readable && user.is_none() {
        let resp = Redirect::to("/login").into_response();
        return apply_sec(resp);
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
    let need_pow = user.is_some();
    let pow_fallback = if need_pow {
        let ch = s.pow.generate(crate::pow::Scope::Post).await;
        pow_fallback_html(&ch, &locale)
    } else {
        String::new()
    };
    // content
    let mut content = String::new();
    content.push_str(&format!(
        r#"<h2><a href="/">{}</a> / {} <span class="muted" style="font-weight:400">· {}</span></h2>
<p class="muted" style="margin:4px 0 8px">{} {}/{} · {} {}</p>"#,
        ui("Boards", "版块", "Разделы"),
        html_escape(&board.name),
        html_escape(&board.description),
        ui("Page", "页", "Страница"),
        page,
        total_pages,
        total,
        ui("posts", "帖", "сообщений")
    ));
    if let Some(u) = &user {
        let pow_title = crate::i18n::translate(&locale, "pow.post_title");
        let pow_description = crate::i18n::translate(&locale, "pow.description");
        let pow_computing = crate::i18n::translate(&locale, "pow.computing");
        let pow_done = crate::i18n::translate(&locale, "pow.done");
        let pow_failed = crate::i18n::translate(&locale, "pow.failed");
        let pow_submitting = crate::i18n::translate(&locale, "pow.submitting");
        content.push_str(&format!(r#"<div class="card">
<h3>{} <span class="muted" style="font-weight:400">· {}</span></h3>
<p class="muted pow-explanation">{}</p>
<div id="pow-status" data-computing="{}" data-done="{}" data-failed="{}" data-submitting="{}"></div>
<div id="pow-progress-container" style="display:none"><div id="pow-progress"></div></div>
<form method="POST" action="/b/{}/new" data-pow-scope="post">
<input name="title" placeholder="{}" required maxlength="120" style="width:100%;margin:5px 0">
<textarea name="content" placeholder="{}" required rows="4" style="width:100%"></textarea>
{}
 {}<button class="btn-primary">{}</button>
</form>
</div>"#, ui("New thread", "发新帖", "Новая тема"), pow_title, pow_description, pow_computing, pow_done, pow_failed, pow_submitting, html_escape(&board.slug), ui("Title, 5-120 characters", "标题 5-120字", "Заголовок, 5-120 символов"), ui("Markdown supported. Images are disabled.", "正文 Markdown 支持 基础+代码块+表格 · 禁图", "Поддерживается Markdown. Изображения отключены."), pow_fallback, if board.allow_anonymous { format!(r#"<label style="font-size:12px"><input type="checkbox" name="anonymous"> {}</label> "#, ui("Anonymous", "匿名", "Анонимно")) } else { String::new() }, ui("Post", "发帖", "Опубликовать")));
    } else {
        content.push_str(&format!(r#"<div class="card" style="padding:6px 8px;font-size:12.5px"><a href="/login">{}</a> <span class="muted">· {}</span></div>"#, ui("Log in to post", "登录后发帖", "Войдите, чтобы создать тему"), ui("Proof of work protects posting", "PoW 解放过滤", "Proof of work защищает публикации")));
    }
    content.push_str(r#"<div class="thread-list" role="list">"#);
    if threads.is_empty() {
        content.push_str(&format!(
            r#"<div class="empty" style="border:none">{}</div>"#,
            ui("No threads yet", "暂无主题 · 抢沙发", "Тем пока нет")
        ));
    } else {
        for t in &threads {
            let pinned = if t.is_pinned {
                &format!(
                    r#"<span class="badge-pinned">[{}]</span> "#,
                    ui("pinned", "置顶", "закреплено")
                )
            } else {
                ""
            };
            let locked = if t.is_locked {
                &format!(
                    r#"<span class="badge-locked">[{}]</span> "#,
                    ui("locked", "锁定", "закрыто")
                )
            } else {
                ""
            };
            let author = html_escape(&t.author_name);
            let last = t.last_reply_at.format("%m-%d %H:%M").to_string();
            let row_class = if t.is_pinned && t.is_locked {
                "thread-row pinned locked"
            } else if t.is_pinned {
                "thread-row pinned"
            } else if t.is_locked {
                "thread-row locked"
            } else {
                "thread-row"
            };
            content.push_str(&format!(r#"<div class="{}" role="listitem"><div style="min-width:0">{}<a href="/t/{}" class="title">{}</a></div><div class="author">{}</div><div class="replies"><b>{}</b></div><div class="last">{}</div></div>"#, row_class, format!("{}{}", pinned, locked), t.id, html_escape(&t.title), author, t.reply_count, last));
        }
    }
    content.push_str("</div>\n");
    content.push_str(&format!(
        r#"<div class="pagination"><span class="muted">{} / {}</span> {} {}</div>"#,
        page,
        total_pages,
        if page > 1 {
            format!(
                r#"<a href="/b/{}?page={}">‹ {}</a>"#,
                html_escape(&slug),
                page - 1,
                ui("Previous", "上一页", "Назад")
            )
        } else {
            "".to_string()
        },
        if page < total_pages {
            format!(
                r#"<a href="/b/{}?page={}">{} ›</a>"#,
                html_escape(&slug),
                page + 1,
                ui("Next", "下一页", "Далее")
            )
        } else {
            "".to_string()
        }
    ));
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
        need_pow,
        None,
        get_theme(&headers),
        &locale,
        &headers,
    );
    let resp = Html(full).into_response();
    apply_sec(resp)
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
    let th_opt = s.store.get_thread(id).await.unwrap_or(None);
    let th = match th_opt {
        Some(t) => t,
        None => {
            let resp = (StatusCode::NOT_FOUND, "thread not found").into_response();
            return apply_sec(resp);
        }
    };
    let board = s.store.get_board_by_id(th.board_id).await.unwrap_or(None);
    let user = current_user(&s, &headers).await;
    if let Some(b) = &board {
        if !b.guest_readable && user.is_none() {
            let resp = Redirect::to("/login").into_response();
            return apply_sec(resp);
        }
    }
    let page = q.page.unwrap_or(1).max(1);
    let page_size: i64 = 50;
    let (posts, total) = s
        .store
        .list_posts(th.id, page, page_size)
        .await
        .unwrap_or((Vec::new(), 0));
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
    let total_pages = ((total + page_size - 1) / page_size).max(1);
    let pow_min = s
        .store
        .get_config("pow_post_minutes")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "0.02".to_string());
    let is_admin = user.as_ref().map(|u| u.is_admin).unwrap_or(false);
    let (boards, _, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let pow_fallback = if user.is_some() && !th.is_locked {
        let ch = s.pow.generate(crate::pow::Scope::Post).await;
        pow_fallback_html(&ch, &locale)
    } else {
        String::new()
    };
    let mut content = String::new();
    content.push_str(&format!(r#"<div class="thread-hero"><div class="thread-kicker"><a href="/b/{board}">/{board}</a><span>{thread_label}</span></div><h1>{title}</h1>
<div class="thread-meta"><span>by <b>{author}</b></span><span>{time}</span>{pinned}{locked}</div></div>"#, board=html_escape(&th.board_slug), title=html_escape(&th.title), author=html_escape(&th.author_name), time=th.created_at.format("%Y-%m-%d %H:%M"),
        thread_label = ui("Thread", "主题", "Тема"),
        pinned = if th.is_pinned { format!(r#"<span class="badge-pinned">[{}]</span>"#, ui("pinned", "置顶", "закреплено")) } else { String::new() },
        locked = if th.is_locked { format!(r#"<span class="badge-locked">[{}]</span>"#, ui("locked", "锁定", "закрыто")) } else { String::new() }
    ));
    if posts.is_empty() {
        content.push_str(&format!(
            r#"<div class="empty">{}</div>"#,
            ui("No replies yet", "暂无回帖", "Ответов пока нет")
        ));
    } else {
        content.push_str(&render_flat_posts(
            &posts,
            th.id,
            page,
            is_admin,
            user.is_some(),
            th.is_locked,
            &locale,
        ));
    }
    content.push_str(&format!(
        r#"<div class="pagination"><span class="muted">{} / {}</span> {} {}</div>"#,
        page,
        total_pages,
        if page > 1 {
            format!(
                r#"<a href="/t/{}?page={}">‹ {}</a>"#,
                th.id,
                page - 1,
                ui("Previous", "上一页", "Назад")
            )
        } else {
            "".to_string()
        },
        if page < total_pages {
            format!(
                r#"<a href="/t/{}?page={}">{} ›</a>"#,
                th.id,
                page + 1,
                ui("Next", "下一页", "Далее")
            )
        } else {
            "".to_string()
        }
    ));
    if let Some(u) = &user {
        if th.is_locked {
            content.push_str(&format!(
                r#"<p class="notice-locked">{}</p>"#,
                ui(
                    "This thread is locked.",
                    "已锁定，禁止回帖",
                    "Эта тема закрыта."
                )
            ));
        } else {
            let reply_hint = reply_post.as_ref().map(|post| {
                let name = if post.is_anonymous { &ui("Anonymous", "匿名", "Аноним") } else { &post.author_name };
                let excerpt = post.content_md.chars().take(120).collect::<String>();
                format!(r#"<div class="reply-target"><b>{} @{}</b><span>“{}”</span><a href="/t/{}#reply-card">{}</a></div>"#, ui("Reply to", "回复", "Ответить"), html_escape(name), html_escape(&excerpt), th.id, ui("Cancel", "取消", "Отмена"))
            }).unwrap_or_default();
            let reply_to_value = reply_post
                .as_ref()
                .map(|post| post.id.to_string())
                .unwrap_or_default();
            let pow_title = crate::i18n::translate(&locale, "pow.reply_title");
            let pow_description = crate::i18n::translate(&locale, "pow.description");
            let pow_computing = crate::i18n::translate(&locale, "pow.computing");
            let pow_done = crate::i18n::translate(&locale, "pow.done");
            let pow_failed = crate::i18n::translate(&locale, "pow.failed");
            let pow_submitting = crate::i18n::translate(&locale, "pow.submitting");
            content.push_str(&format!(r#"<div class="card" id="reply-card">
<h3>{reply_label} <span class="muted" style="font-weight:400">· {pow_title}</span></h3>
<p class="muted pow-explanation">{pow_description}</p>
<div id="pow-status" data-computing="{pow_computing}" data-done="{pow_done}" data-failed="{pow_failed}" data-submitting="{pow_submitting}"></div>
<div id="pow-progress-container" style="display:none"><div id="pow-progress"></div></div>
<form method="POST" action="/t/{thread_id}/reply" data-pow-scope="post" id="reply-form">
{reply_hint}
<input type="hidden" name="parent_post_id" value="{reply_to}">
<textarea name="content" required rows="4" style="width:100%" placeholder="{markdown_hint}"></textarea>
{pow_fallback}
 {anonymous_field}<button class="btn-primary">{reply_label}</button>
</form>
</div>"#, reply_label = ui("Reply", "回帖", "Ответить"), pow_title = pow_title, pow_description = pow_description, pow_computing = pow_computing, pow_done = pow_done, pow_failed = pow_failed, pow_submitting = pow_submitting, thread_id = th.id, reply_hint = reply_hint, reply_to = reply_to_value, markdown_hint = ui("Markdown supported.", "Markdown 支持 基础+代码块+表格", "Поддерживается Markdown."), pow_fallback = pow_fallback, anonymous_field = if board.as_ref().map(|b| b.allow_anonymous).unwrap_or(false) { format!(r#"<label style="font-size:12px"><input type="checkbox" name="anonymous"> {}</label> "#, ui("Anonymous", "匿名", "Анонимно")) } else { String::new() }));
        }
    } else {
        content.push_str(&format!(r#"<div class="card" style="padding:6px 8px;font-size:12.5px"><a href="/login">{}</a></div>"#, ui("Log in to reply", "登录后回帖", "Войдите, чтобы ответить")));
    }
    if is_admin {
        content.push_str(&format!(r#"<div class="card">
<b>{}</b>
<form method="POST" action="/admin/thread/{}/pin" style="display:inline"><button>{}</button></form>
<form method="POST" action="/admin/thread/{}/lock" style="display:inline"><button>{}</button></form>
<form method="POST" action="/admin/thread/{}/delete" style="display:inline" onsubmit="return confirm('{}')"><button class="btn-danger">{}</button></form>
</div>"#, ui("Moderator actions", "管理员操作", "Действия модератора"), th.id, if th.is_pinned {ui("Unpin", "取消置顶", "Открепить")} else {ui("Pin", "置顶", "Закрепить")}, th.id, if th.is_locked {ui("Unlock", "解锁", "Открыть") } else {ui("Lock", "锁定", "Закрыть")}, th.id, ui("Delete this thread and all replies?", "删主题及全部回帖?", "Удалить тему и все ответы?"), ui("Delete thread", "删主题", "Удалить тему")));
    }
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
    let resp = Html(full).into_response();
    apply_sec(resp)
}

// ---------- Search ----------
async fn search(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let query = q.get("q").cloned().unwrap_or_default().trim().to_string();
    let page: i64 = q
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let user = current_user(&s, &headers).await;
    let site = get_site_name(&s.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let mut content = String::new();
    content.push_str(&format!(r#"<h2>{}</h2>
<form method="GET" action="/search" role="search" style="display:flex;gap:6px"><input name="q" value="{}" placeholder="{}" aria-label="{}" style="flex:1;min-width:0"><button aria-label="{}">{}</button></form>"#, ui("Search", "搜索", "Поиск"), html_escape(&query), ui("Search terms", "关键词", "Поисковый запрос"), ui("Search terms", "搜索关键词", "Поисковый запрос"), ui("Search", "搜索", "Поиск"), ui("Search", "搜", "Найти")));
    if !query.is_empty() {
        let page_size: i64 = 20;
        let (posts, _threads, total) = s
            .store
            .search_posts(&query, page, page_size)
            .await
            .unwrap_or((Vec::new(), Vec::new(), 0));
        let total_pages = ((total + page_size - 1) / page_size).max(1);
        content.push_str(&format!(
            r#"<p class="muted" style="margin:8px 0">{} {} · {} {}/{}</p>"#,
            total,
            ui("results", "条结果", "результатов"),
            ui("Page", "页", "Страница"),
            page,
            total_pages
        ));
        if posts.is_empty() {
            content.push_str(&format!(
                r#"<div class="empty">{}</div>"#,
                ui("No results", "无结果 · 换词再试", "Ничего не найдено")
            ));
        } else {
            for p in posts {
                let th = s.store.get_thread(p.thread_id).await.unwrap_or(None);
                let title = th.map(|t| t.title).unwrap_or_else(|| query.clone());
                let snip_raw = p.content_md.chars().take(200).collect::<String>();
                let snip_raw = if p.content_md.chars().count() > 200 {
                    format!("{}...", snip_raw)
                } else {
                    snip_raw
                };
                let snip = crate::markdown::render(&snip_raw);
                let author = if p.is_anonymous {
                    ui("Anonymous", "匿名", "Аноним")
                } else {
                    html_escape(&p.author_name)
                };
                let time = p.created_at.format("%m-%d").to_string();
                content.push_str(&format!(r#"<div class="card" style="padding:7px 9px">
<div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap"><a href="/t/{}#p{}" style="font-weight:650">{}</a> <span class="muted" style="font-size:11px">by {} {}</span></div>
<div class="post-body" style="padding:4px 0 2px;font-size:13px">{}</div>
</div>"#, p.thread_id, p.id, html_escape(&title), author, time, snip));
            }
        }
        content.push_str(&format!(
            r#"<div class="pagination"><span class="muted">{} / {}</span> {} {}</div>"#,
            page,
            total_pages,
            if page > 1 {
                format!(
                    r#"<a href="/search?q={}&page={}">‹ {}</a>"#,
                    html_escape(&query),
                    page - 1,
                    ui("Previous", "上一页", "Назад")
                )
            } else {
                "".to_string()
            },
            if page < total_pages {
                format!(
                    r#"<a href="/search?q={}&page={}">{} ›</a>"#,
                    html_escape(&query),
                    page + 1,
                    ui("Next", "下一页", "Далее")
                )
            } else {
                "".to_string()
            }
        ));
    }
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
    let resp = Html(full).into_response();
    apply_sec(resp)
}

// ---------- Register ----------
async fn register_get(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = current_user(&s, &headers).await;
    if user.is_some() {
        let resp = Redirect::to("/").into_response();
        return apply_sec(resp);
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
    let username = crate::i18n::translate(&locale, "auth.username");
    let password = crate::i18n::translate(&locale, "auth.password");
    let register = crate::i18n::translate(&locale, "nav.register");
    let login = crate::i18n::translate(&locale, "nav.login");
    let register_button = crate::i18n::format(
        crate::i18n::translate(&locale, "auth.register_pow"),
        "minutes",
        &pow_min,
    );
    let pow_title = crate::i18n::translate(&locale, "pow.register_title");
    let pow_description = crate::i18n::translate(&locale, "pow.description");
    let pow_computing = crate::i18n::translate(&locale, "pow.computing");
    let pow_done = crate::i18n::translate(&locale, "pow.done");
    let pow_failed = crate::i18n::translate(&locale, "pow.failed");
    let pow_submitting = crate::i18n::translate(&locale, "pow.submitting");
    let invite_field = if need_invite {
        &format!(
            r#"<input name="invite_code" placeholder="{}" required style="width:100%;margin:5px 0">"#,
            ui("Invite code", "邀请码", "Код приглашения")
        )
    } else {
        ""
    };
    let pow_ch = s.pow.generate(crate::pow::Scope::Register).await;
    let pow_fallback = pow_fallback_html(&pow_ch, &locale);
    let content = format!(
        r#"<h2>{register} <span class="muted" style="font-weight:400">· {pow_title}</span></h2>
<p class="muted pow-explanation">{pow_description}</p>
<div id="pow-status" data-computing="{pow_computing}" data-done="{pow_done}" data-failed="{pow_failed}" data-submitting="{pow_submitting}"></div>
<div id="pow-progress-container" style="display:none"><div id="pow-progress"></div></div>
<form method="POST" action="/register" data-pow-scope="register" style="max-width:420px">
<input name="username" placeholder="{username}" aria-label="{username}" required pattern="[a-zA-Z0-9_]{{3,20}}" style="width:100%;margin:5px 0">
<input name="password" type="password" placeholder="{password}" aria-label="{password}" required minlength="6" maxlength="72" style="width:100%;margin:5px 0">
{invite_field}
{pow_fallback}<button class="btn-primary" style="width:100%;margin-top:6px">{register_button}</button>
</form>
<p style="font-size:12.5px">{login}? <a href="/login">{login}</a></p>
<p class="muted" style="font-size:11.5px">{registration_mode}: {reg_mode} · {recovery_hint}</p>"#,
        invite_field = invite_field,
        pow_fallback = pow_fallback,
        pow_title = pow_title,
        pow_description = pow_description,
        pow_computing = pow_computing,
        pow_done = pow_done,
        pow_failed = pow_failed,
        pow_submitting = pow_submitting,
        registration_mode = ui("Registration mode", "注册模式", "Режим регистрации"),
        reg_mode = html_escape(&reg_mode),
        recovery_hint = ui(
            "No email recovery. Keep your password safe.",
            "无邮箱找回，丢密即丢号",
            "Восстановления по email нет. Сохраните пароль."
        )
    );
    let full = layout_html(
        &register,
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
    let resp = Html(full).into_response();
    apply_sec(resp)
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
    if reg_mode == "invite" {
        if invite.is_empty() {
            let resp = (StatusCode::BAD_REQUEST, "invite required").into_response();
            return apply_sec(resp);
        }
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
        Err(_) => {
            let resp = (StatusCode::CONFLICT, "username taken").into_response();
            return apply_sec(resp);
        }
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
fn is_admin_user(u: &Option<crate::store::User>) -> bool {
    u.as_ref().map(|x| x.is_admin).unwrap_or(false)
}

// ---------- Login ----------
async fn login_get(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = current_user(&s, &headers).await;
    if user.is_some() {
        let resp = Redirect::to("/").into_response();
        return apply_sec(resp);
    }
    let pow_min = s
        .store
        .get_config("pow_login_minutes")
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "0.02".to_string());
    let site = get_site_name(&s.store).await;
    let (boards, _, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    let locale = site_locale(&s.store).await;
    let username = crate::i18n::translate(&locale, "auth.username");
    let password = crate::i18n::translate(&locale, "auth.password");
    let register = crate::i18n::translate(&locale, "nav.register");
    let login = crate::i18n::translate(&locale, "nav.login");
    let login_button = crate::i18n::format(
        crate::i18n::translate(&locale, "auth.login_pow"),
        "minutes",
        &pow_min,
    );
    let pow_title = crate::i18n::translate(&locale, "pow.login_title");
    let pow_description = crate::i18n::translate(&locale, "pow.description");
    let pow_computing = crate::i18n::translate(&locale, "pow.computing");
    let pow_done = crate::i18n::translate(&locale, "pow.done");
    let pow_failed = crate::i18n::translate(&locale, "pow.failed");
    let pow_submitting = crate::i18n::translate(&locale, "pow.submitting");
    let pow_ch = s.pow.generate(crate::pow::Scope::Login).await;
    let pow_fallback = pow_fallback_html(&pow_ch, &locale);
    let content = format!(
        r#"<h2>{login_button} <span class="muted" style="font-weight:400">· {pow_title}</span></h2>
<p class="muted pow-explanation">{pow_description}</p>
<div id="pow-status" data-computing="{pow_computing}" data-done="{pow_done}" data-failed="{pow_failed}" data-submitting="{pow_submitting}"></div>
<div id="pow-progress-container" style="display:none"><div id="pow-progress"></div></div>
<form method="POST" action="/login" data-pow-scope="login" style="max-width:420px">
<input name="username" placeholder="{username}" aria-label="{username}" required style="width:100%;margin:5px 0">
<input name="password" type="password" placeholder="{password}" aria-label="{password}" required style="width:100%;margin:5px 0">
{pow_fallback}<button class="btn-primary" style="width:100%;margin-top:6px">{login_button}</button>
</form>
<p style="font-size:12.5px"><a href="/register">{register}</a> <span class="muted">· {email_hint}</span></p>"#,
        pow_fallback = pow_fallback,
        pow_title = pow_title,
        pow_description = pow_description,
        pow_computing = pow_computing,
        pow_done = pow_done,
        pow_failed = pow_failed,
        pow_submitting = pow_submitting,
        email_hint = crate::i18n::ui(
            &locale,
            "no email required",
            "无需邮箱",
            "email не требуется"
        )
    );
    let full = layout_html(
        &login,
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
    let resp = Html(full).into_response();
    apply_sec(resp)
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
            let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
            return apply_sec(resp);
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
        let resp = (StatusCode::FORBIDDEN, format!("PoW failed: {}", e)).into_response();
        return apply_sec(resp);
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
        .and_then(|pid| {
            // 同步校验：先简单检查 pid >0，实际线程一致性在下方异步校验时再做
            if pid > 0 {
                Some(pid)
            } else {
                None
            }
        });
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
        None => {
            let resp = (StatusCode::FORBIDDEN, "forbidden").into_response();
            return apply_sec(resp);
        }
    };
    let boards = s.store.list_boards().await.unwrap_or_default();
    let users = s.store.list_users(100).await.unwrap_or_default();
    let configs = s.store.get_all_configs().await.unwrap_or_default();
    let invites = s.store.list_invites().await.unwrap_or_default();
    let site = get_site_name(&s.store).await;
    let locale = site_locale(&s.store).await;
    let ui = |en, zh, ru| crate::i18n::ui(&locale, en, zh, ru);
    let (sboards, pow_min, st, sp, su, recent, announcement) = sidebar_data(&s.store).await;
    // build admin content similar to admin.html
    let mut content = String::new();
    content.push_str(&format!(
        "<h2>{}</h2>\n<div class=\"admin-grid\">\n<div class=\"card\">\n<h3>{}</h3>\n",
        ui("Administration", "管理后台", "Администрирование"),
        ui("Site settings", "站点配置", "Настройки сайта")
    ));
    content.push_str(&format!(r#"<form method="POST" action="/admin/config/site">
<label>{site_name_label} <input name="site_name" value="{}" style="width:100%"></label>
<button>{save}</button>
</form>
<hr>
<form method="POST" action="/admin/config/locale">
<label>{locale_label} <select name="default_locale">
<option value="en" {}>English</option>
<option value="zh" {}>中文</option>
<option value="ru" {}>Русский</option>
</select></label><button>{save}</button>
</form>
<hr>
<form method="POST" action="/admin/config/announcement">
<label>{announcement_label} <textarea name="announcement" rows="4" maxlength="1000" style="width:100%" placeholder="{announcement_hint}">{}</textarea></label>
<small style="color:#888">{announcement_help}</small><br><button>{save_announcement}</button>
</form>
<hr>
<form method="POST" action="/admin/config/pow">
<label>{register_pow} <input name="pow_register_minutes" value="{}" style="width:100%"></label>
<label>{login_pow} <input name="pow_login_minutes" value="{}" style="width:100%"></label>
<label>{post_pow} <input name="pow_post_minutes" value="{}" style="width:100%"></label>
<small style="color:#888">{pow_help}</small><br>
<button>{save_pow}</button>
</form>
<hr>
<form method="POST" action="/admin/config/registration">
<label>{registration_mode}
<select name="registration_mode">
<option value="open" {}>{open}</option>
<option value="invite" {}>{invite}</option>
<option value="closed" {}>{closed}</option>
</select></label><button>{save}</button>
</form>
    </div>"#, html_escape(configs.get("site_name").map(|x| x.as_str()).unwrap_or("secure-forum")),
        if configs.get("default_locale").map(|x| x=="en").unwrap_or(true) {"selected"} else {""},
        if configs.get("default_locale").map(|x| x=="zh").unwrap_or(false) {"selected"} else {""},
        if configs.get("default_locale").map(|x| x=="ru").unwrap_or(false) {"selected"} else {""},
        html_escape(configs.get("announcement").map(|x| x.as_str()).unwrap_or("")),
        html_escape(configs.get("pow_register_minutes").map(|x| x.as_str()).unwrap_or("0.02")),
        html_escape(configs.get("pow_login_minutes").map(|x| x.as_str()).unwrap_or("0.02")),
        html_escape(configs.get("pow_post_minutes").map(|x| x.as_str()).unwrap_or("0.02")),
        if configs.get("registration_mode").map(|x| x=="open").unwrap_or(false) {"selected"} else {""},
        if configs.get("registration_mode").map(|x| x=="invite").unwrap_or(false) {"selected"} else {""},
        if configs.get("registration_mode").map(|x| x=="closed").unwrap_or(false) {"selected"} else {""},
        site_name_label = ui("Site name", "站点名", "Название сайта"), save = crate::i18n::translate(&locale, "admin.save"),
        locale_label = crate::i18n::translate(&locale, "admin.default_locale"),
        announcement_label = ui("Announcement", "公告", "Объявление"), announcement_hint = ui("Leave blank to hide", "留空则不显示", "Оставьте пустым, чтобы скрыть"), announcement_help = ui("Shown on every page.", "显示在所有页面右侧。", "Показывается на каждой странице."), save_announcement = ui("Save announcement", "保存公告", "Сохранить объявление"),
        register_pow = ui("Registration PoW minutes", "注册 PoW 分钟", "Минуты PoW регистрации"), login_pow = ui("Login PoW minutes", "登录 PoW 分钟", "Минуты PoW входа"), post_pow = ui("Posting PoW minutes", "发帖 PoW 分钟", "Минуты PoW публикации"), pow_help = ui("Argon2id minutes, from 0.005 to 10.", "Argon2id 小数分钟 0.005~10", "Минуты Argon2id, от 0.005 до 10."), save_pow = ui("Save PoW", "保存PoW", "Сохранить PoW"), registration_mode = ui("Registration mode", "注册模式", "Режим регистрации"), open = ui("Open", "开放", "Открытая"), invite = ui("Invite only", "需邀请码", "Только по приглашению"), closed = ui("Closed", "关闭", "Закрыта"),
    ));
    content.push_str(&format!(
        r#"<div class="card">
<h3>{} ({})</h3>
<form method="POST" action="/admin/change-password">
<input name="old_password" type="password" placeholder="{}" style="width:100%">
<input name="new_password" type="password" placeholder="{}" style="width:100%">
<button>{}</button>
</form>
<hr>
<h3>{}</h3>
<form method="POST" action="/admin/invite/create"><button>{}</button></form>
<ul>"#,
        ui("Change password", "改密", "Сменить пароль"),
        html_escape(&user.username),
        ui("Current password", "旧密码", "Текущий пароль"),
        ui("New password", "新密码", "Новый пароль"),
        ui("Change password", "改密", "Сменить пароль"),
        ui("Invite codes", "生成邀请码", "Коды приглашений"),
        ui("Create code", "生成1枚", "Создать код")
    ));
    if invites.is_empty() {
        content.push_str(&format!(
            "<li>{}</li>",
            ui("No invite codes", "无邀请码", "Нет кодов приглашения")
        ));
    } else {
        for inv in &invites {
            if inv.used_by.is_some() {
                content.push_str(&format!(
                    r#"<li><code>{}</code> {} {}</li>"#,
                    html_escape(&inv.code),
                    ui("used by", "已用 by", "использован"),
                    inv.used_by.unwrap()
                ));
            } else {
                content.push_str(&format!(r#"<li><code>{}</code> {}<form method="POST" action="/admin/invite/{}/delete" style="display:inline"><button>{}</button></form></li>"#, html_escape(&inv.code), ui("unused", "未用", "не использован"), html_escape(&inv.code), ui("Revoke", "作废", "Отозвать")));
            }
        }
    }
    content.push_str("</ul></div></div>\n");
    // boards
    content.push_str(&format!(r#"<div class="card">
<h3>{}</h3>
<form method="POST" action="/admin/board/create" style="border:1px solid #333;padding:6px">
<input name="slug" placeholder="slug a-z 0-9 _ -" required pattern="[a-z0-9_-]{{2,20}}"> <input name="name" placeholder="{}" required> <input name="description" placeholder="{}" style="width:40%">
<label><input type="checkbox" name="allow_anonymous" checked>{}</label>
<label><input type="checkbox" name="guest_readable" checked>{}</label>
<button>{}</button>
</form>
<table>
<tr><th>slug</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>"#, ui("Board management", "版块管理", "Управление разделами"), ui("Name", "名称", "Название"), ui("Description", "描述", "Описание"), ui("Allow anonymous", "允许匿名", "Разрешить анонимно"), ui("Guest readable", "游客可读", "Доступно гостям"), ui("Create board", "创建版块", "Создать раздел"), ui("Name", "名称", "Название"), ui("Anonymous", "匿名", "Анонимно"), ui("Guest readable", "游客可读", "Доступно гостям"), ui("Actions", "操作", "Действия")));
    for b in &boards {
        content.push_str(&format!(r#"<tr>
<td>{}</td><td>{}</td><td>{}</td><td>{}</td>
<td>
<form method="POST" action="/admin/board/{}/update" style="display:inline">
<input type="hidden" name="name" value="{}"><input type="hidden" name="description" value="{}">
<label><input type="checkbox" name="allow_anonymous" {}>{}</label>
<label><input type="checkbox" name="guest_readable" {}>{}</label>
<button>{}</button>
</form>
<form method="POST" action="/admin/board/{}/delete" style="display:inline" onsubmit="return confirm('{}')"><button>{}</button></form>
</td></tr>"#, html_escape(&b.slug), html_escape(&b.name), if b.allow_anonymous {ui("Yes", "是", "Да")} else {ui("No", "否", "Нет")}, if b.guest_readable {ui("Yes", "是", "Да")} else {ui("No", "否", "Нет")}, b.id, html_escape(&b.name), html_escape(&b.description), if b.allow_anonymous {"checked"} else {""}, ui("Anonymous", "匿名", "Анонимно"), if b.guest_readable {"checked"} else {""}, ui("Readable", "可读", "Чтение"), ui("Update", "更新", "Обновить"), b.id, ui("Delete this board and its threads?", "删版及帖?", "Удалить раздел и темы?"), ui("Delete", "删", "Удалить")));
    }
    content.push_str("</table></div>\n");
    content.push_str(&format!(
        r#"<div class="card">
<h3>{}</h3>
<table>
<tr><th>ID</th><th>{}</th><th>admin</th><th>{}</th><th>{}</th></tr>"#,
        ui(
            "User management (latest 100)",
            "用户管理 (近100)",
            "Управление пользователями (100 последних)"
        ),
        ui("User", "用户", "Пользователь"),
        ui("Banned", "banned", "Заблокирован"),
        ui("Actions", "操作", "Действия")
    ));
    for u in &users {
        content.push_str(&format!(r#"<tr>
<td>{}</td><td>{}</td><td>{}</td><td>{}</td>
<td>
{} </td></tr>"#, u.id, html_escape(&u.username), u.is_admin, u.is_banned,
            if u.is_banned { format!(r#"<form method="POST" action="/admin/user/{}/unban" style="display:inline"><button>{}</button></form>"#, u.id, ui("Unban", "解封", "Разблокировать")) } else { format!(r#"<form method="POST" action="/admin/user/{}/ban" style="display:inline"><button>{}</button></form>"#, u.id, ui("Ban", "封禁", "Заблокировать")) }
        ));
    }
    content.push_str("</table></div>\n");
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
    let resp = Html(full).into_response();
    apply_sec(resp)
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
