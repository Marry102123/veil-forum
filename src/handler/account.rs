//! Account page (profile, password, TOTP second factor, sessions) and the
//! second login step.
//!
//! Flow decisions:
//!   * The password step never creates a session when the account has TOTP
//!     active; it creates a short-lived `pending_logins` row instead, so a
//!     stolen password alone is not enough.
//!   * Enrolment is confirmed with a code before it becomes active, so a
//!     mistyped or abandoned enrolment cannot lock an account out.
//!   * Recovery codes are shown exactly once and stored as hashes.
//!   * Every security-relevant action is written to the audit log without any
//!     secret material.

use super::*;

/// Site setting: offer the TOTP option at all.
const TOTP_FEATURE_KEY: &str = "totp_enabled";
/// Site setting: `none`, `staff`, or `all`.
const TOTP_POLICY_KEY: &str = "totp_required";
/// Window in which a single account may spend second-factor attempts.
const TOTP_ATTEMPT_WINDOW_MINUTES: i64 = 15;
/// Attempts allowed per account inside that window, across pending logins.
const TOTP_ACCOUNT_ATTEMPT_LIMIT: i64 = 15;

#[derive(Deserialize)]
pub struct AccountQuery {
    pub ok: Option<String>,
    pub err: Option<String>,
}

#[derive(Deserialize)]
pub struct PendingQuery {
    pub p: Option<String>,
}

/// Is the TOTP feature offered by this deployment?
///
/// The `!= Some("0")` comparison is deliberate in the fail-closed direction: an
/// unreadable key reads as "offered", not "off". The login path uses this to
/// decide whether a password step may complete without a second factor, so
/// treating a storage error as "off" would let a database outage silently turn
/// a two-factor login into a password-only one. `middleware::totp_policy_gate`
/// answers 503 for the same key, so the two agree during an outage.
pub async fn feature_enabled(store: &crate::store::Store) -> bool {
    store.get_config_opt(TOTP_FEATURE_KEY).await.as_deref() != Some("0")
}

/// Current enforcement policy.
pub async fn policy(store: &crate::store::Store) -> String {
    store
        .get_config_opt(TOTP_POLICY_KEY)
        .await
        .unwrap_or_else(|| "none".to_string())
}

/// Version of the policy as a stable identifier for the settings form.
pub fn policy_value(value: &str) -> &'static str {
    match value {
        "staff" => "staff",
        "all" => "all",
        _ => "none",
    }
}

/// Notice codes are mapped to localised text, so redirects stay free of
/// user-controlled content.
fn notice_text(locale: &str, code: &str, error: bool) -> Option<String> {
    let ui = |en: &str, zh: &str, ru: &str| crate::i18n::ui(locale, en, zh, ru);
    Some(match (code, error) {
        ("password_changed", false) => ui(
            "Password updated. Other sessions were signed out.",
            "密码已更新，其他会话已退出。",
            "Пароль обновлён. Другие сеансы завершены.",
        ),
        ("totp_enabled", false) => ui(
            "Two-step verification is now active.",
            "动态口令已启用。",
            "Двухшаговая проверка включена.",
        ),
        ("totp_disabled", false) => ui(
            "Two-step verification was disabled.",
            "动态口令已停用。",
            "Двухшаговая проверка отключена.",
        ),
        ("totp_cancelled", false) => ui(
            "Enrolment cancelled.",
            "已取消绑定。",
            "Регистрация отменена.",
        ),
        ("recovery_reissued", false) => ui(
            "New recovery codes were issued and the old ones stopped working.",
            "新的恢复码已生成，旧的已失效。",
            "Новые коды восстановления выпущены, старые больше не работают.",
        ),
        ("sessions_revoked", false) => ui(
            "Other sessions were signed out.",
            "其他会话已退出。",
            "Другие сеансы завершены.",
        ),
        ("bad_password", true) => ui(
            "That password is not correct.",
            "密码不正确。",
            "Неверный пароль.",
        ),
        ("bad_code", true) => ui("That code is not valid.", "验证码不正确。", "Неверный код."),
        ("replayed_code", true) => ui(
            "That code was already used. Wait for the next one.",
            "该验证码已被使用，请等待下一个。",
            "Этот код уже использован. Дождитесь следующего.",
        ),
        ("weak_password", true) => ui(
            "Choose a strong password between 15 and 128 characters.",
            "请选择 15 到 128 个字符的强密码。",
            "Выберите надёжный пароль длиной от 15 до 128 символов.",
        ),
        ("no_change", true) => ui(
            "The new password must differ from the old one.",
            "新密码不能与旧密码相同。",
            "Новый пароль должен отличаться от старого.",
        ),
        ("feature_off", true) => ui(
            "Two-step verification is disabled on this site.",
            "本站已关闭动态口令功能。",
            "На этом сайте двухшаговая проверка отключена.",
        ),
        _ => return None,
    })
}

fn notice_html(locale: &str, query: &AccountQuery) -> Option<String> {
    if let Some(code) = query.ok.as_deref() {
        if let Some(text) = notice_text(locale, code, false) {
            return Some(format!(
                "<div class=\"flash flash-ok\" role=\"status\">{}</div>",
                html_escape(&text)
            ));
        }
    }
    if let Some(code) = query.err.as_deref() {
        if let Some(text) = notice_text(locale, code, true) {
            return Some(format!(
                "<div class=\"flash flash-error\" role=\"alert\">{}</div>",
                html_escape(&text)
            ));
        }
    }
    None
}

/// Create the session and set the cookie. Shared by both login paths.
pub(super) async fn complete_login(
    state: &AppState,
    user: &crate::store::User,
    headers: &HeaderMap,
) -> Response {
    let _ = state.store.delete_sessions_by_user(user.id).await;
    let sid = match state.store.create_session(user.id).await {
        Ok(sid) => sid,
        Err(_) => {
            return apply_sec(
                (StatusCode::INTERNAL_SERVER_ERROR, "session creation failed").into_response(),
            );
        }
    };
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&sid, 12 * 3600, state.secure_session_cookie)
            .parse()
            .unwrap(),
    );
    let _ = state
        .store
        .audit(
            Some(user.id),
            "login.succeeded",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    let _ = headers;
    apply_sec(resp)
}

/// Verify the submitting session's own password from a form field.
///
/// Actions that replace an account credential (enrolling a second factor,
/// disabling one, reissuing recovery codes) cost the current password even
/// though the caller is already signed in, so a stolen session alone is not
/// enough to change how the account authenticates.
async fn confirm_password(
    state: &AppState,
    user: &crate::store::User,
    form: &HashMap<String, String>,
) -> bool {
    let password = form.get("password").cloned().unwrap_or_default();
    let Ok(Some(db_user)) = state.store.get_user_by_id(user.id).await else {
        return false;
    };
    let hash = db_user.password_hash.clone();
    let valid = crate::auth::verify_password_blocking(hash, password).await;
    valid
}

/// Drop every session of this account except the one making the request.
///
/// Called when the second factor is switched on or off: sessions created before
/// that change must not survive it.
async fn revoke_other_sessions(state: &AppState, user: &crate::store::User, headers: &HeaderMap) {
    let current = session_id(headers).map(|raw| crate::auth::digest_token(&raw));
    for session in state
        .store
        .list_sessions_by_user(user.id)
        .await
        .unwrap_or_default()
    {
        if current.as_deref() != Some(session.id.as_str()) {
            let _ = state.store.delete_session_digest(&session.id).await;
        }
    }
}

async fn render_account(
    state: &AppState,
    headers: &HeaderMap,
    user: &crate::store::User,
    query: &AccountQuery,
    recovery_codes: Option<&[String]>,
) -> Response {
    let locale = site_locale(&state.store).await;
    let ui = |en: &str, zh: &str, ru: &str| crate::i18n::ui(&locale, en, zh, ru);
    let site = get_site_name(&state.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement, friend_links, sidebar_settings) =
        sidebar_data(&state.store).await;

    let totp = state.store.totp_state(user.id).await.unwrap_or_default();
    let feature = feature_enabled(&state.store).await;
    let sessions = state
        .store
        .list_sessions_by_user(user.id)
        .await
        .unwrap_or_default();
    let current_sid = session_id(headers).map(|raw| crate::auth::digest_token(&raw));
    let roles = state
        .store
        .list_user_roles(user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|role| role.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut context = Context::new();
    context.insert("csrf_field", &csrf_field(headers));
    context.insert("username", &user.username);
    context.insert(
        "created_at",
        &user.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
    );
    context.insert("roles", if roles.is_empty() { "member" } else { &roles });
    context.insert("totp_feature", &feature);
    context.insert("totp_active", &totp.is_active());
    context.insert("totp_pending", &totp.pending_secret.is_some());
    context.insert("recovery_remaining", &totp.unused_recovery_codes);
    context.insert(
        "totp_activated_at",
        &totp
            .activated_at
            .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_default(),
    );
    context.insert("session_count", &(sessions.len() as i64));
    context.insert(
        "sessions",
        &sessions
            .iter()
            .map(|session| {
                serde_json::json!({
                    "current": current_sid.as_deref() == Some(session.id.as_str()),
                    "created": session.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                    "last_seen": session
                        .last_seen_at
                        .map(|seen| seen.format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_else(|| "—".to_string()),
                })
            })
            .collect::<Vec<_>>(),
    );
    if let Some(codes) = recovery_codes {
        context.insert(
            "recovery_codes",
            &codes
                .iter()
                .map(|code| html_escape(code))
                .collect::<Vec<_>>(),
        );
    }
    if let Some(pending) = totp.pending_secret.as_deref() {
        // Enrolment material: the QR code is inline SVG, so the page needs no
        // script and makes no external request.
        let url = crate::totp::otpauth_url(pending, &user.username, &site)
            .unwrap_or_else(|_| String::new());
        context.insert("pending_secret", pending);
        context.insert("otpauth_url", &url);
        context.insert(
            "qr_svg",
            &crate::totp::qr_svg(&url).unwrap_or_else(|_| String::new()),
        );
    }
    context.insert(
        "notice_html",
        &notice_html(&locale, query).unwrap_or_default(),
    );

    for (key, value) in [
        (
            "account_title",
            ui("Your account", "你的账号", "Ваш аккаунт"),
        ),
        (
            "account_intro",
            ui(
                "Everything here applies to this account only.",
                "这里的所有设置只影响当前账号。",
                "Все настройки здесь относятся только к этому аккаунту.",
            ),
        ),
        ("profile_title", ui("Profile", "资料", "Профиль")),
        (
            "username_label",
            ui("Username", "用户名", "Имя пользователя"),
        ),
        (
            "created_label",
            ui("Registered", "注册时间", "Зарегистрирован"),
        ),
        ("roles_label", ui("Roles", "角色", "Роли")),
        (
            "password_title",
            ui("Change password", "修改密码", "Смена пароля"),
        ),
        (
            "old_password_label",
            ui("Current password", "当前密码", "Текущий пароль"),
        ),
        (
            "new_password_label",
            ui("New password", "新密码", "Новый пароль"),
        ),
        (
            "repeat_password_label",
            ui(
                "Repeat new password",
                "重复新密码",
                "Повторите новый пароль",
            ),
        ),
        ("save_label", ui("Save", "保存", "Сохранить")),
        (
            "totp_title",
            ui(
                "Two-step verification (TOTP)",
                "二步验证（动态口令）",
                "Двухшаговая проверка (TOTP)",
            ),
        ),
        (
            "totp_intro",
            ui(
                "A 6 digit code from an authenticator app, on top of your password.",
                "在密码之外，再要求一个来自验证器 App 的 6 位动态码。",
                "Дополнительно к паролю требуется 6-значный код из приложения.",
            ),
        ),
        (
            "totp_active_note",
            ui(
                "Two-step verification is active for this account.",
                "此账号已启用二步验证。",
                "Для этого аккаунта включена двухшаговая проверка.",
            ),
        ),
        (
            "totp_activated_label",
            ui("Active since", "启用时间", "Активно с"),
        ),
        (
            "totp_disabled_note",
            ui(
                "Two-step verification is not enabled yet.",
                "尚未启用二步验证。",
                "Двухшаговая проверка пока не включена.",
            ),
        ),
        ("totp_enable_label", ui("Enable", "启用", "Включить")),
        ("totp_disable_label", ui("Disable", "停用", "Отключить")),
        (
            "totp_cancel_label",
            ui("Cancel enrolment", "取消绑定", "Отменить регистрацию"),
        ),
        (
            "totp_scan_intro",
            ui(
                "Scan this code with an authenticator app, or type the secret by hand.",
                "用验证器 App 扫描下面的二维码，或手动输入密钥。",
                "Отсканируйте код приложением или введите секрет вручную.",
            ),
        ),
        ("totp_manual_label", ui("Secret", "密钥", "Секрет")),
        (
            "totp_confirm_intro",
            ui(
                "Enter the code the app shows to finish enrolment.",
                "输入 App 当前显示的验证码完成绑定。",
                "Введите код из приложения, чтобы завершить регистрацию.",
            ),
        ),
        (
            "totp_code_label",
            ui(
                "Code or recovery code",
                "动态码或恢复码",
                "Код или код восстановления",
            ),
        ),
        (
            "totp_confirm_label",
            ui(
                "Confirm and activate",
                "确认并启用",
                "Подтвердить и включить",
            ),
        ),
        (
            "totp_disable_intro",
            ui(
                "Disabling needs your password and a current code.",
                "停用需要输入密码和当前验证码。",
                "Для отключения нужны пароль и текущий код.",
            ),
        ),
        (
            "recovery_title",
            ui("Recovery codes", "恢复码", "Коды восстановления"),
        ),
        (
            "recovery_remaining_label",
            ui("Unused codes", "未使用恢复码", "Неиспользованных кодов"),
        ),
        (
            "recovery_intro",
            ui(
                "Save these now. Each one works once and they are shown only this time.",
                "请立刻保存，每个只能用一次，且只显示这一次。",
                "Сохраните их сейчас. Каждый работает один раз и показывается только сейчас.",
            ),
        ),
        (
            "recovery_regenerate_label",
            ui(
                "Issue new recovery codes",
                "重新生成恢复码",
                "Выпустить новые коды",
            ),
        ),
        (
            "recovery_regenerate_intro",
            ui(
                "A new set replaces the old one immediately.",
                "新的恢复码会立刻替代旧的。",
                "Новый набор сразу заменяет старый.",
            ),
        ),
        (
            "sessions_title",
            ui("Active sessions", "登录会话", "Активные сеансы"),
        ),
        (
            "sessions_intro",
            ui(
                "One active session per account. Signing in again ends the previous one.",
                "每个账号只保留一个有效会话，重新登录会结束上一个。",
                "Один активный сеанс на аккаунт. Новый вход завершает предыдущий.",
            ),
        ),
        (
            "session_created_label",
            ui("Signed in", "登录时间", "Вход выполнен"),
        ),
        (
            "session_seen_label",
            ui("Last seen", "最近活动", "Последняя активность"),
        ),
        (
            "session_current_label",
            ui("this session", "当前会话", "этот сеанс"),
        ),
        (
            "sessions_revoke_label",
            ui(
                "Sign out other sessions",
                "退出其他会话",
                "Завершить другие сеансы",
            ),
        ),
        (
            "logout_label",
            crate::i18n::translate(&locale, "nav.logout"),
        ),
    ] {
        context.insert(key, &value);
    }

    let content = crate::templates::render_page("account", &context)
        .expect("embedded account template must render");
    let full = layout_html(
        &crate::i18n::translate(&locale, "account.title"),
        &site,
        Some(user),
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &friend_links,
        &sidebar_settings,
        &get_footer_text(&state.store, &locale).await,
        &content,
        false,
        None,
        get_theme(headers),
        &get_palette(&state.store).await,
        &locale,
        headers,
    );
    apply_sec(Html(full).into_response())
}

async fn render_login_totp(
    state: &AppState,
    headers: &HeaderMap,
    pending_id: &str,
    error: Option<&str>,
) -> Response {
    let locale = site_locale(&state.store).await;
    let ui = |en: &str, zh: &str, ru: &str| crate::i18n::ui(&locale, en, zh, ru);
    let site = get_site_name(&state.store).await;
    let (boards, pow_min, st, sp, su, recent, announcement, friend_links, sidebar_settings) =
        sidebar_data(&state.store).await;

    let mut context = Context::new();
    context.insert("csrf_field", &csrf_field(headers));
    context.insert("pending_id", pending_id);
    context.insert(
        "error_html",
        &error
            .map(|text| {
                format!(
                    "<div class=\"flash flash-error\" role=\"alert\">{}</div>",
                    html_escape(text)
                )
            })
            .unwrap_or_default(),
    );
    for (key, value) in [
        (
            "totp_login_title",
            ui("Second step", "第二步验证", "Второй шаг"),
        ),
        (
            "totp_login_intro",
            ui(
                "Enter the current code from your authenticator app. A recovery code works too.",
                "请输入验证器 App 当前显示的验证码，恢复码也可以。",
                "Введите текущий код из приложения. Код восстановления тоже подойдёт.",
            ),
        ),
        (
            "totp_code_label",
            ui(
                "Code or recovery code",
                "动态码或恢复码",
                "Код или код восстановления",
            ),
        ),
        ("totp_submit_label", ui("Verify", "验证", "Проверить")),
        (
            "totp_back_label",
            ui("Start over", "返回重新登录", "Начать заново"),
        ),
        ("login_label", crate::i18n::translate(&locale, "nav.login")),
    ] {
        context.insert(key, &value);
    }
    let content = crate::templates::render_page("login_totp", &context)
        .expect("embedded second step template must render");
    let full = layout_html(
        &ui("Second step", "第二步验证", "Второй шаг"),
        &site,
        None,
        &boards,
        &pow_min,
        st,
        sp,
        su,
        &recent,
        &announcement,
        &friend_links,
        &sidebar_settings,
        &get_footer_text(&state.store, &locale).await,
        &content,
        false,
        None,
        get_theme(headers),
        &get_palette(&state.store).await,
        &locale,
        headers,
    );
    apply_sec(Html(full).into_response())
}

pub async fn account_get(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AccountQuery>,
) -> Response {
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    render_account(&s, &headers, &user, &query, None).await
}

pub async fn account_password(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    let old = form.get("old_password").cloned().unwrap_or_default();
    let new = form.get("new_password").cloned().unwrap_or_default();
    let repeat = form.get("repeat_password").cloned().unwrap_or_default();
    if !crate::auth::validate_password(&new, &[&user.username]) {
        return apply_sec(Redirect::to("/account?err=weak_password").into_response());
    }
    if new != repeat {
        return apply_sec(Redirect::to("/account?err=weak_password").into_response());
    }
    if new == old {
        return apply_sec(Redirect::to("/account?err=no_change").into_response());
    }
    let Some(db_user) = s.store.get_user_by_id(user.id).await.unwrap_or(None) else {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "user not found").into_response());
    };
    let hash = db_user.password_hash.clone();
    let valid = crate::auth::verify_password_blocking(hash, old).await;
    if !valid {
        let _ = s
            .store
            .audit(
                Some(user.id),
                "account.password_change",
                Some("user"),
                Some(user.id),
                false,
            )
            .await;
        return apply_sec(Redirect::to("/account?err=bad_password").into_response());
    }
    let new_hash = match crate::auth::hash_password_blocking(new).await {
        Ok(hash) => hash,
        Err(_) => {
            return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "hash failed").into_response());
        }
    };
    let sid = if let Ok(sid) = s
        .store
        .update_password_and_rotate_sessions(user.id, &new_hash)
        .await
    {
        sid
    } else {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response());
    };
    let _ = s
        .store
        .audit(
            Some(user.id),
            "account.password_change",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    let mut response = Redirect::to("/account?ok=password_changed").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        session_cookie(&sid, 12 * 3600, s.secure_session_cookie)
            .parse()
            .unwrap(),
    );
    apply_sec(response)
}

pub async fn account_totp_setup(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    if !feature_enabled(&s.store).await {
        return apply_sec(Redirect::to("/account?err=feature_off").into_response());
    }
    // Enrolling replaces the credential that protects the account, so it costs
    // the current password. Without this, a stolen session could bind a secret
    // the owner cannot read and lock them out.
    if !confirm_password(&s, &user, &form).await {
        return apply_sec(Redirect::to("/account?err=bad_password").into_response());
    }
    let secret = crate::totp::generate_secret();
    if s.store.set_totp_pending(user.id, &secret).await.is_err() {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "enrolment failed").into_response());
    }
    let _ = s
        .store
        .audit(
            Some(user.id),
            "totp.enrolment_started",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    apply_sec(Redirect::to("/account").into_response())
}

pub async fn account_totp_cancel(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    let _ = s.store.clear_totp_pending(user.id).await;
    apply_sec(Redirect::to("/account?ok=totp_cancelled").into_response())
}

pub async fn account_totp_confirm(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    let code = form.get("code").cloned().unwrap_or_default();
    let state = match s.store.totp_state(user.id).await {
        Ok(state) => state,
        Err(_error) => {
            tracing::error!(
                operation = "totp_disable",
                error_chain_kind = "database_error",
                "second-factor state unavailable"
            );
            return apply_sec(
                (StatusCode::SERVICE_UNAVAILABLE, "state unavailable").into_response(),
            );
        }
    };
    let Some(pending) = state.pending_secret.as_deref() else {
        return apply_sec(Redirect::to("/account?err=bad_code").into_response());
    };
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let outcome = crate::totp::verify_code(
        pending,
        &user.username,
        &get_site_name(&s.store).await,
        &code,
        now,
        None,
    );
    let step = match outcome {
        Ok(crate::totp::CodeOutcome::Accepted { step }) => step,
        Ok(crate::totp::CodeOutcome::Replayed) => {
            return apply_sec(Redirect::to("/account?err=replayed_code").into_response());
        }
        Ok(crate::totp::CodeOutcome::Invalid) | Err(_) => {
            let _ = s
                .store
                .audit(
                    Some(user.id),
                    "totp.enrolment_confirm",
                    Some("user"),
                    Some(user.id),
                    false,
                )
                .await;
            return apply_sec(Redirect::to("/account?err=bad_code").into_response());
        }
    };
    if s.store
        .activate_totp(user.id, pending, step as i64)
        .await
        .is_err()
    {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "activation failed").into_response());
    }
    // A session that predates the second factor must not outlive it.
    revoke_other_sessions(&s, &user, &headers).await;
    let codes = crate::totp::generate_recovery_codes();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| crate::totp::hash_recovery_code(code))
        .collect();
    let _ = s.store.replace_recovery_codes(user.id, &hashes).await;
    let _ = s
        .store
        .audit(
            Some(user.id),
            "totp.activated",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    let query = AccountQuery {
        ok: Some("totp_enabled".to_string()),
        err: None,
    };
    render_account(&s, &headers, &user, &query, Some(&codes)).await
}

pub async fn account_totp_disable(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    let code = form.get("code").cloned().unwrap_or_default();
    if !confirm_password(&s, &user, &form).await {
        return apply_sec(Redirect::to("/account?err=bad_password").into_response());
    }
    // Fail closed: a storage error must not look like "no factor configured".
    let state = match s.store.totp_state(user.id).await {
        Ok(state) => state,
        Err(_error) => {
            tracing::error!(
                operation = "totp_recovery_codes",
                error_chain_kind = "database_error",
                "second-factor state unavailable"
            );
            return apply_sec(
                (StatusCode::SERVICE_UNAVAILABLE, "state unavailable").into_response(),
            );
        }
    };
    let verified = match state.secret.as_deref() {
        None => true,
        Some(secret) => {
            if crate::totp::looks_like_recovery_code(&code) {
                s.store
                    .consume_recovery_code(user.id, &crate::totp::hash_recovery_code(&code))
                    .await
                    .unwrap_or(false)
            } else {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                match crate::totp::verify_code(
                    secret,
                    &user.username,
                    &get_site_name(&s.store).await,
                    &code,
                    now,
                    state.last_step,
                ) {
                    Ok(crate::totp::CodeOutcome::Accepted { step }) => {
                        // Spend the step too, so a code used to switch the factor
                        // off cannot be replayed into a login afterwards.
                        s.store
                            .claim_totp_step(user.id, step as i64)
                            .await
                            .unwrap_or(false)
                    }
                    _ => false,
                }
            }
        }
    };
    if !verified {
        let _ = s
            .store
            .audit(
                Some(user.id),
                "totp.disable",
                Some("user"),
                Some(user.id),
                false,
            )
            .await;
        return apply_sec(Redirect::to("/account?err=bad_code").into_response());
    }
    if s.store.disable_totp(user.id).await.is_err() {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "disable failed").into_response());
    }
    // Removing the factor must not leave older sessions behind either.
    revoke_other_sessions(&s, &user, &headers).await;
    let _ = s
        .store
        .audit(
            Some(user.id),
            "totp.disabled",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    apply_sec(Redirect::to("/account?ok=totp_disabled").into_response())
}

pub async fn account_recovery_regenerate(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    if !confirm_password(&s, &user, &form).await {
        return apply_sec(Redirect::to("/account?err=bad_password").into_response());
    }
    match s.store.totp_state(user.id).await {
        Ok(state) if state.is_active() => {}
        Ok(_) => {
            return apply_sec(Redirect::to("/account?err=feature_off").into_response());
        }
        Err(_error) => {
            tracing::error!(
                operation = "account_recovery_regenerate",
                error_chain_kind = "database_error",
                "second-factor state unavailable"
            );
            return apply_sec(
                (StatusCode::SERVICE_UNAVAILABLE, "state unavailable").into_response(),
            );
        }
    }
    let codes = crate::totp::generate_recovery_codes();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| crate::totp::hash_recovery_code(code))
        .collect();
    if s.store
        .replace_recovery_codes(user.id, &hashes)
        .await
        .is_err()
    {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "regenerate failed").into_response());
    }
    let _ = s
        .store
        .audit(
            Some(user.id),
            "totp.recovery_regenerated",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    let query = AccountQuery {
        ok: Some("recovery_reissued".to_string()),
        err: None,
    };
    render_account(&s, &headers, &user, &query, Some(&codes)).await
}

pub async fn account_sessions_revoke(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(user) = current_user(&s, &headers).await else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    revoke_other_sessions(&s, &user, &headers).await;
    let _ = s
        .store
        .audit(
            Some(user.id),
            "account.sessions_revoked",
            Some("user"),
            Some(user.id),
            true,
        )
        .await;
    apply_sec(Redirect::to("/account?ok=sessions_revoked").into_response())
}

pub async fn login_totp_get(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PendingQuery>,
) -> Response {
    let Some(pending_id) = query.p.as_deref() else {
        return apply_sec(Redirect::to("/login").into_response());
    };
    match s.store.pending_login(pending_id).await {
        Ok(Some(_)) => render_login_totp(&s, &headers, pending_id, None).await,
        _ => apply_sec(Redirect::to("/login").into_response()),
    }
}

pub async fn login_totp_post(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !s.limits.allow_auth() {
        return apply_sec(
            (StatusCode::TOO_MANY_REQUESTS, "authentication rate limit").into_response(),
        );
    }
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let pending_id = form.get("pending_id").cloned().unwrap_or_default();
    let code = form.get("code").cloned().unwrap_or_default();
    let locale = site_locale(&s.store).await;
    let ui = |en: &str, zh: &str, ru: &str| crate::i18n::ui(&locale, en, zh, ru);

    let pending = match s.store.pending_login(&pending_id).await {
        Ok(Some(pending)) => pending,
        _ => {
            return apply_sec(
                (
                    StatusCode::FORBIDDEN,
                    ui(
                        "This login attempt expired. Please sign in again.",
                        "本次登录已过期，请重新登录。",
                        "Попытка входа истекла. Войдите снова.",
                    ),
                )
                    .into_response(),
            );
        }
    };
    let Some(user) = s
        .store
        .get_user_by_id(pending.user_id)
        .await
        .unwrap_or(None)
    else {
        return apply_sec((StatusCode::INTERNAL_SERVER_ERROR, "user not found").into_response());
    };
    // Bound guessing per account, not only per pending login. Without this, a
    // password holder can open a fresh attempt (and five new guesses) as often
    // as the global authentication limiter allows.
    let since = chrono::Utc::now() - chrono::Duration::minutes(TOTP_ATTEMPT_WINDOW_MINUTES);
    // Fail closed: a counter read that fails must not silently reopen the
    // per-account second-factor guessing budget.
    let recent_failures = match s.store.recent_failed_totp_attempts(user.id, since).await {
        Ok(count) => count,
        Err(_error) => {
            tracing::error!(
                operation = "login_totp_post",
                error_chain_kind = "database_error",
                "second-factor attempt counter unavailable"
            );
            return apply_sec(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "second-factor attempt counter unavailable",
                )
                    .into_response(),
            );
        }
    };
    if recent_failures >= TOTP_ACCOUNT_ATTEMPT_LIMIT {
        let _ = s
            .store
            .audit(
                Some(user.id),
                "login.totp_throttled",
                Some("user"),
                Some(user.id),
                false,
            )
            .await;
        return apply_sec(
            (
                StatusCode::TOO_MANY_REQUESTS,
                ui(
                    "Too many second-factor attempts. Please wait a few minutes.",
                    "二步验证尝试次数过多，请稍后再试。",
                    "Слишком много попыток. Попробуйте через несколько минут.",
                ),
            )
                .into_response(),
        );
    }
    let state = match s.store.totp_state(user.id).await {
        Ok(state) => state,
        Err(_error) => {
            tracing::error!(
                operation = "login_totp_post",
                error_chain_kind = "database_error",
                "second-factor state unavailable"
            );
            return apply_sec(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "second-factor state unavailable",
                )
                    .into_response(),
            );
        }
    };
    let Some(secret) = state.secret.as_deref().filter(|_| state.is_active()) else {
        // The factor disappeared mid-login; treat it as a failed attempt.
        let _ = s.store.fail_pending_login(&pending_id).await;
        return apply_sec(Redirect::to("/login").into_response());
    };

    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let recovery = crate::totp::looks_like_recovery_code(&code);
    let outcome = if recovery {
        let consumed = s
            .store
            .consume_recovery_code(user.id, &crate::totp::hash_recovery_code(&code))
            .await
            .unwrap_or(false);
        if consumed {
            Ok(crate::totp::CodeOutcome::Accepted { step: 0 })
        } else {
            Ok(crate::totp::CodeOutcome::Invalid)
        }
    } else {
        crate::totp::verify_code(
            secret,
            &user.username,
            &get_site_name(&s.store).await,
            &code,
            now,
            state.last_step,
        )
    };

    match outcome {
        Ok(crate::totp::CodeOutcome::Accepted { step }) => {
            // Claim the step before anything else: a concurrent login holding
            // the same code must not be able to reuse it, and only the writer
            // that moved the column forward may continue.
            let claimed = if recovery {
                true
            } else {
                s.store
                    .claim_totp_step(user.id, step as i64)
                    .await
                    .unwrap_or(false)
            };
            if !claimed {
                return apply_sec(
                    (
                        StatusCode::FORBIDDEN,
                        ui(
                            "That code was already used. Wait for the next one.",
                            "该验证码已被使用，请等待下一个。",
                            "Этот код уже использован. Дождитесь следующего.",
                        ),
                    )
                        .into_response(),
                );
            }
            if s.store
                .consume_pending_login(&pending_id, user.id)
                .await
                .unwrap_or(false)
            {
                let _ = s
                    .store
                    .audit(
                        Some(user.id),
                        if recovery {
                            "login.recovery_code"
                        } else {
                            "login.totp"
                        },
                        Some("user"),
                        Some(user.id),
                        true,
                    )
                    .await;
                return complete_login(&s, &user, &headers).await;
            }
            apply_sec(Redirect::to("/login").into_response())
        }
        Ok(crate::totp::CodeOutcome::Replayed) => apply_sec(
            (
                StatusCode::FORBIDDEN,
                ui(
                    "That code was already used. Wait for the next one.",
                    "该验证码已被使用，请等待下一个。",
                    "Этот код уже использован. Дождитесь следующего.",
                ),
            )
                .into_response(),
        ),
        _ => {
            // A genuine storage failure must not reset the per-attempt budget
            // to zero, but a rejected code is not a storage failure: the
            // counter still has to be spent and the form has to be redisplayed.
            let attempts = match s.store.fail_pending_login(&pending_id).await {
                Ok(attempts) => attempts,
                Err(_error) => {
                    tracing::error!(
                        operation = "login_totp_post",
                        error_chain_kind = "database_error",
                        "second-factor attempt counter unavailable"
                    );
                    return apply_sec(
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "second-factor attempt counter unavailable",
                        )
                            .into_response(),
                    );
                }
            };
            let _ = s
                .store
                .audit(
                    Some(user.id),
                    "login.totp_failed",
                    Some("user"),
                    Some(user.id),
                    false,
                )
                .await;
            if attempts >= crate::store::PENDING_LOGIN_MAX_ATTEMPTS {
                return apply_sec(
                    (
                        StatusCode::FORBIDDEN,
                        ui(
                            "Too many attempts. Please sign in again.",
                            "尝试次数过多，请重新登录。",
                            "Слишком много попыток. Войдите снова.",
                        ),
                    )
                        .into_response(),
                );
            }
            let message = ui("That code is not valid.", "验证码不正确。", "Неверный код.");
            render_login_totp(&s, &headers, &pending_id, Some(&message)).await
        }
    }
}

/// Administration: turn the feature on or off and choose the policy.
pub async fn admin_config_totp(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !require_form_security(&headers, &form) {
        return apply_sec((StatusCode::FORBIDDEN, "csrf check failed").into_response());
    }
    let Some(actor) = require_admin_state(&s, &headers).await else {
        return apply_sec((StatusCode::FORBIDDEN, "forbidden").into_response());
    };
    let enabled = form.get("totp_enabled").map(String::as_str) == Some("1");
    let policy = policy_value(
        form.get("totp_required")
            .map(String::as_str)
            .unwrap_or("none"),
    );
    let ok = s
        .store
        .set_config(TOTP_FEATURE_KEY, if enabled { "1" } else { "0" })
        .await
        .is_ok()
        && s.store.set_config(TOTP_POLICY_KEY, policy).await.is_ok();
    s.store
        .audit(
            Some(actor.id),
            "admin.totp_settings",
            Some("config"),
            None,
            ok,
        )
        .await
        .ok();
    apply_sec(Redirect::to("/admin/settings").into_response())
}
