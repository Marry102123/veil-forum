use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct Post {
    pub id: i64,
    pub thread_id: i64,
    pub board_id: i64,
    pub author_id: i64,
    pub is_anonymous: bool,
    pub parent_post_id: Option<i64>,
    pub content_md: String,
    pub content_html: String,
    pub created_at: DateTime<Utc>,
    pub author_name: String,
}

#[derive(Debug, Clone)]
pub struct ThreadBrief {
    pub id: i64,
    pub board_id: i64,
    pub title: String,
}

#[derive(Debug, Clone)]
pub struct Thread {
    pub id: i64,
    pub board_id: i64,
    pub title: String,
    pub author_id: i64,
    pub is_pinned: bool,
    pub is_locked: bool,
    pub reply_count: i64,
    pub last_reply_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub author_name: String,
    pub board_slug: String,
}

#[derive(Debug, Clone)]
pub struct Board {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub allow_anonymous: bool,
    pub guest_readable: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Nullable in the schema and in imported legacy rows: a session without a
    /// last-seen timestamp is treated as expired rather than assumed fresh.
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub is_banned: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    Moderator,
}

impl Role {
    /// Stable name as stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Moderator => "moderator",
        }
    }

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "moderator" => Ok(Self::Moderator),
            _ => anyhow::bail!("unknown role: {value}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub id: i64,
    pub reporter_user_id: Option<i64>,
    pub target_type: String,
    pub target_id: i64,
    pub reason: String,
    pub status: String,
    pub resolved_by_user_id: Option<i64>,
    pub resolution_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    pub id: i64,
    pub actor_user_id: Option<i64>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<i64>,
    pub success: bool,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct InviteCode {
    pub code: String,
    pub created_by: i64,
    pub used_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub max_uses: i64,
    pub use_count: i64,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<i64>,
    pub note: String,
}

/// How long the user has between the password step and the second factor.
pub const PENDING_LOGIN_TTL_SECONDS: i64 = 300;
/// Failed second-factor attempts allowed per pending login.
pub const PENDING_LOGIN_MAX_ATTEMPTS: i64 = 5;

/// TOTP enrolment and activation state for one account.
#[derive(Debug, Clone, Default)]
pub struct TotpState {
    /// Active shared secret (base32) when the second factor is enabled.
    pub secret: Option<String>,
    pub activated_at: Option<DateTime<Utc>>,
    /// Highest time step already accepted, for replay prevention.
    pub last_step: Option<i64>,
    /// Enrolment awaiting confirmation by a valid code.
    pub pending_secret: Option<String>,
    pub pending_created_at: Option<DateTime<Utc>>,
    pub unused_recovery_codes: i64,
}

impl TotpState {
    /// True when the account must present a second factor at login.
    pub fn is_active(&self) -> bool {
        self.secret.is_some() && self.activated_at.is_some()
    }
}

/// A password step that is waiting for its second factor.
#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub id: String,
    pub user_id: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub attempts: i64,
}

/// Number of connection attempts at startup so the service can come up while
/// PostgreSQL is still starting.
const CONNECT_ATTEMPTS: u32 = 10;
const CONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);
/// Per-attempt ceiling so startup cannot hang on an unreachable host.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Remove any password from a database URL before it reaches logs or errors.
///
/// Three forms reach this function: the URL form
/// (`postgres://user:secret@host/db`), a password as a query parameter
/// (`...?password=secret`), and the libpq keyword/value form that sqlx also
/// accepts (`host=127.0.0.1 password=secret user=u`).
pub fn redact_database_url(url: &str) -> String {
    let mut out = url.to_string();

    // URL form. The authority runs to the first `/` after `scheme://`, and a
    // password may itself contain '@', so the last '@' before the path is the
    // separator.
    if let Some(scheme_slash) = out.find("://") {
        let authority_start = scheme_slash + 3;
        let authority_end = out[authority_start..]
            .find('/')
            .map(|offset| authority_start + offset)
            .unwrap_or(out.len());
        if let Some(at) = out[authority_start..authority_end].rfind('@') {
            let userinfo_end = authority_start + at;
            if let Some(colon) = out[authority_start..userinfo_end].find(':') {
                out.replace_range(authority_start + colon + 1..userinfo_end, "***");
            }
        }
    }

    // Password named as a parameter: separated by '?', '&', whitespace (libpq
    // keyword form), or the start of the string. The search always resumes past
    // the value that was just handled, so it cannot loop.
    let mut search_from = 0;
    while let Some(relative) = out[search_from..].find("password=") {
        let key_start = search_from + relative;
        let boundary =
            key_start == 0 || matches!(out.as_bytes()[key_start - 1], b'?' | b'&' | b' ' | b'\t');
        let value_start = key_start + "password=".len();
        let value_first = out[value_start..].chars().next();
        let value_end = match value_first {
            Some(quote @ ('\'' | '"')) => {
                let quoted = value_start + quote.len_utf8();
                out[quoted..]
                    .find(quote)
                    .map(|offset| quoted + offset + quote.len_utf8())
                    .unwrap_or(out.len())
            }
            _ => {
                value_start
                    + out[value_start..]
                        .find(['&', '#', ' ', '\t', '\n'])
                        .unwrap_or(out.len() - value_start)
            }
        };
        if boundary {
            out.replace_range(value_start..value_end, "***");
        }
        search_from = value_start + 3;
    }
    out
}

/// Above this many matches, search results are ordered newest-first instead of
/// by similarity: ranking a very common term scores every matching row, while
/// the ordered path stops as soon as the page is full.
const SEARCH_RANK_LIMIT: i64 = 2000;

/// Common table expression that yields one row per matching post id.
///
/// Each branch of the `UNION` touches a single table so that the planner can use
/// `idx_posts_content_trgm` or `idx_threads_title_trgm`; combining both
/// conditions in one `OR` across two tables rules out both indexes.
const SEARCH_MATCHES: &str = "WITH matches AS ( \
     SELECT p.id AS post_id FROM posts p \
       JOIN threads th ON th.id=p.thread_id \
       JOIN boards b ON b.id=th.board_id \
      WHERE p.deleted_at IS NULL AND th.deleted_at IS NULL AND ($1 OR b.guest_readable) \
        AND p.content_md ILIKE $2 ESCAPE '\\' \
     UNION \
     SELECT p.id FROM posts p \
       JOIN threads th ON th.id=p.thread_id \
       JOIN boards b ON b.id=th.board_id \
      WHERE p.deleted_at IS NULL AND th.deleted_at IS NULL AND ($1 OR b.guest_readable) \
        AND th.title ILIKE $2 ESCAPE '\\' \
 )";

/// Escape LIKE/ILIKE wildcards so search input matches literally. The query is
/// always paired with `ESCAPE '\'` in SQL.
fn escape_like_pattern(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

async fn connect_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let mut last_error = None;
    for attempt in 1..=CONNECT_ATTEMPTS {
        // Bound each attempt explicitly: a blackholed host would otherwise hold
        // startup for the operating system's TCP timeout, which is longer than
        // the service manager's start timeout.
        let connect = tokio::time::timeout(
            CONNECT_TIMEOUT,
            PgPoolOptions::new()
                .max_connections(16)
                .acquire_timeout(std::time::Duration::from_secs(5))
                .connect(database_url),
        )
        .await;
        match connect {
            Ok(Ok(pool)) => return Ok(pool),
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("connect timed out after {CONNECT_TIMEOUT:?}")),
        }
        if attempt < CONNECT_ATTEMPTS {
            tokio::time::sleep(CONNECT_BACKOFF).await;
        }
    }
    Err(anyhow::anyhow!(
        "could not connect to PostgreSQL at {} after {CONNECT_ATTEMPTS} attempts: {}",
        redact_database_url(database_url),
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

impl Store {
    /// Connect to PostgreSQL, apply embedded migrations, and seed first-run
    /// values.
    ///
    /// `database_url` is a libpq-style URL such as
    /// `postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum`. The socket form with
    /// peer authentication is recommended: the database never listens on the
    /// network and no password is stored in configuration or the environment.
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = connect_pool(database_url).await?;
        let store = Self { pool };
        store.migrate().await?;
        store.seed_defaults().await?;
        Ok(store)
    }

    /// Apply the embedded `migrations/*.sql`. sqlx holds a database advisory
    /// lock for the run, so two instances starting at once cannot interleave
    /// schema changes, and every migration is applied in a transaction.
    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Insert first-run defaults (site config, default board). Idempotent, so
    /// it is safe to call on every start and from tests.
    pub async fn seed_defaults(&self) -> anyhow::Result<()> {
        let defaults = [
            ("pow_register_minutes", "0.02"),
            ("pow_login_minutes", "0.02"),
            ("pow_post_minutes", "0.02"),
            ("registration_mode", "invite"),
            ("reports_enabled", "1"),
            ("registration_pow_enabled", "1"),
            ("registration_captcha_enabled", "0"),
            ("login_pow_enabled", "1"),
            ("login_captcha_enabled", "0"),
            ("post_pow_enabled", "1"),
            ("post_captcha_enabled", "0"),
            ("captcha_difficulty", "low"),
            ("registration_invite_enabled", "1"),
            ("site_name", "secure-forum"),
            ("footer_text", ""),
            ("totp_enabled", "1"),
            ("totp_required", "none"),
        ];
        for (k, v) in defaults {
            sqlx::query(
                "INSERT INTO configs(key,value) VALUES($1,$2) ON CONFLICT (key) DO NOTHING",
            )
            .bind(k)
            .bind(v)
            .execute(&self.pool)
            .await?;
        }
        sqlx::query("INSERT INTO configs(key,value) VALUES($1,$2) ON CONFLICT (key) DO NOTHING")
            .bind("default_locale")
            .bind("en")
            .execute(&self.pool)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boards")
            .fetch_one(&self.pool)
            .await?;
        if cnt.0 == 0 {
            sqlx::query("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES($1,$2,$3,$4,$5,$6)")
                .bind("general").bind("General").bind("General discussion").bind(true).bind(true).bind(Utc::now())
                .execute(&self.pool).await?;
        }
        Ok(())
    }
    /// GetConfig — 对齐 Go `(string,error)` 语义：
    /// - not-found: Go 返回 sql.ErrNoRows; Rust 返回 Ok(None)（调用方可 fallback 到默认值）
    /// - DB 错误: Go 返回 error; Rust 返回 Err(anyhow)
    ///
    /// 旧签名 `Option<String>` 会吞掉 DB 错误（`.ok().flatten()`），现改为 `Result<Option>`
    /// 以与 Go 一致可区分错误与缺失。
    pub async fn get_config(&self, key: &str) -> anyhow::Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM configs WHERE key=$1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.0))
    }
    /// 兼容旧调用点的简便封装：忽略 DB 错误返回 None（仅用于幂等 fallback 场景）
    pub async fn get_config_opt(&self, key: &str) -> Option<String> {
        self.get_config(key).await.unwrap_or(None)
    }
    pub async fn set_config(&self, key: &str, val: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO configs(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key).bind(val).execute(&self.pool).await?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn set_registration_policies(
        &self,
        reports_enabled: bool,
        registration_pow_enabled: bool,
        registration_invite_enabled: bool,
        registration_captcha_enabled: bool,
        login_pow_enabled: bool,
        login_captcha_enabled: bool,
        post_pow_enabled: bool,
        post_captcha_enabled: bool,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        for (key, enabled) in [
            ("reports_enabled", reports_enabled),
            ("registration_pow_enabled", registration_pow_enabled),
            ("registration_invite_enabled", registration_invite_enabled),
            ("registration_captcha_enabled", registration_captcha_enabled),
            ("login_pow_enabled", login_pow_enabled),
            ("login_captcha_enabled", login_captcha_enabled),
            ("post_pow_enabled", post_pow_enabled),
            ("post_captcha_enabled", post_captcha_enabled),
        ] {
            sqlx::query("INSERT INTO configs(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                .bind(key)
                .bind(if enabled { "1" } else { "0" })
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn get_all_configs(
        &self,
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        let rows = sqlx::query("SELECT key,value FROM configs")
            .fetch_all(&self.pool)
            .await?;
        let mut m = std::collections::HashMap::new();
        for r in rows {
            m.insert(r.get::<String, _>("key"), r.get::<String, _>("value"));
        }
        Ok(m)
    }

    // ---- users — ported from Go internal/store/users.go ----
    pub async fn create_user(
        &self,
        username: &str,
        hash: &str,
        is_admin: bool,
    ) -> anyhow::Result<i64> {
        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES($1,$2,$3,$4) RETURNING id",
        )
        .bind(username)
        .bind(hash)
        .bind(is_admin)
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }
    pub async fn get_user_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        let row = sqlx::query("SELECT id,username,password_hash,is_admin,is_banned,created_at FROM users WHERE username=$1")
            .bind(username).fetch_optional(&self.pool).await?;
        row.map(|r| -> anyhow::Result<User> {
            let created: DateTime<Utc> = r.get("created_at");
            Ok(User {
                id: r.get("id"),
                username: r.get("username"),
                password_hash: r.get("password_hash"),
                is_admin: r.get::<bool, _>("is_admin"),
                is_banned: r.get::<bool, _>("is_banned"),
                created_at: created,
            })
        })
        .transpose()
    }
    pub async fn get_user_by_id(&self, id: i64) -> anyhow::Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id,username,password_hash,is_admin,is_banned,created_at FROM users WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| -> anyhow::Result<User> {
            let created: DateTime<Utc> = r.get("created_at");
            Ok(User {
                id: r.get("id"),
                username: r.get("username"),
                password_hash: r.get("password_hash"),
                is_admin: r.get::<bool, _>("is_admin"),
                is_banned: r.get::<bool, _>("is_banned"),
                created_at: created,
            })
        })
        .transpose()
    }
    pub async fn list_users(&self, limit: i64) -> anyhow::Result<Vec<User>> {
        let rows = sqlx::query("SELECT id,username,password_hash,is_admin,is_banned,created_at FROM users ORDER BY id DESC LIMIT $1")
            .bind(limit).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| -> anyhow::Result<User> {
                let created: DateTime<Utc> = r.get("created_at");
                Ok(User {
                    id: r.get("id"),
                    username: r.get("username"),
                    password_hash: r.get("password_hash"),
                    is_admin: r.get::<bool, _>("is_admin"),
                    is_banned: r.get::<bool, _>("is_banned"),
                    created_at: created,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()
    }
    pub async fn set_user_banned(&self, id: i64, banned: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET is_banned=$1 WHERE id=$2")
            .bind(banned)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn update_password(&self, id: i64, hash: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET password_hash=$1 WHERE id=$2")
            .bind(hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn audit(
        &self,
        actor_user_id: Option<i64>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<i64>,
        success: bool,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        sqlx::query("INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,success,created_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(actor_user_id).bind(action).bind(target_type).bind(target_id)
            .bind(success).bind(now)
            .execute(&self.pool).await?;
        Ok(())
    }
    pub async fn audit_with_metadata(
        &self,
        actor_user_id: Option<i64>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<i64>,
        success: bool,
        metadata: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,success,metadata,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(actor_user_id).bind(action).bind(target_type).bind(target_id)
            .bind(success).bind(metadata)
            .bind(Utc::now())
            .execute(&self.pool).await?;
        Ok(())
    }
    pub async fn list_audit_logs(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> anyhow::Result<Vec<AuditLog>> {
        let rows = sqlx::query("SELECT id,actor_user_id,action,target_type,target_id,success,metadata,created_at FROM audit_logs WHERE ($1 IS NULL OR id < $2) ORDER BY id DESC LIMIT $3")
            .bind(before_id).bind(before_id).bind(limit.clamp(1, 200)).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(AuditLog {
                    id: r.get("id"),
                    actor_user_id: r.get("actor_user_id"),
                    action: r.get("action"),
                    target_type: r.get("target_type"),
                    target_id: r.get("target_id"),
                    success: r.get::<bool, _>("success"),
                    metadata: r.get("metadata"),
                    created_at: r.get("created_at"),
                })
            })
            .collect()
    }

    pub async fn grant_role(
        &self,
        user_id: i64,
        role: Role,
        granted_by_user_id: Option<i64>,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO user_roles(user_id,role_name,granted_by_user_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT (user_id, role_name) DO NOTHING")
            .bind(user_id).bind(role.as_str()).bind(granted_by_user_id)
            .bind(Utc::now()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn revoke_role(&self, user_id: i64, role: Role) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM user_roles WHERE user_id=$1 AND role_name=$2")
            .bind(user_id)
            .bind(role.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn list_user_roles(&self, user_id: i64) -> anyhow::Result<Vec<Role>> {
        sqlx::query_scalar::<_, String>(
            "SELECT role_name FROM user_roles WHERE user_id=$1 ORDER BY role_name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|name| Role::from_str(&name))
        .collect()
    }
    pub async fn user_has_role(&self, user_id: i64, role: Role) -> anyhow::Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_name=$2)",
        )
        .bind(user_id)
        .bind(role.as_str())
        .fetch_one(&self.pool)
        .await?)
    }
    pub async fn add_board_moderator(
        &self,
        board_id: i64,
        user_id: i64,
        granted_by_user_id: Option<i64>,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO board_moderators(board_id,user_id,granted_by_user_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT (board_id, user_id) DO NOTHING")
            .bind(board_id).bind(user_id).bind(granted_by_user_id).bind(Utc::now()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn remove_board_moderator(&self, board_id: i64, user_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM board_moderators WHERE board_id=$1 AND user_id=$2")
            .bind(board_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn is_board_moderator(&self, board_id: i64, user_id: i64) -> anyhow::Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM board_moderators WHERE board_id=$1 AND user_id=$2)",
        )
        .bind(board_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?)
    }
    pub async fn can_moderate_board(&self, board_id: i64, user_id: i64) -> anyhow::Result<bool> {
        if self.user_has_role(user_id, Role::Owner).await?
            || self.user_has_role(user_id, Role::Admin).await?
        {
            return Ok(true);
        }
        Ok(self.user_has_role(user_id, Role::Moderator).await?
            && self.is_board_moderator(board_id, user_id).await?)
    }
    pub async fn create_report(
        &self,
        reporter_user_id: Option<i64>,
        target_type: &str,
        target_id: i64,
        reason: &str,
    ) -> anyhow::Result<i64> {
        if !matches!(target_type, "post" | "thread" | "user") {
            anyhow::bail!("invalid report target type");
        }
        Ok(sqlx::query_scalar::<_, i64>("INSERT INTO reports(reporter_user_id,target_type,target_id,reason,created_at) VALUES($1,$2,$3,$4,$5) RETURNING id")
            .bind(reporter_user_id).bind(target_type).bind(target_id).bind(reason).bind(Utc::now()).fetch_one(&self.pool).await?)
    }
    pub async fn list_reports(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<Report>> {
        let rows = sqlx::query("SELECT id,reporter_user_id,target_type,target_id,reason,status,resolved_by_user_id,resolution_note,created_at,resolved_at FROM reports WHERE ($1 IS NULL OR status=$2) ORDER BY id DESC LIMIT $3")
            .bind(status).bind(status).bind(limit.clamp(1, 200)).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(Report {
                    id: r.get("id"),
                    reporter_user_id: r.get("reporter_user_id"),
                    target_type: r.get("target_type"),
                    target_id: r.get("target_id"),
                    reason: r.get("reason"),
                    status: r.get("status"),
                    resolved_by_user_id: r.get("resolved_by_user_id"),
                    resolution_note: r.get("resolution_note"),
                    created_at: r.get("created_at"),
                    resolved_at: r.get("resolved_at"),
                })
            })
            .collect()
    }
    pub async fn resolve_report(
        &self,
        id: i64,
        resolver_user_id: i64,
        status: &str,
        resolution_note: Option<&str>,
    ) -> anyhow::Result<()> {
        if !matches!(status, "resolved" | "dismissed") {
            anyhow::bail!("invalid report resolution status");
        }
        sqlx::query("UPDATE reports SET status=$1,resolved_by_user_id=$2,resolution_note=$3,resolved_at=$4 WHERE id=$5 AND status='open'").bind(status).bind(resolver_user_id).bind(resolution_note).bind(Utc::now()).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ---- boards — ported from Go internal/store/boards.go ----
    fn row_to_board(row: &PgRow) -> anyhow::Result<Board> {
        let created: DateTime<Utc> = row.get("created_at");
        Ok(Board {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            description: row.get("description"),
            allow_anonymous: row.get::<bool, _>("allow_anonymous"),
            guest_readable: row.get::<bool, _>("guest_readable"),
            created_at: created,
        })
    }

    /// CreateBoard — INSERT INTO boards(...) VALUES($1..$6) RETURNING id
    pub async fn create_board(
        &self,
        slug: &str,
        name: &str,
        desc: &str,
        allow_anonymous: bool,
        guest_readable: bool,
    ) -> anyhow::Result<i64> {
        let id = sqlx::query_scalar::<_, i64>("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id")
            .bind(slug).bind(name).bind(desc)
            .bind(allow_anonymous)
            .bind(guest_readable)
            .bind(Utc::now())
            .fetch_one(&self.pool).await?;
        Ok(id)
    }

    /// ListBoards — ORDER BY id ASC, bool映射, chrono文本解析 (RFC3339Nano/RFC3339兼容)
    pub async fn list_boards(&self) -> anyhow::Result<Vec<Board>> {
        let rows = sqlx::query("SELECT id,slug,name,description,allow_anonymous,guest_readable,created_at FROM boards ORDER BY id ASC")
            .fetch_all(&self.pool).await?;
        rows.iter().map(Self::row_to_board).collect()
    }

    /// GetBoardBySlug — SELECT ... WHERE slug=?
    pub async fn get_board_by_slug(&self, slug: &str) -> anyhow::Result<Option<Board>> {
        let row = sqlx::query("SELECT id,slug,name,description,allow_anonymous,guest_readable,created_at FROM boards WHERE slug=$1")
            .bind(slug).fetch_optional(&self.pool).await?;
        row.as_ref().map(Self::row_to_board).transpose()
    }

    /// GetBoardByID — SELECT ... WHERE id=?
    pub async fn get_board_by_id(&self, id: i64) -> anyhow::Result<Option<Board>> {
        let row = sqlx::query("SELECT id,slug,name,description,allow_anonymous,guest_readable,created_at FROM boards WHERE id=$1")
            .bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(Self::row_to_board).transpose()
    }

    /// UpdateBoard — UPDATE boards SET name=?,description=?,allow_anonymous=?,guest_readable=? WHERE id=?
    pub async fn update_board(
        &self,
        id: i64,
        name: &str,
        desc: &str,
        allow_anonymous: bool,
        guest_readable: bool,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE boards SET name=$1,description=$2,allow_anonymous=$3,guest_readable=$4 WHERE id=$5",
        )
        .bind(name)
        .bind(desc)
        .bind(allow_anonymous)
        .bind(guest_readable)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// DeleteBoard — DELETE FROM boards WHERE id=?
    pub async fn delete_board(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM boards WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- posts ----
    /// CreatePost: 插入 posts 行，并触发回帖计数（reply_count+1 + last_reply_at）
    /// 对齐 Go: CreatePost(threadID, boardID, authorID, isAnonymous, md, html)
    pub async fn create_post(
        &self,
        thread_id: i64,
        board_id: i64,
        author_id: i64,
        is_anonymous: bool,
        md: &str,
        html: &str,
    ) -> anyhow::Result<i64> {
        self.create_post_with_parent(thread_id, board_id, author_id, is_anonymous, md, html, None)
            .await
    }
    pub async fn last_post_at(&self, author_id: i64) -> anyhow::Result<Option<DateTime<Utc>>> {
        let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
            "SELECT created_at FROM posts WHERE author_id=$1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(author_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(value,)| value))
    }
    /// CreatePostWithParent: 楼中楼，parent_post_id None 表示回楼主，Some(pid) 表示回复某条评论
    #[allow(clippy::too_many_arguments)]
    pub async fn create_post_with_parent(
        &self,
        thread_id: i64,
        board_id: i64,
        author_id: i64,
        is_anonymous: bool,
        md: &str,
        html: &str,
        parent_post_id: Option<i64>,
    ) -> anyhow::Result<i64> {
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        let id = sqlx::query_scalar::<_, i64>("INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,parent_post_id,content_md,content_html,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id")
            .bind(thread_id).bind(board_id).bind(author_id).bind(is_anonymous).bind(parent_post_id).bind(md).bind(html).bind(now)
            .fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE threads SET reply_count=reply_count+1, last_reply_at=$1 WHERE id=$2")
            .bind(now)
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(id)
    }
    /// ListPosts: thread 分页 + author join，未匿名显示 username，匿名仍存 author_id 但显示上游可忽略
    pub async fn list_posts(
        &self,
        thread_id: i64,
        page: i64,
        page_size: i64,
    ) -> anyhow::Result<(Vec<Post>, i64)> {
        let page = page.max(1);
        let page_size = page_size.clamp(1, 100);
        let offset = (page - 1) * page_size;
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM posts WHERE thread_id=$1 AND deleted_at IS NULL")
                .bind(thread_id)
                .fetch_one(&self.pool)
                .await?;
        let rows = sqlx::query(
            "SELECT p.id, p.thread_id, p.board_id, p.author_id, p.is_anonymous, p.parent_post_id, p.content_md, p.content_html, p.created_at, COALESCE(u.username,'deleted') \
             FROM posts p LEFT JOIN users u ON u.id=p.author_id \
             WHERE p.thread_id=$1 AND p.deleted_at IS NULL ORDER BY p.id ASC LIMIT $2 OFFSET $3"
        )
        .bind(thread_id).bind(page_size).bind(offset)
        .fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let created: DateTime<Utc> = r.get("created_at");
            out.push(Post {
                id: r.get("id"),
                thread_id: r.get("thread_id"),
                board_id: r.get("board_id"),
                author_id: r.get("author_id"),
                is_anonymous: r.get::<bool, _>("is_anonymous"),
                parent_post_id: r.get::<Option<i64>, _>("parent_post_id"),
                content_md: r.get("content_md"),
                content_html: r.get("content_html"),
                created_at: created,
                author_name: r.get::<String, _>(9),
            });
        }
        Ok((out, total.0))
    }

    pub async fn get_post(&self, id: i64) -> anyhow::Result<Option<Post>> {
        let row = sqlx::query(
            "SELECT p.id,p.thread_id,p.board_id,p.author_id,p.is_anonymous,p.parent_post_id,p.content_md,p.content_html,p.created_at, COALESCE(u.username,'deleted') \
             FROM posts p LEFT JOIN users u ON u.id=p.author_id WHERE p.id=$1 AND p.deleted_at IS NULL"
        )
        .bind(id).fetch_optional(&self.pool).await?;
        if let Some(r) = row {
            let created: DateTime<Utc> = r.get("created_at");
            return Ok(Some(Post {
                id: r.get("id"),
                thread_id: r.get("thread_id"),
                board_id: r.get("board_id"),
                author_id: r.get("author_id"),
                is_anonymous: r.get::<bool, _>("is_anonymous"),
                parent_post_id: r.get::<Option<i64>, _>("parent_post_id"),
                content_md: r.get("content_md"),
                content_html: r.get("content_html"),
                created_at: created,
                author_name: r.get::<String, _>(9),
            }));
        }
        Ok(None)
    }

    pub async fn delete_post(&self, id: i64) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let post = sqlx::query("SELECT thread_id FROM posts WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(post) = post else {
            return Ok(());
        };
        let thread_id: i64 = post.get("thread_id");
        let first_post: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM posts WHERE thread_id=$1 ORDER BY id ASC LIMIT 1")
                .bind(thread_id)
                .fetch_optional(&mut *tx)
                .await?;
        sqlx::query("DELETE FROM posts WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if first_post.map(|row| row.0 != id).unwrap_or(false) {
            sqlx::query(
                "UPDATE threads SET reply_count=GREATEST(reply_count-1, 0), last_reply_at=COALESCE((SELECT MAX(created_at) FROM posts WHERE thread_id=$1), created_at) WHERE id=$2",
            )
            .bind(thread_id)
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn soft_delete_post(
        &self,
        id: i64,
        deleted_by_user_id: Option<i64>,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE posts SET deleted_at=$1, deleted_by_user_id=$2 WHERE id=$3 AND deleted_at IS NULL",
        )
        .bind(Utc::now())
        .bind(deleted_by_user_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn restore_post(&self, id: i64) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE posts SET deleted_at=NULL, deleted_by_user_id=NULL WHERE id=$1 AND deleted_at IS NOT NULL")
            .bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn list_deleted_posts(&self, limit: i64) -> anyhow::Result<Vec<Post>> {
        let rows = sqlx::query(
            "SELECT p.id,p.thread_id,p.board_id,p.author_id,p.is_anonymous,p.parent_post_id,p.content_md,p.content_html,p.created_at,COALESCE(u.username,'deleted') \
             FROM posts p LEFT JOIN users u ON u.id=p.author_id \
             WHERE p.deleted_at IS NOT NULL ORDER BY p.deleted_at DESC,p.id DESC LIMIT $1",
        )
        .bind(limit.clamp(1, 200))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(Post {
                    id: r.get("id"),
                    thread_id: r.get("thread_id"),
                    board_id: r.get("board_id"),
                    author_id: r.get("author_id"),
                    is_anonymous: r.get::<bool, _>("is_anonymous"),
                    parent_post_id: r.get("parent_post_id"),
                    content_md: r.get("content_md"),
                    content_html: r.get("content_html"),
                    created_at: r.get("created_at"),
                    author_name: r.get(9),
                })
            })
            .collect()
    }

    /// SearchPosts: substring search across thread titles and post bodies.
    ///
    /// SQLite FTS5 is replaced by `pg_trgm`. The input is treated as plain text
    /// rather than a search expression, and the GIN trigram indexes on
    /// `threads.title` and `posts.content_md` serve selective terms directly.
    ///
    /// The matching set is built per table (`SEARCH_MATCHES`) because a single
    /// `title ILIKE .. OR content ILIKE ..` predicate spans two tables, which
    /// forces a sequential scan on both sides of the join and cannot use either
    /// index. Ordering depends on the match count: a small result set is ranked
    /// by trigram similarity, while a very common term is returned newest-first,
    /// which lets PostgreSQL stop after the requested page.
    ///
    /// Returns (posts, threads, total).
    pub async fn search_posts(
        &self,
        query: &str,
        page: i64,
        page_size: i64,
        include_private_boards: bool,
    ) -> anyhow::Result<(Vec<Post>, Vec<ThreadBrief>, i64)> {
        let page = page.max(1);
        let page_size = page_size.clamp(1, 100);
        let offset = (page - 1) * page_size;
        let normalized = query
            .chars()
            .filter(|c| !c.is_control())
            .take(1024)
            .collect::<String>();
        let q = normalized.trim();
        if q.is_empty() {
            return Ok((Vec::new(), Vec::new(), 0));
        }
        // Escape LIKE wildcards so plain input cannot become a pattern that
        // matches everything. Backslash is PostgreSQL's default LIKE escape.
        let pattern = format!("%{}%", escape_like_pattern(q));
        let total =
            // The statement is a compile-time constant plus bind parameters, so it is
        // safe to hand to sqlx as-is.
        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
            "{SEARCH_MATCHES} SELECT COUNT(*) FROM matches"
        )))
                .bind(include_private_boards)
                .bind(&pattern)
                .fetch_one(&self.pool)
                .await?;
        if total == 0 {
            return Ok((Vec::new(), Vec::new(), 0));
        }
        let rows = if total <= SEARCH_RANK_LIMIT {
            // Few matches: score every row and rank by relevance.
            let sql = format!(
                "{SEARCH_MATCHES} \
                 SELECT p.id,p.thread_id,p.board_id,p.author_id,p.is_anonymous,p.parent_post_id,\
                        p.content_md,p.content_html,p.created_at, \
                        COALESCE(u.username,'deleted') AS author_name, th.title, th.board_id AS th_board_id \
                 FROM matches m \
                 JOIN posts p ON p.id = m.post_id \
                 JOIN threads th ON th.id = p.thread_id \
                 JOIN boards b ON b.id = th.board_id \
                 LEFT JOIN users u ON u.id = p.author_id \
                 ORDER BY GREATEST(similarity(th.title,$3), similarity(p.content_md,$3)) DESC, p.id DESC \
                 LIMIT $4 OFFSET $5"
            );
            // Same here: `SEARCH_MATCHES` is a constant and every value is bound.
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(include_private_boards)
                .bind(&pattern)
                .bind(q)
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        } else {
            // A very common term: newest first, which the primary key index
            // satisfies by scanning backwards and stopping at the page size.
            let sql = "SELECT p.id,p.thread_id,p.board_id,p.author_id,p.is_anonymous,p.parent_post_id,\
                              p.content_md,p.content_html,p.created_at, \
                       COALESCE(u.username,'deleted') AS author_name, th.title, th.board_id AS th_board_id \
                FROM posts p \
                JOIN threads th ON th.id=p.thread_id \
                JOIN boards b ON b.id=th.board_id \
                LEFT JOIN users u ON u.id=p.author_id \
                WHERE p.deleted_at IS NULL AND th.deleted_at IS NULL AND ($1 OR b.guest_readable) \
                  AND (th.title ILIKE $2 ESCAPE '\\' OR p.content_md ILIKE $2 ESCAPE '\\') \
                ORDER BY p.id DESC LIMIT $3 OFFSET $4";
            sqlx::query(sql)
                .bind(include_private_boards)
                .bind(&pattern)
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        };
        let mut posts = Vec::with_capacity(rows.len());
        let mut map: std::collections::HashMap<i64, ThreadBrief> = std::collections::HashMap::new();
        for r in rows {
            let tid: i64 = r.get("thread_id");
            let title: String = r.get("title");
            let th_board: i64 = r.get("th_board_id");
            posts.push(Post {
                id: r.get("id"),
                thread_id: tid,
                board_id: r.get("board_id"),
                author_id: r.get("author_id"),
                is_anonymous: r.get::<bool, _>("is_anonymous"),
                parent_post_id: r.get::<Option<i64>, _>("parent_post_id"),
                content_md: r.get("content_md"),
                content_html: r.get("content_html"),
                created_at: r.get("created_at"),
                author_name: r.get::<String, _>("author_name"),
            });
            map.entry(tid).or_insert(ThreadBrief {
                id: tid,
                board_id: th_board,
                title,
            });
        }
        let threads: Vec<ThreadBrief> = map.into_values().collect();
        Ok((posts, threads, total))
    }

    // ---- threads — ported from Go internal/store/threads.go ----
    fn row_to_thread(row: &PgRow) -> anyhow::Result<Thread> {
        let last: DateTime<Utc> = row.get("last_reply_at");
        let created: DateTime<Utc> = row.get("created_at");
        Ok(Thread {
            id: row.get("id"),
            board_id: row.get("board_id"),
            title: row.get("title"),
            author_id: row.get("author_id"),
            is_pinned: row.get::<bool, _>("is_pinned"),
            is_locked: row.get::<bool, _>("is_locked"),
            reply_count: row.get("reply_count"),
            last_reply_at: last,
            created_at: created,
            author_name: row.get::<String, _>("author_name"),
            board_slug: row.get::<String, _>("board_slug"),
        })
    }

    /// CreateThread — 事务插入 threads+posts 首帖，对齐 Go: tx Begin→Insert thread→Insert post→Commit
    pub async fn create_thread(
        &self,
        board_id: i64,
        author_id: i64,
        title: &str,
        content_md: &str,
        content_html: &str,
        is_anonymous: bool,
    ) -> anyhow::Result<i64> {
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        let tid = sqlx::query_scalar::<_, i64>("INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id")
            .bind(board_id).bind(title).bind(author_id).bind(false).bind(false).bind(0i64).bind(now).bind(now)
            .fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(tid).bind(board_id).bind(author_id).bind(is_anonymous).bind(content_md).bind(content_html).bind(now)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(tid)
    }

    /// GetThread — author/board LEFT JOIN，COALESCE 已删用户/版块，对齐 Go
    pub async fn get_thread(&self, id: i64) -> anyhow::Result<Option<Thread>> {
        let row = sqlx::query(
            "SELECT th.id, th.board_id, th.title, th.author_id, th.is_pinned, th.is_locked, th.reply_count, th.last_reply_at, th.created_at, \
                    CASE WHEN EXISTS (SELECT 1 FROM posts op WHERE op.thread_id=th.id AND op.id=(SELECT MIN(op2.id) FROM posts op2 WHERE op2.thread_id=th.id) AND op.is_anonymous) THEN 'Anonymous' ELSE COALESCE(u.username,'deleted') END as author_name, COALESCE(b.slug,'') as board_slug \
             FROM threads th \
             LEFT JOIN users u ON u.id=th.author_id \
             LEFT JOIN boards b ON b.id=th.board_id \
             WHERE th.id=$1 AND th.deleted_at IS NULL"
        )
        .bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(Self::row_to_thread).transpose()
    }

    /// ListThreads — board_id 分页 + pinned/last_reply 排序，对齐 Go: ORDER BY is_pinned DESC, last_reply_at DESC, id DESC
    pub async fn list_threads(
        &self,
        board_id: i64,
        page: i64,
        page_size: i64,
    ) -> anyhow::Result<(Vec<Thread>, i64)> {
        let page = page.max(1);
        let page_size = page_size.clamp(1, 100);
        let offset = (page - 1) * page_size;
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM threads WHERE board_id=$1 AND deleted_at IS NULL")
                .bind(board_id)
                .fetch_one(&self.pool)
                .await?;
        let rows = sqlx::query(
            "SELECT th.id, th.board_id, th.title, th.author_id, th.is_pinned, th.is_locked, th.reply_count, th.last_reply_at, th.created_at, \
                    CASE WHEN EXISTS (SELECT 1 FROM posts op WHERE op.thread_id=th.id AND op.id=(SELECT MIN(op2.id) FROM posts op2 WHERE op2.thread_id=th.id) AND op.is_anonymous) THEN 'Anonymous' ELSE COALESCE(u.username,'deleted') END as author_name, COALESCE(b.slug,'') as board_slug \
             FROM threads th \
             LEFT JOIN users u ON u.id=th.author_id \
             LEFT JOIN boards b ON b.id=th.board_id \
             WHERE th.board_id=$1 AND th.deleted_at IS NULL \
             ORDER BY th.is_pinned DESC, th.last_reply_at DESC, th.id DESC \
             LIMIT $2 OFFSET $3"
        )
        .bind(board_id).bind(page_size).bind(offset)
        .fetch_all(&self.pool).await?;
        Ok((
            rows.iter()
                .map(Self::row_to_thread)
                .collect::<anyhow::Result<Vec<_>>>()?,
            total.0,
        ))
    }

    /// SetThreadPinned — UPDATE threads SET is_pinned=?
    pub async fn set_thread_pinned(&self, id: i64, pinned: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE threads SET is_pinned=$1 WHERE id=$2")
            .bind(pinned)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// SetThreadLocked — UPDATE threads SET is_locked=?
    pub async fn set_thread_locked(&self, id: i64, locked: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE threads SET is_locked=$1 WHERE id=$2")
            .bind(locked)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// DeleteThread — DELETE FROM threads WHERE id=? (posts CASCADE via FK)
    pub async fn delete_thread(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM threads WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn soft_delete_thread(
        &self,
        id: i64,
        deleted_by_user_id: Option<i64>,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE threads SET deleted_at=$1, deleted_by_user_id=$2 WHERE id=$3 AND deleted_at IS NULL")
            .bind(Utc::now()).bind(deleted_by_user_id).bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn restore_thread(&self, id: i64) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE threads SET deleted_at=NULL, deleted_by_user_id=NULL WHERE id=$1 AND deleted_at IS NOT NULL")
            .bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn list_deleted_threads(&self, limit: i64) -> anyhow::Result<Vec<Thread>> {
        let rows = sqlx::query(
            "SELECT th.id,th.board_id,th.title,th.author_id,th.is_pinned,th.is_locked,th.reply_count,th.last_reply_at,th.created_at, \
                    CASE WHEN EXISTS (SELECT 1 FROM posts op WHERE op.thread_id=th.id AND op.id=(SELECT MIN(op2.id) FROM posts op2 WHERE op2.thread_id=th.id) AND op.is_anonymous) THEN 'Anonymous' ELSE COALESCE(u.username,'deleted') END AS author_name,COALESCE(b.slug,'') AS board_slug \
             FROM threads th LEFT JOIN users u ON u.id=th.author_id LEFT JOIN boards b ON b.id=th.board_id \
             WHERE th.deleted_at IS NOT NULL ORDER BY th.deleted_at DESC,th.id DESC LIMIT $1",
        )
        .bind(limit.clamp(1, 200))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::row_to_thread).collect()
    }

    // ---- invite_codes — ported from Go internal/store/invite.go ----
    pub async fn create_invite(&self, code: &str, created_by: i64) -> anyhow::Result<()> {
        self.create_invite_with_options(code, created_by, 1, None, "")
            .await
    }
    pub async fn create_invite_with_options(
        &self,
        code: &str,
        created_by: i64,
        max_uses: i64,
        expires_at: Option<&str>,
        note: &str,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        sqlx::query("INSERT INTO invite_codes(code,created_by,created_at,max_uses,expires_at,note) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(code)
            .bind(created_by)
            .bind(now)
            .bind(max_uses.clamp(1, 100000))
            .bind(expires_at)
            .bind(note)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn use_invite(&self, code: &str, used_by: i64) -> anyhow::Result<()> {
        let now = Utc::now();
        let res = sqlx::query(
            "UPDATE invite_codes SET used_by=COALESCE(used_by,$1), used_at=$2, use_count=use_count+1 WHERE code=$3 AND revoked_at IS NULL AND use_count < max_uses AND (expires_at IS NULL OR expires_at > $4)",
        )
        .bind(used_by)
        .bind(now)
        .bind(code)
        .bind(now)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            anyhow::bail!("invite invalid or already used");
        }
        Ok(())
    }
    pub async fn register_with_invite(
        &self,
        username: &str,
        hash: &str,
        code: &str,
    ) -> anyhow::Result<i64> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();
        let uid = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES($1,$2,FALSE,$3) RETURNING id",
        )
        .bind(username)
        .bind(hash)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        let used = sqlx::query(
            "UPDATE invite_codes SET used_by=COALESCE(used_by,$1), used_at=$2, use_count=use_count+1 WHERE code=$3 AND revoked_at IS NULL AND use_count < max_uses AND (expires_at IS NULL OR expires_at > $4)",
        )
        .bind(uid)
        .bind(now)
        .bind(code)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if used.rows_affected() != 1 {
            tx.rollback().await?;
            anyhow::bail!("invite invalid or already used");
        }
        tx.commit().await?;
        Ok(uid)
    }
    pub async fn invite_exists(&self, code: &str) -> anyhow::Result<bool> {
        let row =
            sqlx::query("SELECT 1 as avail FROM invite_codes WHERE code=$1 AND revoked_at IS NULL AND use_count < max_uses AND (expires_at IS NULL OR expires_at > now())")
                .bind(code)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }
    pub async fn list_invites(&self) -> anyhow::Result<Vec<InviteCode>> {
        let rows = sqlx::query("SELECT code,created_by,used_by,created_at,used_at,max_uses,use_count,expires_at,revoked_at,revoked_by,note FROM invite_codes ORDER BY created_at DESC")
            .fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let created: DateTime<Utc> = r.get("created_at");
            let used: Option<DateTime<Utc>> = r.get("used_at");
            out.push(InviteCode {
                code: r.get("code"),
                created_by: r.get("created_by"),
                used_by: r.get("used_by"),
                created_at: created,
                used_at: used,
                max_uses: r.get("max_uses"),
                use_count: r.get("use_count"),
                expires_at: r.get("expires_at"),
                revoked_at: r.get("revoked_at"),
                revoked_by: r.get("revoked_by"),
                note: r.get("note"),
            });
        }
        Ok(out)
    }
    pub async fn delete_invite(&self, code: &str) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE invite_codes SET revoked_at=now() WHERE code=$1 AND revoked_at IS NULL",
        )
        .bind(code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    pub async fn revoke_invite(&self, code: &str, revoked_by: i64) -> anyhow::Result<()> {
        sqlx::query("UPDATE invite_codes SET revoked_at=now(), revoked_by=$1 WHERE code=$2 AND revoked_at IS NULL")
            .bind(revoked_by)
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- sessions (merged from r03) ----
    pub async fn create_session(&self, user_id: i64) -> anyhow::Result<String> {
        use rand::Rng;
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        let id = hex::encode(b);
        let now = Utc::now();
        let exp = now + chrono::Duration::hours(30 * 24);
        sqlx::query(
            "INSERT INTO sessions(id,user_id,created_at,expires_at,last_seen_at) VALUES($1,$2,$3,$4,$5)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(now)
        .bind(exp)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }
    pub async fn get_session(&self, id: &str) -> anyhow::Result<Option<Session>> {
        let row = sqlx::query("SELECT s.id,s.user_id,s.created_at,s.expires_at,s.last_seen_at, u.username, u.is_banned FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1")
            .bind(id).fetch_optional(&self.pool).await?;
        if let Some(r) = row {
            let created: DateTime<Utc> = r.get("created_at");
            let exp: DateTime<Utc> = r.get("expires_at");
            let last_seen: Option<DateTime<Utc>> = r.get("last_seen_at");
            let is_banned: bool = r.get("is_banned");
            let sess = Session {
                id: r.get("id"),
                user_id: r.get("user_id"),
                created_at: created,
                expires_at: exp,
                last_seen_at: last_seen,
            };
            let now = Utc::now();
            if now > sess.expires_at
                || sess
                    .last_seen_at
                    .is_none_or(|seen| now - seen > chrono::Duration::hours(12))
                || is_banned
            {
                let _ = self.delete_session(id).await;
                return Ok(None);
            }
            let _ = sqlx::query("UPDATE sessions SET last_seen_at=$1 WHERE id=$2")
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await;
            return Ok(Some(sess));
        }
        Ok(None)
    }
    pub async fn delete_session(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn delete_sessions_by_user(&self, user_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id=$1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn list_sessions_by_user(&self, user_id: i64) -> anyhow::Result<Vec<Session>> {
        let rows = sqlx::query("SELECT id,user_id,created_at,expires_at,last_seen_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC")
            .bind(user_id).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(Session {
                    id: r.get("id"),
                    user_id: r.get("user_id"),
                    created_at: r.get("created_at"),
                    expires_at: r.get("expires_at"),
                    last_seen_at: r.get("last_seen_at"),
                })
            })
            .collect()
    }
    pub async fn count_sessions_by_user(&self, user_id: i64) -> anyhow::Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }
    pub async fn delete_expired_sessions(&self) -> anyhow::Result<u64> {
        let now = Utc::now();
        Ok(
            sqlx::query("DELETE FROM sessions WHERE expires_at <= $1 OR last_seen_at <= $2")
                .bind(now)
                .bind(Utc::now() - chrono::Duration::hours(12))
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }
    /// GetUserBySession: join users.banned 检查，封禁则删除并返回错误（对齐 Go sqlErrBanned）
    pub async fn get_user_by_session(&self, id: &str) -> anyhow::Result<Option<User>> {
        let session = match self.get_session(id).await? {
            Some(s) => s,
            None => return Ok(None),
        };
        self.get_user_by_id(session.user_id).await
    }

    // ---- TOTP second factor -------------------------------------------------

    /// Current TOTP state for a user, including how many recovery codes are
    /// still unused.
    pub async fn totp_state(&self, user_id: i64) -> anyhow::Result<TotpState> {
        let row = sqlx::query(
            "SELECT totp_secret, totp_activated_at, totp_last_step, totp_pending_secret, \
                    totp_pending_created_at, \
                    (SELECT COUNT(*) FROM totp_recovery_codes c \
                      WHERE c.user_id = u.id AND c.used_at IS NULL) AS unused_codes \
             FROM users u WHERE id=$1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            anyhow::bail!("user {user_id} not found");
        };
        Ok(TotpState {
            secret: row.get("totp_secret"),
            activated_at: row.get("totp_activated_at"),
            last_step: row.get("totp_last_step"),
            pending_secret: row.get("totp_pending_secret"),
            pending_created_at: row.get("totp_pending_created_at"),
            unused_recovery_codes: row.get("unused_codes"),
        })
    }

    /// Store an enrolment secret that is not active until a code proves the user
    /// can read it.
    pub async fn set_totp_pending(&self, user_id: i64, secret: &str) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE users SET totp_pending_secret=$1, totp_pending_created_at=$2 WHERE id=$3",
        )
        .bind(secret)
        .bind(Utc::now())
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Discard an unconfirmed enrolment.
    pub async fn clear_totp_pending(&self, user_id: i64) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE users SET totp_pending_secret=NULL, totp_pending_created_at=NULL WHERE id=$1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Promote a pending secret to the active second factor.
    pub async fn activate_totp(&self, user_id: i64, secret: &str, step: i64) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE users SET totp_secret=$1, totp_activated_at=$2, totp_last_step=$3, \
                    totp_pending_secret=NULL, totp_pending_created_at=NULL WHERE id=$4",
        )
        .bind(secret)
        .bind(Utc::now())
        .bind(step)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove the second factor and all of its recovery codes.
    pub async fn disable_totp(&self, user_id: i64) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE users SET totp_secret=NULL, totp_activated_at=NULL, totp_last_step=NULL, \
                    totp_pending_secret=NULL, totp_pending_created_at=NULL WHERE id=$1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Claim a time step for a code that just verified.
    ///
    /// The update is conditional, so two concurrent logins cannot both accept
    /// the same code: only the caller whose write actually moved the column
    /// forward may continue, and a late writer can never move it backwards.
    pub async fn claim_totp_step(&self, user_id: i64, step: i64) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE users SET totp_last_step=$1 \
             WHERE id=$2 AND (totp_last_step IS NULL OR totp_last_step < $1)",
        )
        .bind(step)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Failed second-factor attempts for one account since an instant.
    ///
    /// The per-request cap alone bounds guessing per pending login; this bounds
    /// it per account, so a password holder cannot keep opening new attempts at
    /// the global authentication rate.
    pub async fn recent_failed_totp_attempts(
        &self,
        user_id: i64,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(attempts), 0) FROM pending_logins \
             WHERE user_id=$1 AND created_at > $2",
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Replace every recovery code with a new set of hashes.
    pub async fn replace_recovery_codes(
        &self,
        user_id: i64,
        hashes: &[String],
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for hash in hashes {
            sqlx::query(
                "INSERT INTO totp_recovery_codes(user_id,code_hash,created_at) VALUES($1,$2,$3)",
            )
            .bind(user_id)
            .bind(hash)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Consume a recovery code. Single use is enforced by the `used_at IS NULL`
    /// predicate, so two concurrent logins cannot both succeed.
    pub async fn consume_recovery_code(
        &self,
        user_id: i64,
        code_hash: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE totp_recovery_codes SET used_at=$1 \
             WHERE user_id=$2 AND code_hash=$3 AND used_at IS NULL",
        )
        .bind(Utc::now())
        .bind(user_id)
        .bind(code_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Start the window between the password step and the second factor.
    pub async fn create_pending_login(&self, user_id: i64) -> anyhow::Result<String> {
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let id = hex::encode(bytes);
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(PENDING_LOGIN_TTL_SECONDS);
        // Housekeeping: drop this user's stale attempts before adding one.
        sqlx::query("DELETE FROM pending_logins WHERE user_id=$1 AND expires_at <= $2")
            .bind(user_id)
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO pending_logins(id,user_id,created_at,expires_at,attempts) \
             VALUES($1,$2,$3,$4,0)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(now)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Look up a still-usable pending login. Returns `None` once it is consumed,
    /// expired, or out of attempts.
    pub async fn pending_login(&self, id: &str) -> anyhow::Result<Option<PendingLogin>> {
        let row = sqlx::query(
            "SELECT id, user_id, created_at, expires_at, attempts FROM pending_logins \
             WHERE id=$1 AND consumed_at IS NULL AND expires_at > $2 AND attempts < $3",
        )
        .bind(id)
        .bind(Utc::now())
        .bind(PENDING_LOGIN_MAX_ATTEMPTS)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PendingLogin {
            id: r.get("id"),
            user_id: r.get("user_id"),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            attempts: r.get("attempts"),
        }))
    }

    /// Count a failed second-factor attempt and return the new total.
    pub async fn fail_pending_login(&self, id: &str) -> anyhow::Result<i64> {
        let attempts: Option<(i64,)> = sqlx::query_as(
            "UPDATE pending_logins SET attempts=attempts+1 WHERE id=$1 RETURNING attempts",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(attempts.map(|(value,)| value).unwrap_or(0))
    }

    /// Finish a pending login exactly once.
    pub async fn consume_pending_login(&self, id: &str, user_id: i64) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE pending_logins SET consumed_at=$1 \
             WHERE id=$2 AND user_id=$3 AND consumed_at IS NULL",
        )
        .bind(Utc::now())
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Remove expired pending logins.
    pub async fn delete_expired_pending_logins(&self) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM pending_logins WHERE expires_at <= $1")
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every credential form sqlx accepts must lose its password before the
    /// string can reach a log line or an error message.
    #[test]
    fn passwords_are_redacted_from_every_connection_string_form() {
        for (input, expected) in [
            (
                "postgres://user:hunter2@127.0.0.1:5432/db",
                "postgres://user:***@127.0.0.1:5432/db",
            ),
            // A password containing '@': the last '@' is the separator.
            (
                "postgres://user:p@ss@127.0.0.1:5432/db",
                "postgres://user:***@127.0.0.1:5432/db",
            ),
            // Query parameter form.
            (
                "postgres:///db?host=/var/run/postgresql&password=hunter2",
                "postgres:///db?host=/var/run/postgresql&password=***",
            ),
            // libpq keyword/value form, password first and in the middle.
            (
                "password=hunter2 host=127.0.0.1 user=u",
                "password=*** host=127.0.0.1 user=u",
            ),
            (
                "host=127.0.0.1 password=hunter2 user=u dbname=x",
                "host=127.0.0.1 password=*** user=u dbname=x",
            ),
            // Quoted keyword value with a space inside.
            (
                "host=h password='two words' user=u",
                "host=h password=*** user=u",
            ),
            // Already redacted stays redacted.
            ("postgres://u:***@h/db", "postgres://u:***@h/db"),
            // No credential at all is left alone, including lookalike keys.
            (
                "postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum",
                "postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum",
            ),
            ("host=h mypassword=x user=u", "host=h mypassword=x user=u"),
        ] {
            assert_eq!(redact_database_url(input), expected, "input: {input}");
        }
    }

    /// The scan must always make progress: a repeated key cannot hang it.
    #[test]
    fn redaction_terminates_on_repeated_keys() {
        assert_eq!(
            redact_database_url("password=password=password=x"),
            "password=***"
        );
        assert_eq!(redact_database_url("password="), "password=***");
    }

    /// `sqlx::test` provisions a fresh database with `migrations/` applied.
    /// Seeding is done here because first-run defaults live in the store, not
    /// in the schema.
    async fn test_store(pool: PgPool) -> anyhow::Result<Store> {
        let store = Store { pool };
        store.seed_defaults().await?;
        Ok(store)
    }

    async fn add_user(pool: &PgPool, username: &str, is_admin: bool) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES($1,$2,$3,$4) RETURNING id",
        )
        .bind(username)
        .bind("hash")
        .bind(is_admin)
        .bind(Utc::now())
        .fetch_one(pool)
        .await?)
    }

    async fn add_thread(
        pool: &PgPool,
        board_id: i64,
        author_id: i64,
        title: &str,
    ) -> anyhow::Result<i64> {
        let now = Utc::now();
        Ok(sqlx::query_scalar::<_, i64>(
            "INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) \
             VALUES($1,$2,$3,FALSE,FALSE,0,$4,$4) RETURNING id",
        )
        .bind(board_id)
        .bind(title)
        .bind(author_id)
        .bind(now)
        .fetch_one(pool)
        .await?)
    }

    #[sqlx::test]
    async fn test_posts_crud_and_search(pool: PgPool) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let uid = add_user(&s.pool, "alice", false).await?;
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        let tid = add_thread(&s.pool, bid.0, uid, "hello world").await?;
        let pid1 = s
            .create_post(tid, bid.0, uid, false, "first post **md**", "<p>first</p>")
            .await?;
        let pid2 = s
            .create_post(
                tid,
                bid.0,
                uid,
                true,
                "anonymous reply secret",
                "<p>anon</p>",
            )
            .await?;
        let rc: (i64,) = sqlx::query_as("SELECT reply_count FROM threads WHERE id=$1")
            .bind(tid)
            .fetch_one(&s.pool)
            .await?;
        assert_eq!(rc.0, 2);
        let (posts, total) = s.list_posts(tid, 1, 10).await?;
        assert_eq!(total, 2);
        assert_eq!(posts[0].content_md, "first post **md**");
        assert_eq!(posts[0].author_name, "alice");
        assert!(posts[1].is_anonymous);
        let (p2, _) = s.list_posts(tid, 2, 1).await?;
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].id, pid2);
        s.delete_post(pid2).await?;
        let rc_after_delete: (i64,) = sqlx::query_as("SELECT reply_count FROM threads WHERE id=$1")
            .bind(tid)
            .fetch_one(&s.pool)
            .await?;
        assert_eq!(rc_after_delete.0, 1);
        let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts WHERE thread_id=$1")
            .bind(tid)
            .fetch_one(&s.pool)
            .await?;
        assert_eq!(remaining.0, 1);
        let gp = s.get_post(pid1).await?.unwrap();
        assert_eq!(gp.id, pid1);

        let pid3 = s
            .create_post(
                tid,
                bid.0,
                uid,
                false,
                "trigram search banana",
                "<p>banana</p>",
            )
            .await?;
        let (hits, threads, total) = s.search_posts("banana", 1, 10, true).await?;
        assert_eq!(total, 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, pid3);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].title, "hello world");

        // Shorter than a full trigram: still matched, via the sequential path.
        let (short_hits, _, short_total) = s.search_posts("ba", 1, 10, true).await?;
        assert_eq!(short_total, 1);
        assert_eq!(short_hits[0].id, pid3);

        // Chinese substring search, which the trigram index serves directly.
        let zh = s
            .create_post(tid, bid.0, uid, false, "中文检索测试内容", "<p>zh</p>")
            .await?;
        let (zh_hits, _, zh_total) = s.search_posts("检索测试", 1, 10, true).await?;
        assert_eq!(zh_total, 1);
        assert_eq!(zh_hits[0].id, zh);

        // A single-character query still matches; page size is clamped to 100.
        let (bounded_hits, _, bounded_total) = s.search_posts("a", 1, 10_000, true).await?;
        assert_eq!(bounded_total, 1);
        assert_eq!(bounded_hits.len(), 1);
        assert_eq!(bounded_hits[0].id, pid3);

        // A page past the last match still reports the real total.
        let (late_hits, _, late_total) = s.search_posts("banana", 2, 10_000, true).await?;
        assert_eq!(late_total, 1);
        assert!(late_hits.is_empty());

        let (empty_hits, empty_threads, empty_total) = s.search_posts("  ", 1, 1000, true).await?;
        assert!(empty_hits.is_empty());
        assert!(empty_threads.is_empty());
        assert_eq!(empty_total, 0);

        s.delete_post(pid1).await?;
        assert!(s.get_post(pid1).await?.is_none());
        let (hits3, _, _) = s.search_posts("first", 1, 10, true).await?;
        assert!(hits3.is_empty());
        Ok(())
    }

    #[sqlx::test]
    async fn search_treats_wildcards_literally(pool: PgPool) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let uid = add_user(&s.pool, "alice", false).await?;
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        let tid = add_thread(&s.pool, bid.0, uid, "pricing thread").await?;
        s.create_post(
            tid,
            bid.0,
            uid,
            false,
            "discount is 50% today",
            "<p>50%</p>",
        )
        .await?;
        s.create_post(tid, bid.0, uid, false, "unrelated body", "<p>x</p>")
            .await?;

        // `%` and `_` are escaped, so they match literally instead of matching
        // everything.
        let (hits, _, total) = s.search_posts("50%", 1, 10, true).await?;
        assert_eq!(total, 1);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].content_md.contains("50%"));

        // `%` matches the post that contains a literal percent sign, and only
        // that post: without escaping it would match every row.
        let (wild, _, wild_total) = s.search_posts("%", 1, 10, true).await?;
        assert_eq!(wild_total, 1, "escaped % must match literally");
        assert_eq!(wild.len(), 1);
        assert!(wild[0].content_md.contains("50%"));

        let (under, _, under_total) = s.search_posts("_", 1, 10, true).await?;
        assert_eq!(
            under_total, 0,
            "escaped _ must not match any single character"
        );
        assert!(under.is_empty());
        Ok(())
    }

    #[sqlx::test]
    async fn search_hides_non_guest_readable_boards_from_visitors(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let user_id = add_user(&s.pool, "searcher", false).await?;
        let private_board = s
            .create_board("private", "Private", "restricted", false, false)
            .await?;
        s.create_thread(
            private_board,
            user_id,
            "private audit marker",
            "private audit marker",
            "<p>private audit marker</p>",
            false,
        )
        .await?;

        let (visitor_hits, _, visitor_total) =
            s.search_posts("private audit marker", 1, 20, false).await?;
        assert_eq!(visitor_total, 0);
        assert!(visitor_hits.is_empty());

        let (member_hits, _, member_total) =
            s.search_posts("private audit marker", 1, 20, true).await?;
        assert_eq!(member_total, 1);
        assert_eq!(member_hits.len(), 1);
        Ok(())
    }

    #[sqlx::test]
    async fn test_invite_registration_is_atomic_and_single_use(pool: PgPool) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let admin = add_user(&s.pool, "admin", true).await?;
        sqlx::query("INSERT INTO invite_codes(code,created_by,created_at) VALUES($1,$2,$3)")
            .bind("one-use")
            .bind(admin)
            .bind(Utc::now())
            .execute(&s.pool)
            .await?;

        let first = s.register_with_invite("alice", "hash", "one-use").await?;
        assert!(first > 0);
        assert!(s
            .register_with_invite("bob", "hash", "one-use")
            .await
            .is_err());
        assert!(s.get_user_by_username("bob").await?.is_none());
        assert!(s
            .register_with_invite("carol", "hash", "missing")
            .await
            .is_err());
        assert!(s.get_user_by_username("carol").await?.is_none());
        Ok(())
    }

    #[sqlx::test]
    async fn test_session_absolute_and_idle_expiry_are_enforced(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let uid = add_user(&s.pool, "alice", false).await?;

        let absolute = s.create_session(uid).await?;
        sqlx::query("UPDATE sessions SET expires_at=$1 WHERE id=$2")
            .bind(Utc::now() - chrono::Duration::seconds(1))
            .bind(&absolute)
            .execute(&s.pool)
            .await?;
        assert!(s.get_user_by_session(&absolute).await?.is_none());
        assert!(sqlx::query("SELECT 1 FROM sessions WHERE id=$1")
            .bind(&absolute)
            .fetch_optional(&s.pool)
            .await?
            .is_none());

        let idle = s.create_session(uid).await?;
        sqlx::query("UPDATE sessions SET last_seen_at=$1 WHERE id=$2")
            .bind(Utc::now() - chrono::Duration::hours(12) - chrono::Duration::seconds(1))
            .bind(&idle)
            .execute(&s.pool)
            .await?;
        assert!(s.get_user_by_session(&idle).await?.is_none());
        Ok(())
    }

    #[sqlx::test]
    async fn test_anonymous_thread_author_is_hidden_in_detail_and_listing(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let uid = add_user(&s.pool, "alice", false).await?;
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        let tid = add_thread(&s.pool, bid.0, uid, "private title").await?;
        s.create_post(tid, bid.0, uid, true, "anonymous", "<p>anonymous</p>")
            .await?;
        s.create_post(tid, bid.0, uid, false, "named reply", "<p>reply</p>")
            .await?;

        assert_eq!(
            s.get_thread(tid).await?.expect("thread").author_name,
            "Anonymous"
        );
        assert_eq!(
            s.list_threads(bid.0, 1, 10).await?.0[0].author_name,
            "Anonymous"
        );
        Ok(())
    }

    #[sqlx::test]
    async fn test_thread_listing_uses_complete_order_index(pool: PgPool) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let uid = add_user(&s.pool, "alice", false).await?;
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        // Enough rows that the planner prefers the ordering index over a sort.
        sqlx::query(
            "INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) \
             SELECT $1, 'thread '||g, $2, FALSE, FALSE, 0, now() - (g || ' seconds')::interval, now() \
             FROM generate_series(1, 500) g",
        )
        .bind(bid.0)
        .bind(uid)
        .execute(&s.pool)
        .await?;

        // This mirrors the board listing query. PostgreSQL must reach the rows
        // through an index that also provides the complete ordering, so the
        // plan must not contain a sort node. Sequence scans are disabled so the
        // assertion tests index coverage rather than table size, and statistics
        // are refreshed so the plan does not depend on default estimates.
        sqlx::query("ANALYZE threads").execute(&s.pool).await?;
        let mut tx = s.pool.begin().await?;
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "EXPLAIN SELECT th.id FROM threads th WHERE th.board_id=$1 AND th.deleted_at IS NULL \
             ORDER BY th.is_pinned DESC, th.last_reply_at DESC, th.id DESC LIMIT $2 OFFSET $3",
        )
        .bind(bid.0)
        .bind(20_i64)
        .bind(0_i64)
        .fetch_all(&mut *tx)
        .await?;
        tx.rollback().await?;
        let plan = rows
            .into_iter()
            .map(|row| row.0)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains("idx_threads"), "plan: {plan}");
        assert!(!plan.contains("Sort"), "unexpected sort node: {plan}");
        Ok(())
    }

    #[sqlx::test]
    async fn search_plan_uses_trigram_index(pool: PgPool) -> anyhow::Result<()> {
        let s = test_store(pool).await?;
        let uid = add_user(&s.pool, "alice", false).await?;
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        let tid = add_thread(&s.pool, bid.0, uid, "index probe").await?;
        for i in 0..200 {
            s.create_post(
                tid,
                bid.0,
                uid,
                false,
                &format!("filler body number {i} with distinctive tokens"),
                "<p>filler</p>",
            )
            .await?;
        }
        // The planner needs statistics for the trigram index to be chosen.
        sqlx::query("ANALYZE posts").execute(&s.pool).await?;
        let mut tx = s.pool.begin().await?;
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "EXPLAIN SELECT p.id FROM posts p WHERE p.content_md ILIKE $1 ESCAPE '\\'",
        )
        .bind("%distinctive tokens%")
        .fetch_all(&mut *tx)
        .await?;
        tx.rollback().await?;
        let plan = rows
            .into_iter()
            .map(|row| row.0)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains("idx_posts_content_trgm"), "plan: {plan}");
        Ok(())
    }

    #[test]
    fn test_redact_database_url_removes_password() {
        assert_eq!(
            redact_database_url("postgres://veil:secret@localhost:5432/veil_forum"),
            "postgres://veil:***@localhost:5432/veil_forum"
        );
        assert_eq!(
            redact_database_url("postgres://veil_forum?host=/var/run/postgresql"),
            "postgres://veil_forum?host=/var/run/postgresql"
        );
        assert_eq!(
            redact_database_url("postgres:///veil?host=/run&password=hunter2&user=x"),
            "postgres:///veil?host=/run&password=***&user=x"
        );
    }

    #[test]
    fn test_escape_like_pattern() {
        assert_eq!(escape_like_pattern("50%"), "50\\%");
        assert_eq!(escape_like_pattern("a_b"), "a\\_b");
        assert_eq!(escape_like_pattern("c:\\tmp"), "c:\\\\tmp");
        assert_eq!(escape_like_pattern("plain"), "plain");
    }
}
