use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub struct Store {
    pub pool: SqlitePool,
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
    pub last_seen_at: DateTime<Utc>,
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

/// 统一 RFC3339/RFC3339Nano 双格式解析
/// 先试 RFC3339Nano 再回落 RFC3339，兼容 Go `time.RFC3339Nano` / `time.RFC3339` 写入的两种格式
pub fn parse_time(s: &str) -> DateTime<Utc> {
    let s = s.trim();
    // 1) RFC3339Nano: chrono::DateTime::parse_from_rfc3339 已支持纳秒（fractional 秒可选），等价 Go time.RFC3339Nano
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.with_timezone(&Utc);
    }
    // 2) 兜底兼容带纳秒的 Z 格式（与 parse_from_rfc3339 互补，覆盖 "%Y-%m-%dT%H:%M:%S%.fZ"）
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
        return dt.and_utc();
    }
    // 3) 回落 RFC3339: 显式尝试不带纳秒的 RFC3339 变体（Go time.RFC3339），处理 Z 后缀的朴素时间
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
        return dt.and_utc();
    }
    // 4) 兼容遗留 SQLite 文本格式（无 T、无时区）—— 含纳秒变体
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return dt.and_utc();
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return dt.and_utc();
    }
    // 5) 空格 + Z 变体（极少数遗留）
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.fZ") {
        return dt.and_utc();
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%SZ") {
        return dt.and_utc();
    }
    Utc::now()
}

// 保留旧名兼容，内部统一委托 parse_time
#[allow(dead_code)]
fn parse_dt(s: &str) -> DateTime<Utc> {
    parse_time(s)
}

#[derive(Debug, Clone)]
pub struct InviteCode {
    pub code: String,
    pub created_by: i64,
    pub used_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

impl Store {
    pub async fn open(path: &str) -> anyhow::Result<Self> {
        let url = format!("sqlite:{}?mode=rwc", path);
        let pool = SqlitePool::connect(&url).await?;
        #[cfg(unix)]
        if !path.starts_with(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let s = Self { pool };
        let _ = sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&s.pool)
            .await;
        let _ = sqlx::query("PRAGMA foreign_keys=ON").execute(&s.pool).await;
        let _ = sqlx::query("PRAGMA busy_timeout=5000")
            .execute(&s.pool)
            .await;
        s.migrate().await?;
        s.seed_defaults().await?;
        Ok(s)
    }
    async fn migrate(&self) -> anyhow::Result<()> {
        // 001_init.sql: 全部为 CREATE IF NOT EXISTS / TRIGGER IF NOT EXISTS / INDEX IF NOT EXISTS，天然幂等，与 Go 的 migrate 行为一致
        sqlx::raw_sql(include_str!("../migrations/001_init.sql"))
            .execute(&self.pool)
            .await?;
        // 002_i18n.sql: 依次执行 ALTER ADD COLUMN locale / name_i18n + INSERT default_locale
        // 幂等性：INSERT 使用 OR IGNORE；ALTER 需容忍重复列（duplicate column / already exists），重复执行不报错
        // raw_sql 多语句批量在中间 ALTER duplicate 时会中断，故逐条执行并单独容错，确保与 Go 的逐条 Exec 语义一致
        for stmt in include_str!("../migrations/002_i18n.sql").split(';') {
            let sql = stmt.trim();
            if sql.is_empty() {
                continue;
            }
            if let Err(e) = sqlx::query(sql).execute(&self.pool).await {
                let msg = e.to_string().to_lowercase();
                if msg.contains("duplicate column")
                    || msg.contains("already exists")
                    || msg.contains("duplicate")
                {
                    continue;
                }
                return Err(anyhow::anyhow!("migrate 002 failed: {} stmt={:?}", e, sql));
            }
        }
        // 003_parent.sql: posts.parent_post_id 楼中楼
        for stmt in include_str!("../migrations/003_parent.sql").split(';') {
            let sql = stmt.trim();
            if sql.is_empty() {
                continue;
            }
            if let Err(e) = sqlx::query(sql).execute(&self.pool).await {
                let msg = e.to_string().to_lowercase();
                if msg.contains("duplicate column")
                    || msg.contains("already exists")
                    || msg.contains("duplicate")
                {
                    continue;
                }
                return Err(anyhow::anyhow!("migrate 003 failed: {} stmt={:?}", e, sql));
            }
        }
        // 004_security.sql: idle sessions and audit log. ALTER is intentionally idempotent.
        for stmt in include_str!("../migrations/004_security.sql").split(';') {
            let sql = stmt.trim();
            if sql.is_empty() {
                continue;
            }
            if let Err(e) = sqlx::query(sql).execute(&self.pool).await {
                let msg = e.to_string().to_lowercase();
                if msg.contains("duplicate column")
                    || msg.contains("already exists")
                    || msg.contains("duplicate")
                {
                    continue;
                }
                return Err(anyhow::anyhow!("migrate 004 failed: {} stmt={:?}", e, sql));
            }
        }
        for stmt in include_str!("../migrations/005_default_english.sql").split(';') {
            let sql = stmt.trim();
            if sql.is_empty() {
                continue;
            }
            sqlx::query(sql).execute(&self.pool).await?;
        }
        for stmt in include_str!("../migrations/006_default_board_english.sql").split(';') {
            let sql = stmt.trim();
            if !sql.is_empty() {
                sqlx::query(sql).execute(&self.pool).await?;
            }
        }
        Ok(())
    }
    async fn seed_defaults(&self) -> anyhow::Result<()> {
        let defaults = [
            ("pow_register_minutes", "0.02"),
            ("pow_login_minutes", "0.02"),
            ("pow_post_minutes", "0.02"),
            ("registration_mode", "invite"),
            ("site_name", "secure-forum"),
        ];
        for (k, v) in defaults {
            sqlx::query("INSERT OR IGNORE INTO configs(key,value) VALUES(?,?)")
                .bind(k)
                .bind(v)
                .execute(&self.pool)
                .await?;
        }
        sqlx::query("INSERT OR IGNORE INTO configs(key,value) VALUES(?,?)")
            .bind("default_locale")
            .bind("en")
            .execute(&self.pool)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boards")
            .fetch_one(&self.pool)
            .await?;
        if cnt.0 == 0 {
            sqlx::query("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES(?,?,?,?,?,?)")
                .bind("general").bind("General").bind("General discussion").bind(1).bind(1).bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true))
                .execute(&self.pool).await?;
        }
        Ok(())
    }
    /// GetConfig — 对齐 Go `(string,error)` 语义：
    /// - not-found: Go 返回 sql.ErrNoRows; Rust 返回 Ok(None)（调用方可 fallback 到默认值）
    /// - DB 错误: Go 返回 error; Rust 返回 Err(anyhow)
    /// 旧签名 `Option<String>` 会吞掉 DB 错误（`.ok().flatten()`），现改为 `Result<Option>` 以与 Go 一致可区分错误与缺失。
    pub async fn get_config(&self, key: &str) -> anyhow::Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM configs WHERE key=?")
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
        sqlx::query("INSERT INTO configs(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key).bind(val).execute(&self.pool).await?;
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
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let res = sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,?,?)",
        )
        .bind(username)
        .bind(hash)
        .bind(if is_admin { 1 } else { 0 })
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }
    pub async fn get_user_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        let row = sqlx::query("SELECT id,username,password_hash,is_admin,is_banned,created_at FROM users WHERE username=?")
            .bind(username).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| {
            let created: String = r.get("created_at");
            User {
                id: r.get("id"),
                username: r.get("username"),
                password_hash: r.get("password_hash"),
                is_admin: r.get::<i64, _>("is_admin") == 1,
                is_banned: r.get::<i64, _>("is_banned") == 1,
                created_at: parse_time(&created),
            }
        }))
    }
    pub async fn get_user_by_id(&self, id: i64) -> anyhow::Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id,username,password_hash,is_admin,is_banned,created_at FROM users WHERE id=?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let created: String = r.get("created_at");
            User {
                id: r.get("id"),
                username: r.get("username"),
                password_hash: r.get("password_hash"),
                is_admin: r.get::<i64, _>("is_admin") == 1,
                is_banned: r.get::<i64, _>("is_banned") == 1,
                created_at: parse_time(&created),
            }
        }))
    }
    pub async fn list_users(&self, limit: i64) -> anyhow::Result<Vec<User>> {
        let rows = sqlx::query("SELECT id,username,password_hash,is_admin,is_banned,created_at FROM users ORDER BY id DESC LIMIT ?")
            .bind(limit).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let created: String = r.get("created_at");
                User {
                    id: r.get("id"),
                    username: r.get("username"),
                    password_hash: r.get("password_hash"),
                    is_admin: r.get::<i64, _>("is_admin") == 1,
                    is_banned: r.get::<i64, _>("is_banned") == 1,
                    created_at: parse_time(&created),
                }
            })
            .collect())
    }
    pub async fn set_user_banned(&self, id: i64, banned: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET is_banned=? WHERE id=?")
            .bind(if banned { 1 } else { 0 })
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn set_user_admin(&self, id: i64, admin: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET is_admin=? WHERE id=?")
            .bind(if admin { 1 } else { 0 })
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn update_password(&self, id: i64, hash: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET password_hash=? WHERE id=?")
            .bind(hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn count_users(&self) -> anyhow::Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    pub async fn audit(
        &self,
        actor_user_id: Option<i64>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<i64>,
        success: bool,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        sqlx::query("INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,success,created_at) VALUES(?,?,?,?,?,?)")
            .bind(actor_user_id).bind(action).bind(target_type).bind(target_id)
            .bind(if success { 1 } else { 0 }).bind(now)
            .execute(&self.pool).await?;
        Ok(())
    }

    // ---- boards — ported from Go internal/store/boards.go ----
    fn row_to_board(row: &sqlx::sqlite::SqliteRow) -> Board {
        let created: String = row.get("created_at");
        Board {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            description: row.get("description"),
            allow_anonymous: row.get::<i64, _>("allow_anonymous") == 1,
            guest_readable: row.get::<i64, _>("guest_readable") == 1,
            created_at: parse_time(&created),
        }
    }

    /// CreateBoard — INSERT INTO boards(...) VALUES(?,?,?,?,?,?) ; bool→int, created_at chrono RFC3339Nano
    pub async fn create_board(
        &self,
        slug: &str,
        name: &str,
        desc: &str,
        allow_anonymous: bool,
        guest_readable: bool,
    ) -> anyhow::Result<i64> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let res = sqlx::query("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES(?,?,?,?,?,?)")
            .bind(slug).bind(name).bind(desc)
            .bind(if allow_anonymous {1} else {0})
            .bind(if guest_readable {1} else {0})
            .bind(&now)
            .execute(&self.pool).await?;
        Ok(res.last_insert_rowid())
    }

    /// ListBoards — ORDER BY id ASC, bool映射, chrono文本解析 (RFC3339Nano/RFC3339兼容)
    pub async fn list_boards(&self) -> anyhow::Result<Vec<Board>> {
        let rows = sqlx::query("SELECT id,slug,name,description,allow_anonymous,guest_readable,created_at FROM boards ORDER BY id ASC")
            .fetch_all(&self.pool).await?;
        Ok(rows.iter().map(Self::row_to_board).collect())
    }

    /// GetBoardBySlug — SELECT ... WHERE slug=?
    pub async fn get_board_by_slug(&self, slug: &str) -> anyhow::Result<Option<Board>> {
        let row = sqlx::query("SELECT id,slug,name,description,allow_anonymous,guest_readable,created_at FROM boards WHERE slug=?")
            .bind(slug).fetch_optional(&self.pool).await?;
        Ok(row.as_ref().map(Self::row_to_board))
    }

    /// GetBoardByID — SELECT ... WHERE id=?
    pub async fn get_board_by_id(&self, id: i64) -> anyhow::Result<Option<Board>> {
        let row = sqlx::query("SELECT id,slug,name,description,allow_anonymous,guest_readable,created_at FROM boards WHERE id=?")
            .bind(id).fetch_optional(&self.pool).await?;
        Ok(row.as_ref().map(Self::row_to_board))
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
            "UPDATE boards SET name=?,description=?,allow_anonymous=?,guest_readable=? WHERE id=?",
        )
        .bind(name)
        .bind(desc)
        .bind(if allow_anonymous { 1 } else { 0 })
        .bind(if guest_readable { 1 } else { 0 })
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// DeleteBoard — DELETE FROM boards WHERE id=?
    pub async fn delete_board(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM boards WHERE id=?")
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
    /// CreatePostWithParent: 楼中楼，parent_post_id None 表示回楼主，Some(pid) 表示回复某条评论
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
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        let res = sqlx::query("INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,parent_post_id,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(thread_id).bind(board_id).bind(author_id).bind(if is_anonymous {1} else {0}).bind(parent_post_id).bind(md).bind(html).bind(&now)
            .execute(&self.pool).await?;
        let id = res.last_insert_rowid();
        // 含回帖计数触发：bump thread
        let _ =
            sqlx::query("UPDATE threads SET reply_count=reply_count+1, last_reply_at=? WHERE id=?")
                .bind(&now)
                .bind(thread_id)
                .execute(&self.pool)
                .await?;
        Ok(id)
    }
    /// 兼容旧调用：无父贴
    pub async fn create_post_simple(
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
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts WHERE thread_id=?")
            .bind(thread_id)
            .fetch_one(&self.pool)
            .await?;
        let rows = sqlx::query(
            "SELECT p.id, p.thread_id, p.board_id, p.author_id, p.is_anonymous, p.parent_post_id, p.content_md, p.content_html, p.created_at, COALESCE(u.username,'deleted') \
             FROM posts p LEFT JOIN users u ON u.id=p.author_id \
             WHERE p.thread_id=? ORDER BY p.id ASC LIMIT ? OFFSET ?"
        )
        .bind(thread_id).bind(page_size).bind(offset)
        .fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let created: String = r.get("created_at");
            out.push(Post {
                id: r.get("id"),
                thread_id: r.get("thread_id"),
                board_id: r.get("board_id"),
                author_id: r.get("author_id"),
                is_anonymous: r.get::<i64, _>("is_anonymous") == 1,
                parent_post_id: r.get::<Option<i64>, _>("parent_post_id"),
                content_md: r.get("content_md"),
                content_html: r.get("content_html"),
                created_at: parse_time(&created),
                author_name: r.get::<String, _>(9),
            });
        }
        Ok((out, total.0))
    }

    pub async fn get_post(&self, id: i64) -> anyhow::Result<Option<Post>> {
        let row = sqlx::query(
            "SELECT p.id,p.thread_id,p.board_id,p.author_id,p.is_anonymous,p.parent_post_id,p.content_md,p.content_html,p.created_at, COALESCE(u.username,'deleted') \
             FROM posts p LEFT JOIN users u ON u.id=p.author_id WHERE p.id=?"
        )
        .bind(id).fetch_optional(&self.pool).await?;
        if let Some(r) = row {
            let created: String = r.get("created_at");
            return Ok(Some(Post {
                id: r.get("id"),
                thread_id: r.get("thread_id"),
                board_id: r.get("board_id"),
                author_id: r.get("author_id"),
                is_anonymous: r.get::<i64, _>("is_anonymous") == 1,
                parent_post_id: r.get::<Option<i64>, _>("parent_post_id"),
                content_md: r.get("content_md"),
                content_html: r.get("content_html"),
                created_at: parse_time(&created),
                author_name: r.get::<String, _>(9),
            }));
        }
        Ok(None)
    }

    pub async fn delete_post(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM posts WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// SearchPosts: FTS5 posts_fts MATCH + rank 分页，返回 (posts, threads, total)
    /// 对齐 Go: SELECT ... FROM posts_fts JOIN posts ... JOIN threads ... WHERE posts_fts MATCH ? ORDER BY rank
    pub async fn search_posts(
        &self,
        query: &str,
        page: i64,
        page_size: i64,
    ) -> anyhow::Result<(Vec<Post>, Vec<ThreadBrief>, i64)> {
        let page = page.max(1);
        let page_size = page_size.clamp(1, 100);
        let offset = (page - 1) * page_size;
        let q = query.trim();
        if q.is_empty() {
            return Ok((Vec::new(), Vec::new(), 0));
        }
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM posts_fts WHERE posts_fts MATCH ?")
                .bind(q)
                .fetch_one(&self.pool)
                .await?;
        let rows = sqlx::query(
            "SELECT p.id,p.thread_id,p.board_id,p.author_id,p.is_anonymous,p.parent_post_id,p.content_md,p.content_html,p.created_at, \
                    COALESCE(u.username,'deleted'), th.title, th.board_id as th_board_id \
             FROM posts_fts \
             JOIN posts p ON p.id=posts_fts.rowid \
             JOIN threads th ON th.id=p.thread_id \
             LEFT JOIN users u ON u.id=p.author_id \
             WHERE posts_fts MATCH ? \
             ORDER BY rank LIMIT ? OFFSET ?"
        )
        .bind(q).bind(page_size).bind(offset)
        .fetch_all(&self.pool).await?;
        let mut posts = Vec::with_capacity(rows.len());
        let mut map: std::collections::HashMap<i64, ThreadBrief> = std::collections::HashMap::new();
        for r in rows {
            let created: String = r.get("created_at");
            let tid: i64 = r.get("thread_id");
            let title: String = r.get("title");
            let th_board: i64 = r.get("th_board_id");
            posts.push(Post {
                id: r.get("id"),
                thread_id: tid,
                board_id: r.get("board_id"),
                author_id: r.get("author_id"),
                is_anonymous: r.get::<i64, _>("is_anonymous") == 1,
                parent_post_id: r.get::<Option<i64>, _>("parent_post_id"),
                content_md: r.get("content_md"),
                content_html: r.get("content_html"),
                created_at: parse_time(&created),
                author_name: r.get::<String, _>(9),
            });
            map.entry(tid).or_insert(ThreadBrief {
                id: tid,
                board_id: th_board,
                title,
            });
        }
        let threads: Vec<ThreadBrief> = map.into_values().collect();
        Ok((posts, threads, total.0))
    }

    /// helpers aligned with Go's IncrementReplyCount (kept for parity)
    pub async fn increment_reply_count(&self, thread_id: i64, now: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE threads SET reply_count=reply_count+1, last_reply_at=? WHERE id=?")
            .bind(now)
            .bind(thread_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- threads — ported from Go internal/store/threads.go ----
    fn row_to_thread(row: &sqlx::sqlite::SqliteRow) -> Thread {
        let last: String = row.get("last_reply_at");
        let created: String = row.get("created_at");
        Thread {
            id: row.get("id"),
            board_id: row.get("board_id"),
            title: row.get("title"),
            author_id: row.get("author_id"),
            is_pinned: row.get::<i64, _>("is_pinned") == 1,
            is_locked: row.get::<i64, _>("is_locked") == 1,
            reply_count: row.get("reply_count"),
            last_reply_at: parse_time(&last),
            created_at: parse_time(&created),
            author_name: row.get::<String, _>("author_name"),
            board_slug: row.get::<String, _>("board_slug"),
        }
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
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query("INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(board_id).bind(title).bind(author_id).bind(0).bind(0).bind(0).bind(&now).bind(&now)
            .execute(&mut *tx).await?;
        let tid = res.last_insert_rowid();
        sqlx::query("INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(tid).bind(board_id).bind(author_id).bind(if is_anonymous {1} else {0}).bind(content_md).bind(content_html).bind(&now)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(tid)
    }

    /// GetThread — author/board LEFT JOIN，COALESCE 已删用户/版块，对齐 Go
    pub async fn get_thread(&self, id: i64) -> anyhow::Result<Option<Thread>> {
        let row = sqlx::query(
            "SELECT th.id, th.board_id, th.title, th.author_id, th.is_pinned, th.is_locked, th.reply_count, th.last_reply_at, th.created_at, \
                    CASE WHEN EXISTS (SELECT 1 FROM posts op WHERE op.thread_id=th.id AND op.id=(SELECT MIN(op2.id) FROM posts op2 WHERE op2.thread_id=th.id) AND op.is_anonymous=1) THEN 'Anonymous' ELSE COALESCE(u.username,'deleted') END as author_name, COALESCE(b.slug,'') as board_slug \
             FROM threads th \
             LEFT JOIN users u ON u.id=th.author_id \
             LEFT JOIN boards b ON b.id=th.board_id \
             WHERE th.id=?"
        )
        .bind(id).fetch_optional(&self.pool).await?;
        Ok(row.as_ref().map(Self::row_to_thread))
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
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM threads WHERE board_id=?")
            .bind(board_id)
            .fetch_one(&self.pool)
            .await?;
        let rows = sqlx::query(
            "SELECT th.id, th.board_id, th.title, th.author_id, th.is_pinned, th.is_locked, th.reply_count, th.last_reply_at, th.created_at, \
                    CASE WHEN EXISTS (SELECT 1 FROM posts op WHERE op.thread_id=th.id AND op.id=(SELECT MIN(op2.id) FROM posts op2 WHERE op2.thread_id=th.id) AND op.is_anonymous=1) THEN 'Anonymous' ELSE COALESCE(u.username,'deleted') END as author_name, COALESCE(b.slug,'') as board_slug \
             FROM threads th \
             LEFT JOIN users u ON u.id=th.author_id \
             LEFT JOIN boards b ON b.id=th.board_id \
             WHERE th.board_id=? \
             ORDER BY th.is_pinned DESC, th.last_reply_at DESC, th.id DESC \
             LIMIT ? OFFSET ?"
        )
        .bind(board_id).bind(page_size).bind(offset)
        .fetch_all(&self.pool).await?;
        Ok((rows.iter().map(Self::row_to_thread).collect(), total.0))
    }

    /// SetThreadPinned — UPDATE threads SET is_pinned=?
    pub async fn set_thread_pinned(&self, id: i64, pinned: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE threads SET is_pinned=? WHERE id=?")
            .bind(if pinned { 1 } else { 0 })
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// SetThreadLocked — UPDATE threads SET is_locked=?
    pub async fn set_thread_locked(&self, id: i64, locked: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE threads SET is_locked=? WHERE id=?")
            .bind(if locked { 1 } else { 0 })
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// DeleteThread — DELETE FROM threads WHERE id=? (posts CASCADE via FK)
    pub async fn delete_thread(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM threads WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- invite_codes — ported from Go internal/store/invite.go ----
    pub async fn create_invite(&self, code: &str, created_by: i64) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        sqlx::query("INSERT INTO invite_codes(code,created_by,created_at) VALUES(?,?,?)")
            .bind(code)
            .bind(created_by)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn use_invite(&self, code: &str, used_by: i64) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let res = sqlx::query(
            "UPDATE invite_codes SET used_by=?, used_at=? WHERE code=? AND used_by IS NULL",
        )
        .bind(used_by)
        .bind(&now)
        .bind(code)
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
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let user = sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,0,?)",
        )
        .bind(username)
        .bind(hash)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        let uid = user.last_insert_rowid();
        let used = sqlx::query(
            "UPDATE invite_codes SET used_by=?, used_at=? WHERE code=? AND used_by IS NULL",
        )
        .bind(uid)
        .bind(&now)
        .bind(code)
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
            sqlx::query("SELECT 1 as avail FROM invite_codes WHERE code=? AND used_by IS NULL")
                .bind(code)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }
    pub async fn list_invites(&self) -> anyhow::Result<Vec<InviteCode>> {
        let rows = sqlx::query("SELECT code,created_by,used_by,created_at,used_at FROM invite_codes ORDER BY created_at DESC")
            .fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let created: String = r.get("created_at");
            let used: Option<String> = r.get("used_at");
            out.push(InviteCode {
                code: r.get("code"),
                created_by: r.get("created_by"),
                used_by: r.get("used_by"),
                created_at: parse_time(&created),
                used_at: used.as_deref().map(parse_time),
            });
        }
        Ok(out)
    }
    pub async fn delete_invite(&self, code: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM invite_codes WHERE code=?")
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- sessions (merged from r03) ----
    pub async fn create_session(&self, user_id: i64) -> anyhow::Result<String> {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        let id = hex::encode(b);
        let now = Utc::now();
        let exp = now + chrono::Duration::hours(30 * 24);
        sqlx::query(
            "INSERT INTO sessions(id,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(now.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .bind(exp.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .bind(now.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .execute(&self.pool)
        .await?;
        Ok(id)
    }
    pub async fn get_session(&self, id: &str) -> anyhow::Result<Option<Session>> {
        let row = sqlx::query("SELECT s.id,s.user_id,s.created_at,s.expires_at,s.last_seen_at, u.username, u.is_banned FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?")
            .bind(id).fetch_optional(&self.pool).await?;
        if let Some(r) = row {
            let created: String = r.get("created_at");
            let exp: String = r.get("expires_at");
            let last_seen: String = r.get("last_seen_at");
            let is_banned: i64 = r.get("is_banned");
            let sess = Session {
                id: r.get("id"),
                user_id: r.get("user_id"),
                created_at: parse_time(&created),
                expires_at: parse_time(&exp),
                last_seen_at: parse_time(&last_seen),
            };
            let now = Utc::now();
            if now > sess.expires_at
                || now - sess.last_seen_at > chrono::Duration::hours(12)
                || is_banned == 1
            {
                let _ = self.delete_session(id).await;
                return Ok(None);
            }
            let _ = sqlx::query("UPDATE sessions SET last_seen_at=? WHERE id=?")
                .bind(now.to_rfc3339_opts(SecondsFormat::Nanos, true))
                .bind(id)
                .execute(&self.pool)
                .await;
            return Ok(Some(sess));
        }
        Ok(None)
    }
    pub async fn delete_session(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn delete_sessions_by_user(&self, user_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id=?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    /// GetUserBySession: join users.banned 检查，封禁则删除并返回错误（对齐 Go sqlErrBanned）
    pub async fn get_user_by_session(&self, id: &str) -> anyhow::Result<Option<User>> {
        let session = match self.get_session(id).await? {
            Some(s) => s,
            None => return Ok(None),
        };
        self.get_user_by_id(session.user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_posts_crud_and_search() -> anyhow::Result<()> {
        let s = Store::open(":memory:").await?;
        sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,0,?)",
        )
        .bind("alice")
        .bind("hash")
        .bind(Utc::now().to_rfc3339())
        .execute(&s.pool)
        .await?;
        let uid: (i64,) = sqlx::query_as("SELECT id FROM users WHERE username='alice'")
            .fetch_one(&s.pool)
            .await?;
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let res = sqlx::query("INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(bid.0).bind("hello world").bind(uid.0).bind(0).bind(0).bind(0).bind(&now).bind(&now).execute(&s.pool).await?;
        let tid = res.last_insert_rowid();
        let pid1 = s
            .create_post(
                tid,
                bid.0,
                uid.0,
                false,
                "first post **md**",
                "<p>first</p>",
            )
            .await?;
        let pid2 = s
            .create_post(
                tid,
                bid.0,
                uid.0,
                true,
                "anonymous reply secret",
                "<p>anon</p>",
            )
            .await?;
        let rc: (i64,) = sqlx::query_as("SELECT reply_count FROM threads WHERE id=?")
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
        let gp = s.get_post(pid1).await?.unwrap();
        assert_eq!(gp.id, pid1);
        let pid3 = s
            .create_post(
                tid,
                bid.0,
                uid.0,
                false,
                "rust fts5 search banana",
                "<p>banana</p>",
            )
            .await?;
        let (hits, threads, total) = s.search_posts("banana", 1, 10).await?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, pid3);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].title, "hello world");
        s.delete_post(pid1).await?;
        assert!(s.get_post(pid1).await?.is_none());
        let (hits3, _, _) = s.search_posts("first", 1, 10).await?;
        // deleted post should not appear
        assert!(hits3.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_invite_registration_is_atomic_and_single_use() -> anyhow::Result<()> {
        let s = Store::open(":memory:").await?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let admin = sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,1,?)",
        )
        .bind("admin")
        .bind("hash")
        .bind(&now)
        .execute(&s.pool)
        .await?
        .last_insert_rowid();
        sqlx::query("INSERT INTO invite_codes(code,created_by,created_at) VALUES(?,?,?)")
            .bind("one-use")
            .bind(admin)
            .bind(&now)
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

    #[tokio::test]
    async fn test_session_absolute_and_idle_expiry_are_enforced() -> anyhow::Result<()> {
        let s = Store::open(":memory:").await?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let uid = sqlx::query("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)")
            .bind("alice")
            .bind("hash")
            .bind(&now)
            .execute(&s.pool)
            .await?
            .last_insert_rowid();

        let absolute = s.create_session(uid).await?;
        sqlx::query("UPDATE sessions SET expires_at=? WHERE id=?")
            .bind(
                (Utc::now() - chrono::Duration::seconds(1))
                    .to_rfc3339_opts(SecondsFormat::Nanos, true),
            )
            .bind(&absolute)
            .execute(&s.pool)
            .await?;
        assert!(s.get_user_by_session(&absolute).await?.is_none());
        assert!(sqlx::query("SELECT 1 FROM sessions WHERE id=?")
            .bind(&absolute)
            .fetch_optional(&s.pool)
            .await?
            .is_none());

        let idle = s.create_session(uid).await?;
        sqlx::query("UPDATE sessions SET last_seen_at=? WHERE id=?")
            .bind(
                (Utc::now() - chrono::Duration::hours(12) - chrono::Duration::seconds(1))
                    .to_rfc3339_opts(SecondsFormat::Nanos, true),
            )
            .bind(&idle)
            .execute(&s.pool)
            .await?;
        assert!(s.get_user_by_session(&idle).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_anonymous_thread_author_is_hidden_in_detail_and_listing() -> anyhow::Result<()> {
        let s = Store::open(":memory:").await?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let uid = sqlx::query("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)")
            .bind("alice")
            .bind("hash")
            .bind(&now)
            .execute(&s.pool)
            .await?
            .last_insert_rowid();
        let bid: (i64,) = sqlx::query_as("SELECT id FROM boards LIMIT 1")
            .fetch_one(&s.pool)
            .await?;
        let tid = sqlx::query("INSERT INTO threads(board_id,title,author_id,last_reply_at,created_at) VALUES(?,?,?,?,?)")
            .bind(bid.0).bind("private title").bind(uid).bind(&now).bind(&now).execute(&s.pool).await?.last_insert_rowid();
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

    #[test]
    fn test_parse_time_dual_format() {
        // Go time.RFC3339Nano 写入示例: 2026-08-26T08:17:36.853853123Z
        let nano = "2026-08-26T08:17:36.853853123Z";
        let dt_nano = parse_time(nano);
        assert_eq!(
            dt_nano.to_rfc3339_opts(SecondsFormat::Nanos, true),
            "2026-08-26T08:17:36.853853123Z"
        );

        // Go time.RFC3339Nano 带 offset
        let nano_offset = "2026-08-26T16:17:36.123456789+08:00";
        let dt_nano_off = parse_time(nano_offset);
        // 验证解析后 UTC 时间正确（+08:00 -> Z 差 8h）
        assert_eq!(
            dt_nano_off.to_rfc3339_opts(SecondsFormat::Nanos, true),
            "2026-08-26T08:17:36.123456789Z"
        );

        // Go time.RFC3339 写入示例: 2026-08-26T08:17:36Z (seedDefaults 使用)
        let rfc = "2026-08-26T08:17:36Z";
        let dt_rfc = parse_time(rfc);
        assert_eq!(
            dt_rfc.to_rfc3339_opts(SecondsFormat::Secs, true),
            "2026-08-26T08:17:36Z"
        );

        // Go time.RFC3339 带 offset
        let rfc_offset = "2026-08-26T16:17:36+08:00";
        let dt_rfc_off = parse_time(rfc_offset);
        assert_eq!(
            dt_rfc_off.to_rfc3339_opts(SecondsFormat::Secs, true),
            "2026-08-26T08:17:36Z"
        );

        // 额外: RFC3339Nano 秒级精度但带 nanos=0 也应解析
        let nano_zero = "2026-08-26T08:17:36.000000000Z";
        let dt_nano_zero = parse_time(nano_zero);
        assert_eq!(dt_nano_zero.timestamp(), dt_rfc.timestamp());

        // 遗留格式兼容: "2006-01-02 15:04:05"
        let legacy = "2026-08-26 08:17:36";
        let dt_legacy = parse_time(legacy);
        assert_eq!(
            dt_legacy.to_rfc3339_opts(SecondsFormat::Secs, true),
            "2026-08-26T08:17:36Z"
        );

        // 混合: Go 两种格式写入后 Rust 读取往返
        let go_nano_written = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let go_rfc_written = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        // 不 panic 且往返时间差 <1s
        let p1 = parse_time(&go_nano_written);
        let p2 = parse_time(&go_rfc_written);
        assert!((p1.timestamp() - chrono::Utc::now().timestamp()).abs() < 2);
        assert!((p2.timestamp() - chrono::Utc::now().timestamp()).abs() < 2);
    }

    #[tokio::test]
    async fn test_go_written_dual_format_roundtrip() -> anyhow::Result<()> {
        // 模拟 Go 写入的两种格式：RFC3339Nano (nowStr) 与 RFC3339 (seedDefaults)
        let s = Store::open(":memory:").await?;
        let go_nano = "2026-08-26T08:17:36.853853123Z"; // Go time.RFC3339Nano
        let go_rfc = "2026-08-26T08:17:36Z"; // Go time.RFC3339

        // users 表两种格式
        sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,0,?)",
        )
        .bind("bob_nano")
        .bind("h")
        .bind(go_nano)
        .execute(&s.pool)
        .await?;
        sqlx::query(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,0,?)",
        )
        .bind("bob_rfc")
        .bind("h")
        .bind(go_rfc)
        .execute(&s.pool)
        .await?;
        let u1 = s.get_user_by_username("bob_nano").await?.unwrap();
        let u2 = s.get_user_by_username("bob_rfc").await?.unwrap();
        assert_eq!(
            u1.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        assert_eq!(
            u2.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );

        // boards 表
        sqlx::query("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES(?,?,?,?,?,?)")
            .bind("b-nano").bind("n").bind("d").bind(1).bind(1).bind(go_nano).execute(&s.pool).await?;
        sqlx::query("INSERT INTO boards(slug,name,description,allow_anonymous,guest_readable,created_at) VALUES(?,?,?,?,?,?)")
            .bind("b-rfc").bind("n").bind("d").bind(1).bind(1).bind(go_rfc).execute(&s.pool).await?;
        let bn = s.get_board_by_slug("b-nano").await?.unwrap();
        let br = s.get_board_by_slug("b-rfc").await?.unwrap();
        assert_eq!(
            bn.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        assert_eq!(
            br.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );

        // threads/posts/sessions/invite_codes 全覆盖
        let uid = u1.id;
        let bid = bn.id;
        // threads 两种格式通过原始 SQL 插入后再读
        sqlx::query("INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(bid).bind("t-nano").bind(uid).bind(0).bind(0).bind(0).bind(go_nano).bind(go_nano).execute(&s.pool).await?;
        sqlx::query("INSERT INTO threads(board_id,title,author_id,is_pinned,is_locked,reply_count,last_reply_at,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(bid).bind("t-rfc").bind(uid).bind(0).bind(0).bind(0).bind(go_rfc).bind(go_rfc).execute(&s.pool).await?;
        let t1: (i64,) = sqlx::query_as("SELECT id FROM threads WHERE title='t-nano'")
            .fetch_one(&s.pool)
            .await?;
        let t2: (i64,) = sqlx::query_as("SELECT id FROM threads WHERE title='t-rfc'")
            .fetch_one(&s.pool)
            .await?;
        let th1 = s.get_thread(t1.0).await?.unwrap();
        let th2 = s.get_thread(t2.0).await?.unwrap();
        assert_eq!(
            th1.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        assert_eq!(
            th2.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );

        // posts
        sqlx::query("INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(t1.0).bind(bid).bind(uid).bind(0).bind("md").bind("html").bind(go_nano).execute(&s.pool).await?;
        sqlx::query("INSERT INTO posts(thread_id,board_id,author_id,is_anonymous,content_md,content_html,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(t2.0).bind(bid).bind(uid).bind(0).bind("md").bind("html").bind(go_rfc).execute(&s.pool).await?;
        let (posts1, _) = s.list_posts(t1.0, 1, 10).await?;
        let (posts2, _) = s.list_posts(t2.0, 1, 10).await?;
        assert_eq!(
            posts1[0]
                .created_at
                .to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        assert_eq!(
            posts2[0]
                .created_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );

        // sessions
        let active_last_seen = "2099-01-01T00:00:00Z";
        sqlx::query(
            "INSERT INTO sessions(id,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)",
        )
        .bind("sess-nano")
        .bind(uid)
        .bind(go_nano)
        .bind(active_last_seen)
        .bind(active_last_seen)
        .execute(&s.pool)
        .await?;
        sqlx::query(
            "INSERT INTO sessions(id,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)",
        )
        .bind("sess-rfc")
        .bind(uid)
        .bind(go_rfc)
        .bind(active_last_seen)
        .bind(active_last_seen)
        .execute(&s.pool)
        .await?;
        let sess1 = s.get_session("sess-nano").await?.unwrap();
        assert_eq!(
            sess1.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        let sess2 = s.get_session("sess-rfc").await?.unwrap();
        assert_eq!(
            sess2.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );

        // invite_codes
        sqlx::query("INSERT INTO invite_codes(code,created_by,created_at) VALUES(?,?,?)")
            .bind("code-nano")
            .bind(uid)
            .bind(go_nano)
            .execute(&s.pool)
            .await?;
        sqlx::query("INSERT INTO invite_codes(code,created_by,created_at) VALUES(?,?,?)")
            .bind("code-rfc")
            .bind(uid)
            .bind(go_rfc)
            .execute(&s.pool)
            .await?;
        sqlx::query("UPDATE invite_codes SET used_at=? WHERE code=?")
            .bind(go_nano)
            .bind("code-nano")
            .execute(&s.pool)
            .await?;
        sqlx::query("UPDATE invite_codes SET used_at=? WHERE code=?")
            .bind(go_rfc)
            .bind("code-rfc")
            .execute(&s.pool)
            .await?;
        let invites = s.list_invites().await?;
        let in_nano = invites.iter().find(|x| x.code == "code-nano").unwrap();
        let in_rfc = invites.iter().find(|x| x.code == "code-rfc").unwrap();
        assert_eq!(
            in_nano
                .created_at
                .to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        assert_eq!(
            in_rfc.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );
        assert_eq!(
            in_nano
                .used_at
                .unwrap()
                .to_rfc3339_opts(SecondsFormat::Nanos, true),
            go_nano
        );
        assert_eq!(
            in_rfc
                .used_at
                .unwrap()
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            go_rfc
        );

        Ok(())
    }
}
