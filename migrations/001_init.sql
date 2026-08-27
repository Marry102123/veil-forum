CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    is_banned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    allow_anonymous INTEGER NOT NULL DEFAULT 1,
    guest_readable INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS configs (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    created_by INTEGER NOT NULL REFERENCES users(id),
    used_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    author_id INTEGER NOT NULL REFERENCES users(id),
    is_pinned INTEGER NOT NULL DEFAULT 0,
    is_locked INTEGER NOT NULL DEFAULT 0,
    reply_count INTEGER NOT NULL DEFAULT 0,
    last_reply_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    board_id INTEGER NOT NULL REFERENCES boards(id),
    author_id INTEGER NOT NULL REFERENCES users(id),
    is_anonymous INTEGER NOT NULL DEFAULT 0,
    content_md TEXT NOT NULL,
    content_html TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
    ,last_seen_at TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(title, content_md, content='posts', content_rowid='id', tokenize='porter unicode61');
CREATE TRIGGER IF NOT EXISTS posts_ai AFTER INSERT ON posts BEGIN INSERT INTO posts_fts(rowid, title, content_md) VALUES (new.id, (SELECT title FROM threads WHERE id=new.thread_id), new.content_md); END;
CREATE TRIGGER IF NOT EXISTS posts_ad AFTER DELETE ON posts BEGIN INSERT INTO posts_fts(posts_fts, rowid, title, content_md) VALUES('delete', old.id, (SELECT title FROM threads WHERE id=old.thread_id), old.content_md); END;
CREATE TRIGGER IF NOT EXISTS posts_au AFTER UPDATE ON posts BEGIN INSERT INTO posts_fts(posts_fts, rowid, title, content_md) VALUES('delete', old.id, (SELECT title FROM threads WHERE id=old.thread_id), old.content_md); INSERT INTO posts_fts(rowid, title, content_md) VALUES (new.id, (SELECT title FROM threads WHERE id=new.thread_id), new.content_md); END;
CREATE INDEX IF NOT EXISTS idx_threads_board ON threads(board_id, is_pinned DESC, last_reply_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_thread ON posts(thread_id, id ASC);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
