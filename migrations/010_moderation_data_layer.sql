-- Moderation and lifecycle support. Roles are intentionally normalized so a user
-- may hold multiple site-wide roles and moderation can be scoped to a board.
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY CHECK (name IN ('owner', 'admin', 'moderator'))
);
INSERT OR IGNORE INTO roles(name) VALUES ('owner'), ('admin'), ('moderator');

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    granted_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, role_name)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_name, user_id);
-- Preserve authority for installations created before normalized roles existed.
INSERT OR IGNORE INTO user_roles(user_id,role_name,granted_by_user_id,created_at)
SELECT id, 'owner', NULL, created_at FROM users WHERE is_admin = 1;

CREATE TABLE IF NOT EXISTS board_moderators (
    board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (board_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_board_moderators_user ON board_moderators(user_id, board_id);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('post', 'thread', 'user')),
    target_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed')),
    resolved_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    resolution_note TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_status_created ON reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_type, target_id);

ALTER TABLE posts ADD COLUMN deleted_at TEXT;
ALTER TABLE posts ADD COLUMN deleted_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE threads ADD COLUMN deleted_at TEXT;
ALTER TABLE threads ADD COLUMN deleted_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_posts_visible_thread ON posts(thread_id, deleted_at, id ASC);
CREATE INDEX IF NOT EXISTS idx_threads_visible_board ON threads(board_id, deleted_at, is_pinned DESC, last_reply_at DESC, id DESC);

ALTER TABLE audit_logs ADD COLUMN metadata TEXT;
