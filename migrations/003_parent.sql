-- 003: 楼中楼回复 — 允许回帖回复某条评论
ALTER TABLE posts ADD COLUMN parent_post_id INTEGER REFERENCES posts(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_posts_parent ON posts(parent_post_id);
CREATE INDEX IF NOT EXISTS idx_posts_thread_parent ON posts(thread_id, parent_post_id);
