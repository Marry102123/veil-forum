-- unicode61 does not tokenize Chinese text. Trigrams support substring search
-- for Chinese while retaining useful matching for Latin text.
-- Drop synchronization triggers before replacing the content table. SQLite
-- otherwise leaves them referencing a missing virtual table during rebuild.
DROP TRIGGER IF EXISTS posts_ai;
DROP TRIGGER IF EXISTS posts_ad;
DROP TRIGGER IF EXISTS posts_au;
DROP TABLE IF EXISTS posts_fts_new;
CREATE VIRTUAL TABLE posts_fts_new USING fts5(
    title, content_md, content='posts', content_rowid='id', tokenize='trigram'
);
INSERT INTO posts_fts_new(rowid, title, content_md)
SELECT p.id, t.title, p.content_md
FROM posts p JOIN threads t ON t.id = p.thread_id;
DROP TABLE posts_fts;
ALTER TABLE posts_fts_new RENAME TO posts_fts;

-- Recreate synchronization triggers after replacing the virtual table.
CREATE TRIGGER posts_ai AFTER INSERT ON posts BEGIN INSERT INTO posts_fts(rowid, title, content_md) VALUES (new.id, (SELECT title FROM threads WHERE id=new.thread_id), new.content_md); END;
CREATE TRIGGER posts_ad AFTER DELETE ON posts BEGIN INSERT INTO posts_fts(posts_fts, rowid, title, content_md) VALUES('delete', old.id, (SELECT title FROM threads WHERE id=old.thread_id), old.content_md); END;
CREATE TRIGGER posts_au AFTER UPDATE ON posts BEGIN INSERT INTO posts_fts(posts_fts, rowid, title, content_md) VALUES('delete', old.id, (SELECT title FROM threads WHERE id=old.thread_id), old.content_md); INSERT INTO posts_fts(rowid, title, content_md) VALUES (new.id, (SELECT title FROM threads WHERE id=new.thread_id), new.content_md); END;
