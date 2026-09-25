-- Anonymous thread/post identity minimization: remove the non-null invariants,
-- then erase author attribution from anonymous threads and every anonymous post.
-- Failure modes:
--   * The schema is not migrated, so anonymous identity remains exposed.
--   * Constraint removal fails because author_id has dependent objects.
--   * A legacy anonymous thread is identified by its opening post, not merely
--     by the presence of any anonymous reply.
--   * The backfill fails, rolls back, and leaves existing identities unchanged.
ALTER TABLE threads ALTER COLUMN author_id DROP NOT NULL;
ALTER TABLE posts ALTER COLUMN author_id DROP NOT NULL;

-- The thread table has no is_anonymous column. Its opening post is the
-- authoritative historical marker, even when later replies are non-anonymous.
-- MIN(id) identifies the opening post without requiring it to remain visible.
UPDATE threads AS th
SET author_id = NULL
WHERE EXISTS (
    SELECT 1
    FROM posts AS opening
    WHERE opening.thread_id = th.id
      AND opening.id = (SELECT MIN(first_post.id) FROM posts AS first_post WHERE first_post.thread_id = th.id)
      AND opening.is_anonymous = TRUE
);

UPDATE posts SET author_id = NULL WHERE is_anonymous = TRUE;
