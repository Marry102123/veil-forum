-- no-transaction
--
-- Post-cooldown index: the per-account posting cooldown reads the most recent
-- non-anonymous post of one author. Failure modes this migration prevents:
--   * The schema is not migrated, so every submission pays a parallel sequential
--     scan over the whole posts table instead of an index lookup.
--   * The index is left invalid, so the planner must fall back to a sequential
--     scan. CONCURRENTLY is required because sqlx wraps migrations in a
--     transaction by default, and this statement cannot run inside one; the
--     `-- no-transaction` directive above is what makes that legal.
--   * The index includes anonymous rows, whose author_id is NULL by design, so it
--     grows with traffic the cooldown is not allowed to consider anyway.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_posts_author_recent
    ON posts (author_id, created_at DESC)
    WHERE is_anonymous = FALSE;
