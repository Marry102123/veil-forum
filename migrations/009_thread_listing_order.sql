-- The board listing orders by all four columns. Including the id tie-breaker
-- lets SQLite satisfy the filter and complete ordering from one index without
-- a temporary sort.
DROP INDEX IF EXISTS idx_threads_board;
CREATE INDEX IF NOT EXISTS idx_threads_board_order
    ON threads(board_id, is_pinned DESC, last_reply_at DESC, id DESC);
