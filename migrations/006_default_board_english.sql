-- Translate only the untouched legacy seed board. Administrator-created names
-- and descriptions are never modified by this migration.
UPDATE boards
SET name = 'General', description = 'General discussion'
WHERE slug = 'general'
  AND name = '综合版'
  AND description = '默认综合讨论区';
