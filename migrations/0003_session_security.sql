-- Session security: persist only SHA-256 digests of bearer tokens.
-- Existing rows are deleted deliberately, invalidating every old cookie and
-- second-factor window. Browser cookies continue to carry random raw tokens.
DELETE FROM sessions;
DELETE FROM pending_logins;
