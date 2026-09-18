-- TOTP second-factor support.
--
-- Storage notes:
--   * The shared secret is stored base32 encoded, like every mainstream forum
--     does. It is a bearer credential: a database dump is enough to generate
--     codes, so backups must be encrypted.
--   * `totp_pending_secret` holds an enrolment that has not been confirmed by a
--     valid code yet, so a mistyped or abandoned enrolment cannot lock an
--     account out.
--   * `totp_last_step` records the last accepted time step for replay
--     prevention: RFC 6238 codes must only be accepted once.
--   * Recovery codes are stored as SHA-256 hashes. The codes themselves are
--     high-entropy random strings, so a fast hash is sufficient.

ALTER TABLE users
    ADD COLUMN totp_secret TEXT,
    ADD COLUMN totp_activated_at TIMESTAMPTZ,
    ADD COLUMN totp_last_step BIGINT,
    ADD COLUMN totp_pending_secret TEXT,
    ADD COLUMN totp_pending_created_at TIMESTAMPTZ;

CREATE TABLE totp_recovery_codes (
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_hash)
);

CREATE INDEX idx_totp_recovery_codes_active
    ON totp_recovery_codes (user_id, used_at);

-- Short-lived state between the password step and the second factor. A pending
-- login is single-use, expires quickly, and allows only a few code attempts.
CREATE TABLE pending_logins (
    id          TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    BIGINT NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_pending_logins_expiry ON pending_logins (expires_at);
CREATE INDEX idx_pending_logins_user ON pending_logins (user_id);
