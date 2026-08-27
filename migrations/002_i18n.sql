ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT 'zh';
ALTER TABLE boards ADD COLUMN name_i18n TEXT NOT NULL DEFAULT '{}';
INSERT OR IGNORE INTO configs(key,value) VALUES('default_locale','en');
