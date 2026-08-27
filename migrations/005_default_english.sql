-- Upgrade databases created before the live locale renderer was connected.
INSERT OR IGNORE INTO configs(key,value) VALUES('locale_default_migrated','0');
UPDATE configs SET value='en'
 WHERE key='default_locale' AND value='zh'
   AND (SELECT value FROM configs WHERE key='locale_default_migrated')='0';
UPDATE configs SET value='1' WHERE key='locale_default_migrated' AND value='0';
