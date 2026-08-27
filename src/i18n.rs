use std::collections::HashMap;

#[derive(Clone)]
pub struct I18n {
    locales: HashMap<String, HashMap<String, String>>,
}

impl I18n {
    pub fn new() -> Self {
        let mut locales = HashMap::new();
        for (lang, data) in [
            ("en", include_str!("../locales/en.json")),
            ("zh", include_str!("../locales/zh.json")),
            ("ru", include_str!("../locales/ru.json")),
        ] {
            if let Ok(v) = serde_json::from_str::<HashMap<String, String>>(data) {
                locales.insert(lang.to_string(), v);
            }
        }
        Self { locales }
    }
    pub fn t(&self, locale: &str, key: &str) -> String {
        if let Some(m) = self.locales.get(locale) {
            if let Some(v) = m.get(key) {
                return v.clone();
            }
        }
        if let Some(m) = self.locales.get("en") {
            if let Some(v) = m.get(key) {
                return v.clone();
            }
        }
        key.to_string()
    }
    pub fn detect(
        &self,
        cookie_locale: Option<&str>,
        accept_lang: Option<&str>,
        default_locale: &str,
    ) -> String {
        if let Some(c) = cookie_locale {
            if self.locales.contains_key(c) {
                return c.to_string();
            }
        }
        if let Some(al) = accept_lang {
            for part in al.split(',') {
                let lang = part
                    .split(';')
                    .next()
                    .unwrap()
                    .trim()
                    .split('-')
                    .next()
                    .unwrap()
                    .trim();
                if self.locales.contains_key(lang) {
                    return lang.to_string();
                }
                if lang.len() >= 2 {
                    let short = &lang[0..2];
                    if self.locales.contains_key(short) {
                        return short.to_string();
                    }
                }
            }
        }
        if self.locales.contains_key(default_locale) {
            default_locale.to_string()
        } else {
            "en".to_string()
        }
    }

    pub fn supported() -> &'static [&'static str] {
        &["en", "zh", "ru"]
    }
}

pub fn translate(locale: &str, key: &str) -> String {
    use std::sync::OnceLock;
    static I18N: OnceLock<I18n> = OnceLock::new();
    I18N.get_or_init(I18n::new).t(locale, key)
}

pub fn ui(locale: &str, english: &str, chinese: &str, russian: &str) -> String {
    match locale {
        "zh" => chinese.to_string(),
        "ru" => russian.to_string(),
        _ => english.to_string(),
    }
}

pub fn format(mut text: String, name: &str, value: &str) -> String {
    text = text.replace(&format!("{{{}}}", name), value);
    text
}
