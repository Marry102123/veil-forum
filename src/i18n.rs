use std::collections::HashMap;

#[derive(Clone)]
pub struct I18n {
    locales: HashMap<String, HashMap<String, String>>,
}

impl Default for I18n {
    fn default() -> Self {
        Self::new()
    }
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
