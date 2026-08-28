use comrak::{markdown_to_html, ComrakOptions};
use regex::Regex;

pub fn render(md: &str) -> String {
    let re_img = Regex::new(r"(?s)!\[[^\]]*\]\([^)]*\)").unwrap();
    let clean = re_img.replace_all(md, "");
    let mut opts = ComrakOptions::default();
    opts.extension.table = true;
    opts.extension.strikethrough = true;
    let html = markdown_to_html(&clean, &opts);
    let cleansed = ammonia::Builder::default()
        .add_tags(&[
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "pre",
            "code",
            "blockquote",
            "ul",
            "ol",
            "li",
            "p",
            "br",
            "strong",
            "em",
            "a",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "hr",
        ])
        .url_schemes(std::collections::HashSet::new())
        .add_tags(&[
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "pre",
            "code",
            "blockquote",
            "ul",
            "ol",
            "li",
            "p",
            "br",
            "strong",
            "em",
            "a",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "hr",
        ])
        .add_generic_attributes(&["class"])
        .link_rel(Some("nofollow"))
        .clean(&html)
        .to_string();
    cleansed
}
