use std::sync::OnceLock;
use tera::{Context, Tera};

/// Templates are embedded into the binary so deployments cannot accidentally
/// omit or modify the site's HTML assets.
fn templates() -> &'static Tera {
    static TEMPLATES: OnceLock<Tera> = OnceLock::new();
    TEMPLATES.get_or_init(|| {
        let mut tera = Tera::default();
        // Register every template in one call: Tera 2 resolves includes while
        // parsing, so a partial must be present in the same batch as its parent.
        let embedded: Vec<(&str, &str)> = vec![
            ("layout.html", include_str!("../templates/layout.html")),
            (
                "partials/pow_fallback.html",
                include_str!("../templates/partials/pow_fallback.html"),
            ),
            (
                "partials/account.html",
                include_str!("../templates/partials/account.html"),
            ),
            (
                "partials/boards.html",
                include_str!("../templates/partials/boards.html"),
            ),
            (
                "partials/recent.html",
                include_str!("../templates/partials/recent.html"),
            ),
            (
                "pages/home.html",
                include_str!("../templates/pages/home.html"),
            ),
            (
                "pages/board.html",
                include_str!("../templates/pages/board.html"),
            ),
            (
                "pages/thread.html",
                include_str!("../templates/pages/thread.html"),
            ),
            (
                "pages/search.html",
                include_str!("../templates/pages/search.html"),
            ),
            (
                "pages/register.html",
                include_str!("../templates/pages/register.html"),
            ),
            (
                "pages/login.html",
                include_str!("../templates/pages/login.html"),
            ),
            (
                "pages/login_totp.html",
                include_str!("../templates/pages/login_totp.html"),
            ),
            (
                "pages/account.html",
                include_str!("../templates/pages/account.html"),
            ),
            (
                "pages/admin.html",
                include_str!("../templates/pages/admin.html"),
            ),
            (
                "pages/admin_settings.html",
                include_str!("../templates/pages/admin_settings.html"),
            ),
            (
                "pages/governance.html",
                include_str!("../templates/pages/governance.html"),
            ),
            (
                "pages/_pagination.html",
                include_str!("../templates/pages/_pagination.html"),
            ),
        ];
        tera.add_raw_templates(embedded)
            .expect("embedded templates must be valid");
        tera
    })
}

pub fn render_layout(context: &Context) -> anyhow::Result<String> {
    Ok(templates().render("layout.html", context)?)
}

pub fn render_pow_fallback(context: &Context) -> anyhow::Result<String> {
    Ok(templates().render("partials/pow_fallback.html", context)?)
}

/// Render a page fragment. `layout_html` remains responsible for the common
/// shell, allowing handlers to share the same page templates without HTML
/// string assembly.
pub fn render_page(name: &str, context: &Context) -> anyhow::Result<String> {
    Ok(templates().render(&format!("pages/{name}.html"), context)?)
}
