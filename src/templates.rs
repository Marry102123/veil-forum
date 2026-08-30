use std::sync::OnceLock;
use tera::{Context, Tera};

/// Templates are embedded into the binary so deployments cannot accidentally
/// omit or modify the site's HTML assets.
fn templates() -> &'static Tera {
    static TEMPLATES: OnceLock<Tera> = OnceLock::new();
    TEMPLATES.get_or_init(|| {
        let mut tera = Tera::default();
        tera.add_raw_template("layout.html", include_str!("../templates/layout.html"))
            .expect("embedded layout template must be valid");
        tera.add_raw_template(
            "partials/pow_fallback.html",
            include_str!("../templates/partials/pow_fallback.html"),
        )
        .expect("embedded PoW fallback template must be valid");
        tera.add_raw_template(
            "partials/account.html",
            include_str!("../templates/partials/account.html"),
        )
        .expect("embedded account template must be valid");
        tera.add_raw_template(
            "partials/boards.html",
            include_str!("../templates/partials/boards.html"),
        )
        .expect("embedded boards template must be valid");
        tera.add_raw_template(
            "partials/recent.html",
            include_str!("../templates/partials/recent.html"),
        )
        .expect("embedded recent template must be valid");
        tera.add_raw_template(
            "pages/home.html",
            include_str!("../templates/pages/home.html"),
        )
        .expect("embedded home template must be valid");
        tera.add_raw_template(
            "pages/board.html",
            include_str!("../templates/pages/board.html"),
        )
        .expect("embedded board template must be valid");
        tera.add_raw_template(
            "pages/thread.html",
            include_str!("../templates/pages/thread.html"),
        )
        .expect("embedded thread template must be valid");
        tera.add_raw_template(
            "pages/search.html",
            include_str!("../templates/pages/search.html"),
        )
        .expect("embedded search template must be valid");
        tera.add_raw_template(
            "pages/register.html",
            include_str!("../templates/pages/register.html"),
        )
        .expect("embedded register template must be valid");
        tera.add_raw_template(
            "pages/login.html",
            include_str!("../templates/pages/login.html"),
        )
        .expect("embedded login template must be valid");
        tera.add_raw_template(
            "pages/admin.html",
            include_str!("../templates/pages/admin.html"),
        )
        .expect("embedded admin template must be valid");
        // Keep the pagination include optional for older deployments, while
        // embedding it when present so page templates are self-contained.
        tera.add_raw_template(
            "pages/_pagination.html",
            include_str!("../templates/pages/_pagination.html"),
        )
        .expect("embedded pagination template must be valid");
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
