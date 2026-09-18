use tower::limit::ConcurrencyLimitLayer;
use veil_forum::{auth, handler, pow, rate_limit, store};

/// Default connection string. The Unix socket form with peer authentication is
/// deliberate: PostgreSQL stays off the network and no password is stored in
/// configuration, the environment, or the unit file.
const DEFAULT_DATABASE_URL: &str = "postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8001".to_string();
    let mut database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_DATABASE_URL.to_string());
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = args[i + 1].clone();
                i += 2;
            }
            "--database-url" if i + 1 < args.len() => {
                database_url = args[i + 1].clone();
                i += 2;
            }
            // Fail loudly rather than silently ignoring an option that no longer
            // selects where data is stored.
            "--data" => anyhow::bail!(
                "--data was removed: veil-forum stores its data in PostgreSQL now; \
                 use --database-url or DATABASE_URL"
            ),
            other => anyhow::bail!(
                "unknown argument {other:?}; usage: veil-forum [--addr HOST:PORT] \
                 [--database-url postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum]"
            ),
        }
    }
    // Resolve the listener instead of only parsing a literal address: a
    // hostname can otherwise resolve to a non-loopback interface and skip the
    // guard below, and `bind` resolves it later regardless.
    let resolved: Vec<std::net::SocketAddr> = {
        use std::net::ToSocketAddrs;
        match addr.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(error) => anyhow::bail!("cannot resolve --addr {addr:?}: {error}"),
        }
    };
    if resolved.is_empty() {
        anyhow::bail!("--addr {addr:?} resolved to no addresses");
    }
    let non_loopback = resolved.iter().any(|parsed| !parsed.ip().is_loopback());
    if non_loopback && std::env::var("VEIL_ALLOW_NONLOOPBACK").ok().as_deref() != Some("1") {
        anyhow::bail!("refusing non-loopback listener; set VEIL_ALLOW_NONLOOPBACK=1 only behind a controlled Onion/I2P gateway");
    }
    let secure_session_cookie = match std::env::var("VEIL_SESSION_COOKIE_SECURE").as_deref() {
        Ok("1") => true,
        Ok("0") if !non_loopback => false,
        Ok("0") => {
            anyhow::bail!("VEIL_SESSION_COOKIE_SECURE=0 is only permitted for a loopback listener")
        }
        Ok(_) => anyhow::bail!("VEIL_SESSION_COOKIE_SECURE must be 0 or 1"),
        Err(_) => non_loopback,
    };
    let store = store::Store::connect(&database_url).await.map_err(|e| {
        anyhow::anyhow!(
            "connect to database {}: {e}",
            store::redact_database_url(&database_url)
        )
    })?;
    auth::ensure_admin(&store.pool)
        .await
        .map_err(|e| anyhow::anyhow!("initialize administrator: {}", e))?;
    println!("veil-forum security mode enabled");
    println!(
        "veil-forum database: {}",
        store::redact_database_url(&database_url)
    );
    let pow = pow::Manager::new(store.clone());
    let state = handler::AppState {
        store: store.clone(),
        pow,
        captcha: veil_forum::captcha::Manager::new(),
        limits: rate_limit::Limits::new(),
        secure_session_cookie,
        password_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let app = handler::routes(state).layer(ConcurrencyLimitLayer::new(64));
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind listener {}: {}", addr, e))?;
    println!("Rust listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
