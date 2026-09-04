use tower::limit::ConcurrencyLimitLayer;
use veil_forum::{auth, handler, pow, rate_limit, store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8001".to_string();
    let mut data = "./data/forum.db".to_string();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--addr" && i + 1 < args.len() {
            addr = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--data" && i + 1 < args.len() {
            data = args[i + 1].clone();
            i += 2;
        } else {
            i += 1;
        }
    }
    if let Ok(parsed) = addr.parse::<std::net::SocketAddr>() {
        if !parsed.ip().is_loopback()
            && std::env::var("VEIL_ALLOW_NONLOOPBACK").ok().as_deref() != Some("1")
        {
            anyhow::bail!("refusing non-loopback listener; set VEIL_ALLOW_NONLOOPBACK=1 only behind a controlled Onion/I2P gateway");
        }
    }
    // ensure data dir
    if let Some(dir) = std::path::Path::new(&data).parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let store = store::Store::open(&data)
        .await
        .map_err(|e| anyhow::anyhow!("open database {}: {}", data, e))?;
    auth::ensure_admin(&store.pool)
        .await
        .map_err(|e| anyhow::anyhow!("initialize administrator: {}", e))?;
    println!("veil-forum security mode enabled");
    let pow = pow::Manager::new(store.clone());
    let state = handler::AppState {
        store: store.clone(),
        pow,
        captcha: veil_forum::captcha::Manager::new(),
        limits: rate_limit::Limits::new(),
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
