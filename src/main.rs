use tower::limit::ConcurrencyLimitLayer;
use veil_forum::{auth, handler, pow, rate_limit, store};

/// Default connection string. The Unix socket form with peer authentication is
/// deliberate: PostgreSQL stays off the network and no password is stored in
/// configuration, the environment, or the unit file.
const DEFAULT_DATABASE_URL: &str = "postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum";

const USAGE: &str = "\
usage: veil-forum [--addr HOST:PORT] [--database-url URL] [--db-socket DIR --db-name NAME --db-user USER] [--version] [--help]
  --addr HOST:PORT     listener address (default 127.0.0.1:8001; loopback only
                       unless VEIL_ALLOW_NONLOOPBACK=1)
  --database-url URL   full PostgreSQL connection string (or DATABASE_URL).
                       Rejects --db-socket/--db-name/--db-user when combined.
  --db-socket DIR      Unix socket directory (default /var/run/postgresql)
  --db-name NAME       database name (default veil_forum)
  --db-user USER       database role; must match the service user for peer
                       authentication (default veil-forum)
  --version, -V        print the version and exit
  --help, -h           print this help and exit";

fn print_usage() {
    println!("veil-forum {}", env!("CARGO_PKG_VERSION"));
    println!("{USAGE}");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8001".to_string();
    let mut flag_database_url: Option<String> = None;
    let mut db_socket: Option<String> = None;
    let mut db_name: Option<String> = None;
    let mut db_user: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = args[i + 1].clone();
                i += 2;
            }
            "--database-url" if i + 1 < args.len() => {
                flag_database_url = Some(args[i + 1].clone());
                i += 2;
            }
            "--db-socket" if i + 1 < args.len() => {
                db_socket = Some(args[i + 1].clone());
                i += 2;
            }
            "--db-name" if i + 1 < args.len() => {
                db_name = Some(args[i + 1].clone());
                i += 2;
            }
            "--db-user" if i + 1 < args.len() => {
                db_user = Some(args[i + 1].clone());
                i += 2;
            }
            "--version" | "-V" => {
                println!("veil-forum {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            // Fail loudly rather than silently ignoring an option that no longer
            // selects where data is stored.
            "--data" => anyhow::bail!(
                "--data was removed: veil-forum stores its data in PostgreSQL now; \
                 use --database-url or DATABASE_URL"
            ),
            other => anyhow::bail!("unknown argument {other:?}; {USAGE}"),
        }
    }
    tracing_subscriber::fmt()
        .json()
        // Keep structured events on stderr, which is what systemd/OpenRC
        // journal capture and the real-process E2E inspect. Diagnostics must
        // never share stdout with normal CLI output.
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()
        .ok();
    let socket_parts_given = db_socket.is_some() || db_name.is_some() || db_user.is_some();
    let env_database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    // An explicit connection string and the socket parts select the same thing
    // two different ways; mixing them is almost certainly a mistake, and the
    // wrong half winning silently would point the forum at the wrong database.
    if socket_parts_given && (flag_database_url.is_some() || env_database_url.is_some()) {
        anyhow::bail!(
            "cannot combine --database-url (or DATABASE_URL) with \
             --db-socket/--db-name/--db-user; use one or the other"
        );
    }
    let database_url = match (flag_database_url, env_database_url) {
        (Some(url), _) => url,
        (None, Some(url)) => url,
        (None, None) if socket_parts_given => {
            let user = db_user.unwrap_or_else(|| store::DEFAULT_DB_USER.to_string());
            let socket = db_socket.unwrap_or_else(|| store::DEFAULT_DB_SOCKET_DIR.to_string());
            let name = db_name.unwrap_or_else(|| store::DEFAULT_DB_NAME.to_string());
            for (label, value) in [
                ("--db-user", &user),
                ("--db-socket", &socket),
                ("--db-name", &name),
            ] {
                if value.trim().is_empty() {
                    anyhow::bail!("{label} must not be empty");
                }
            }
            store::socket_database_url(&user, &socket, &name)
        }
        (None, None) => DEFAULT_DATABASE_URL.to_string(),
    };
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
    println!(
        "veil-forum {} security mode enabled",
        env!("CARGO_PKG_VERSION")
    );
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
    };
    let app = handler::routes(state).layer(ConcurrencyLimitLayer::new(64));
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind listener {}: {}", addr, e))?;
    println!("Rust listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
