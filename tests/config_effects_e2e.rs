//! End-to-end proof that administrator configuration forms change real behavior.
//!
//! Failure modes covered:
//! - maintenance settings are persisted but public pages still render the forum;
//! - closed registration still accepts a direct form POST, or rendered controls drift;
//! - registration PoW/invite switches are stored without changing the public form;
//! - the TOTP feature and policy switches are stored without changing enforcement;
//! - a palette is stored but absent from rendered page HTML;
//! - malformed theme, registration, PoW, or TOTP values crash the service or poison config;
//! - login, CSRF, or the browser session is not carried through a real TCP HTTP exchange.
//!
//! The application is served on an ephemeral loopback TCP port. Every setting is
//! changed through the administrator login and HTML form endpoints. PostgreSQL is
//! queried only after the HTTP assertions to confirm the durable final state.

use anyhow::{bail, Context};
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions, PgPool};
use std::collections::HashSet;
use std::process::{Child, Command, Stdio};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use veil_forum::{captcha, handler, pow, store::Store};

const ADMIN_PASSWORD: &str = "Aurora-Basalt8-Willow";

struct E2eReport {
    test: &'static str,
    path: std::path::PathBuf,
    log_path: std::path::PathBuf,
    started_at: String,
    ended_at: Option<String>,
    result: &'static str,
    failed_step: Option<&'static str>,
    expected_checks: Vec<&'static str>,
    completed_checks: Vec<&'static str>,
    written: bool,
}

impl E2eReport {
    fn start() -> Self {
        Self {
            test: "admin_forms_change_http_behavior_and_postgresql_state",
            path: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/config-effects-e2e-report.json"),
            log_path: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/config-effects-e2e-stderr.jsonl"),
            started_at: utc_now(),
            ended_at: None,
            result: "failed",
            failed_step: Some("fixture_setup"),
            expected_checks: vec![
                "real loopback HTTP and administrator session",
                "real subprocess PostgreSQL constraint errors",
                "stable public error responses and CSP",
                "structured JSON request logs and redaction",
                "theme and maintenance behavior",
                "registration PoW, invite, and closed-mode enforcement",
                "TOTP feature and policy enforcement",
                "invalid input normalization",
                "PostgreSQL final state",
            ],
            completed_checks: Vec::new(),
            written: false,
        }
    }

    fn step(&mut self, step: &'static str) -> &'static str {
        self.failed_step = Some(step);
        step
    }

    fn complete(&mut self, step: &str, checks: &[&'static str]) {
        if self.failed_step == Some(step) {
            self.completed_checks.extend_from_slice(checks);
            self.failed_step = None;
        }
    }

    fn succeed(&mut self) -> anyhow::Result<()> {
        self.result = "passed";
        self.failed_step = None;
        if let Err(error) = self.write() {
            self.result = "failed";
            self.failed_step = Some("report_write");
            return Err(error);
        }
        Ok(())
    }

    fn write(&mut self) -> anyhow::Result<()> {
        self.ended_at = Some(utc_now());
        let report = serde_json::json!({
            "schema_version": 1,
            "test": self.test,
            "started_at_utc": self.started_at,
            "ended_at_utc": self.ended_at,
            "input_summary": {
                "database": "sqlx isolated PostgreSQL database",
                "transport": "real loopback TCP HTTP",
                "settings": ["theme", "maintenance", "registration", "PoW", "TOTP"],
                "secrets": "test-only values excluded"
            },
            "result": self.result,
            "failed_step": self.failed_step,
            "key_checks": {
                "expected": self.expected_checks,
                "completed": self.completed_checks
            },
            "artifacts": {
                "report_path": self.path,
                "log_path": self.log_path,
                "log_policy": "credential-free application stderr JSON lines only"
            },
            "reproduce_command": "DATABASE_URL=<test-postgres-url> cargo test --test config_effects_e2e -- --nocapture",
            "credentials_included": false
        });
        let Some(parent) = self.path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(parent)?;
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        let temporary = self.path.with_extension("json.tmp");
        if let Err(error) = std::fs::write(&temporary, bytes) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        if let Err(error) = std::fs::rename(&temporary, &self.path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        self.written = true;
        Ok(())
    }
}

impl Drop for E2eReport {
    fn drop(&mut self) {
        if !self.written {
            let _ = self.write();
        }
    }
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

struct Http {
    authority: String,
    cookie: Option<String>,
}

struct Response {
    status: u16,
    headers: String,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }
}

struct ServerProcess {
    child: Child,
    authority: String,
}

impl ServerProcess {
    async fn start(pool: &PgPool, log_path: &std::path::Path) -> anyhow::Result<Self> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::File::create(log_path)?.sync_all()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let authority = listener.local_addr()?.to_string();
        drop(listener);
        let database_url = pool.connect_options().to_url_lossy().to_string();
        let binary = option_env!("CARGO_BIN_EXE_veil-forum")
            .context("CARGO_BIN_EXE_veil-forum was not provided by Cargo")?;
        let stderr = std::fs::OpenOptions::new().append(true).open(log_path)?;
        let child = Command::new(binary)
            .arg("--addr")
            .arg(&authority)
            .arg("--database-url")
            .arg(database_url)
            .env("VEIL_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .env("RUST_LOG", "info")
            .env("VEIL_SESSION_COOKIE_SECURE", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let server = Self { child, authority };
        let mut client = Http {
            authority: server.authority.clone(),
            cookie: None,
        };
        for _ in 0..80 {
            match client.get("/healthz").await {
                Ok(response) if response.body == "ok" => return Ok(server),
                Ok(_) | Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
        }
        bail!("real subprocess did not become healthy")
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Http {
    fn connect(authority: &str) -> Self {
        Self {
            authority: authority.to_owned(),
            cookie: None,
        }
    }

    async fn start(state: handler::AppState) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let authority = listener.local_addr()?.to_string();
        let app = handler::routes(state);
        tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            authority,
            cookie: None,
        })
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        form: Option<&str>,
    ) -> anyhow::Result<Response> {
        let body = form.unwrap_or_default();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nOrigin: http://{}\r\nContent-Length: {}\r\n",
            self.authority,
            self.authority,
            body.len()
        );
        if let Some(cookie) = &self.cookie {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);

        let mut stream = TcpStream::connect(&self.authority).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        let raw = String::from_utf8(raw)?;
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .context("missing HTTP body separator")?;
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .context("missing HTTP status")?
            .parse::<u16>()?;
        let headers = lines.collect::<Vec<_>>().join("\n");
        if let Some(value) = headers
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .or_else(|| {
                headers
                    .lines()
                    .find_map(|line| line.strip_prefix("set-cookie: "))
            })
        {
            if value.starts_with("session_id=") {
                self.cookie = Some(value.split(';').next().unwrap_or(value).to_owned());
            }
        }
        Ok(Response {
            status,
            headers,
            body: body.to_owned(),
        })
    }

    async fn get(&mut self, path: &str) -> anyhow::Result<Response> {
        self.request("GET", path, None).await
    }

    async fn post(&mut self, path: &str, form: &str) -> anyhow::Result<Response> {
        self.request("POST", path, Some(form)).await
    }

    async fn csrf(&mut self, path: &str) -> anyhow::Result<String> {
        let html = self.get(path).await?.body;
        let marker = "name=\"csrf_token\" value=\"";
        let start = html.find(marker).context("CSRF token missing")? + marker.len();
        let end = html[start..].find('"').context("unterminated CSRF token")? + start;
        Ok(html[start..end].to_owned())
    }

    async fn submit(&mut self, path: &str, fields: &[(&str, &str)]) -> anyhow::Result<Response> {
        let csrf = self.csrf("/admin/settings").await?;
        let mut form = vec![("csrf_token", csrf.as_str())];
        form.extend_from_slice(fields);
        let encoded = form
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let response = self.post(path, &encoded).await?;
        if response.status != 303 {
            bail!(
                "form {path} returned {}: {}",
                response.status,
                response.body
            );
        }
        Ok(response)
    }
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn policy_fields(
    registration_pow: bool,
    registration_invite: bool,
) -> [(&'static str, &'static str); 9] {
    [
        ("reports_enabled", "1"),
        (
            "registration_pow_enabled",
            if registration_pow { "1" } else { "0" },
        ),
        (
            "registration_invite_enabled",
            if registration_invite { "1" } else { "0" },
        ),
        ("registration_captcha_enabled", "0"),
        ("login_pow_enabled", "1"),
        ("login_captcha_enabled", "0"),
        ("post_pow_enabled", "1"),
        ("post_captcha_enabled", "0"),
        ("captcha_difficulty", "low"),
    ]
}

async fn admin_login(http: &mut Http) -> anyhow::Result<()> {
    let csrf = http.csrf("/login").await?;
    let challenge: serde_json::Value =
        serde_json::from_str(&http.get("/api/pow/challenge?scope=login").await?.body)?;
    let salt = challenge["salt"].as_str().context("PoW salt")?;
    let target = challenge["challenge"].as_str().context("PoW challenge")?;
    let difficulty = challenge["difficulty"].as_u64().context("PoW difficulty")?;
    let mut nonce = 0_u64;
    let solution = loop {
        let input = format!("veil-forum-pow-v2{salt}{target}{nonce}");
        let digest = Sha256::digest(input.as_bytes());
        if digest[..difficulty.div_ceil(8) as usize]
            .iter()
            .all(|byte| *byte == 0)
        {
            break nonce;
        }
        nonce += 1;
        if nonce > 10_000_000 {
            bail!("PoW did not converge");
        }
    };
    let nonce = solution.to_string();
    let difficulty = challenge["difficulty"].to_string();
    let expires_at = challenge["expires_at"]
        .as_i64()
        .context("PoW expires_at")?
        .to_string();
    let hmac = challenge["hmac"].as_str().context("PoW hmac")?.to_owned();
    let fields = [
        ("csrf_token", csrf),
        ("username", "admin".to_owned()),
        ("password", ADMIN_PASSWORD.to_owned()),
        ("pow_challenge", target.to_owned()),
        ("pow_salt", salt.to_owned()),
        ("pow_difficulty", difficulty),
        ("pow_expires_at", expires_at),
        ("pow_hmac", hmac),
        ("pow_nonce", nonce),
        ("pow_scope", "login".to_owned()),
    ];
    let form = fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let response = http.post("/login", &form).await?;
    if response.status != 303 || !response.headers.contains("session_id=") {
        bail!(
            "administrator login failed: {} {}",
            response.status,
            response.body
        );
    }
    Ok(())
}

async fn config(pool: &PgPool, key: &str) -> anyhow::Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT value FROM configs WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?,
    )
}

async fn assert_subprocess_security(pool: &PgPool, report: &E2eReport) -> anyhow::Result<()> {
    let mut server = ServerProcess::start(pool, &report.log_path).await?;
    let mut http = Http::connect(&server.authority);
    admin_login(&mut http).await?;
    let csrf = http.csrf("/admin/settings").await?;
    let form = format!(
        "csrf_token={}&slug=general&name=Duplicate+General&description=constraint+e2e",
        encode(&csrf)
    );
    for _ in 0..2 {
        let response = http.post("/admin/board/create", &form).await?;
        assert_eq!(response.status, 400);
        assert_eq!(response.body, "unable to create board");
        let csp = response
            .header("content-security-policy")
            .with_context(|| {
                format!(
                    "missing CSP header; observed header names: {:?}",
                    response
                        .headers
                        .lines()
                        .filter_map(|line| line.split_once(':').map(|(key, _)| key))
                        .collect::<Vec<_>>()
                )
            })?;
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("wasm-unsafe-eval"));
        let forbidden = [
            "INSERT",
            "SELECT",
            "boards",
            "DatabaseError",
            "duplicate key",
        ];
        assert!(
            forbidden.iter().all(|text| !response.body.contains(text)),
            "public response exposed database details"
        );
    }

    let _ = server.child.kill();
    let _ = server.child.wait();
    let logs = std::fs::read_to_string(&report.log_path)?;
    let records = logs
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let error_records = records
        .iter()
        .filter(|record| record["fields"]["message"] == "internal request failed")
        .collect::<Vec<_>>();
    assert_eq!(error_records.len(), 2);
    let allowed = [
        "timestamp",
        "level",
        "fields",
        "target",
        "filename",
        "line_number",
        "message",
        "log.target",
        "span",
        "spans",
    ];
    let mut previous_request_id = 0;
    for record in error_records {
        assert_eq!(record["fields"]["operation"], "board creation");
        assert_eq!(
            record["fields"]["error_chain_kind"],
            "database_unique_violation"
        );
        let request_id = record["fields"]["request_id"]
            .as_u64()
            .context("request_id")?;
        assert!(request_id > previous_request_id);
        previous_request_id = request_id;
        assert!(
            record
                .as_object()
                .context("log record object")?
                .keys()
                .all(|key| allowed.contains(&key.as_str())),
            "application JSON log added an unexpected field"
        );
        let field_keys = record["fields"]
            .as_object()
            .context("log fields object")?
            .keys()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        assert_eq!(
            field_keys,
            HashSet::from(["message", "operation", "request_id", "error_chain_kind",])
        );
    }
    let database_url = pool.connect_options().to_url_lossy().to_string();
    let sensitive = [
        ADMIN_PASSWORD,
        "Aurora-Basalt8-Willow",
        "Cookie",
        "session_id",
        "token",
        "INSERT",
        "SELECT",
        "DatabaseError",
        "duplicate key",
        &database_url,
    ];
    assert!(
        sensitive.iter().all(|text| !logs.contains(text)),
        "application stderr JSON exposed credentials, request secrets, or SQL"
    );
    Ok(())
}

#[sqlx::test]
async fn admin_forms_change_http_behavior_and_postgresql_state(pool: PgPool) -> anyhow::Result<()> {
    let mut report = E2eReport::start();
    let store = Store { pool: pool.clone() };
    let hash = veil_forum::auth::hash_password(ADMIN_PASSWORD)?;
    sqlx::query("INSERT INTO users(username,password_hash,is_admin,created_at) VALUES('admin',$1,TRUE,now())")
        .bind(hash)
        .execute(&pool)
        .await?;
    let step = report.step("subprocess_database_error_security");
    assert_subprocess_security(&pool, &report).await?;
    report.complete(
        step,
        &[
            "real subprocess PostgreSQL constraint errors",
            "stable public error responses and CSP",
            "structured JSON request logs and redaction",
        ],
    );
    let step = report.step("http_admin_session");
    let state = handler::AppState {
        pow: pow::Manager::new(store.clone()),
        captcha: captcha::Manager::new(),
        limits: veil_forum::rate_limit::Limits::new(),
        secure_session_cookie: false,
        store: store.clone(),
    };
    let mut admin_http = Http::start(state.clone()).await?;
    let mut guest_http = Http::start(state).await?;
    admin_login(&mut admin_http).await?;
    assert!(
        admin_http
            .cookie
            .as_deref()
            .is_some_and(|cookie| cookie.starts_with("session_id=")),
        "administrator login did not retain a session cookie"
    );
    report.complete(step, &["real loopback HTTP and administrator session"]);

    let step = report.step("theme_and_maintenance");
    // Theme changes must affect an ordinary page, not only the settings page.
    admin_http
        .submit("/admin/config/theme", &[("theme_palette", "ocean")])
        .await?;
    let home = guest_http.get("/").await?;
    assert_eq!(home.status, 200);
    assert!(
        home.body.contains(r#"data-palette="ocean""#),
        "palette was not rendered"
    );

    // Maintenance mode must replace the public home page while preserving admin access.
    admin_http
        .submit(
            "/admin/config/maintenance",
            &[
                ("maintenance_enabled", "1"),
                ("maintenance_title", "Config E2E maintenance"),
                (
                    "maintenance_message",
                    "The form really closed the public forum",
                ),
                ("maintenance_eta", "after this assertion"),
            ],
        )
        .await?;
    let maintenance = guest_http.get("/").await?;
    assert_eq!(maintenance.status, 200);
    assert!(maintenance.body.contains("Config E2E maintenance"));
    assert!(maintenance
        .body
        .contains("The form really closed the public forum"));
    assert_eq!(admin_http.get("/admin/settings").await?.status, 200);
    admin_http.submit("/admin/config/maintenance", &[]).await?;
    assert!(guest_http.get("/").await?.body.contains("Boards"));
    assert!(admin_http
        .cookie
        .as_deref()
        .is_some_and(|cookie| cookie.starts_with("session_id=")));
    assert!(guest_http.cookie.is_none());
    report.complete(step, &["theme and maintenance behavior"]);

    let step = report.step("registration_and_policies");
    // Policy switches must change both rendered controls and direct POST enforcement.
    admin_http
        .submit("/admin/config/policies", &policy_fields(true, false))
        .await?;
    let register = guest_http.get("/register").await?;
    assert!(register.body.contains(r#"name="pow_nonce""#));
    assert!(!register.body.contains(r#"name="invite_code""#));
    let csrf = guest_http.csrf("/register").await?;
    let response = guest_http
        .post(
            "/register",
            &format!(
                "csrf_token={}&username=configuser&password=Glacier-Maple7-Raven",
                encode(&csrf)
            ),
        )
        .await?;
    assert_eq!(
        response.status, 403,
        "enabled PoW did not gate registration POST"
    );
    admin_http
        .submit("/admin/config/policies", &policy_fields(false, true))
        .await?;
    let register = guest_http.get("/register").await?;
    assert!(!register.body.contains(r#"name="pow_nonce""#));
    assert!(register.body.contains(r#"name="invite_code""#));
    let csrf = guest_http.csrf("/register").await?;
    let response = guest_http
        .post(
            "/register",
            &format!(
                "csrf_token={}&username=configuser&password=Glacier-Maple7-Raven",
                encode(&csrf)
            ),
        )
        .await?;
    assert_eq!(
        response.status, 400,
        "enabled invite policy did not gate registration POST"
    );
    admin_http
        .submit(
            "/admin/config/registration",
            &[("registration_mode", "closed")],
        )
        .await?;
    assert_eq!(guest_http.get("/register").await?.status, 403);
    let csrf = guest_http.csrf("/login").await?;
    let response = guest_http
        .post(
            "/register",
            &format!(
                "csrf_token={}&username=configuser&password=Glacier-Maple7-Raven",
                encode(&csrf)
            ),
        )
        .await?;
    assert_eq!(
        response.status, 403,
        "closed registration accepted a direct POST"
    );
    assert!(admin_http
        .cookie
        .as_deref()
        .is_some_and(|cookie| cookie.starts_with("session_id=")));
    assert!(guest_http.cookie.is_none());
    report.complete(
        step,
        &["registration PoW, invite, and closed-mode enforcement"],
    );

    let step = report.step("totp_and_normalization");
    // Disabling the feature overrides a still-selected all-users policy, both in
    // the page control and in subsequent admin access.
    admin_http
        .submit(
            "/admin/config/totp",
            &[("totp_enabled", "0"), ("totp_required", "all")],
        )
        .await?;
    let settings = admin_http.get("/admin/settings").await?;
    assert_eq!(
        settings.status, 200,
        "disabled TOTP feature still gated the administrator"
    );
    assert!(!settings
        .body
        .contains(r#"name="totp_required" value="all""#));
    assert!(settings.body.contains(r#"<option value="all" selected>"#));
    assert!(!settings
        .body
        .contains(r#"name="totp_enabled" value="1" checked"#));
    admin_http
        .submit(
            "/admin/config/totp",
            &[("totp_enabled", "1"), ("totp_required", "none")],
        )
        .await?;

    // Invalid enum and numeric inputs must be normalized, remain serviceable, and
    // be visible in the normal administrator page.
    admin_http
        .submit("/admin/config/theme", &[("theme_palette", "not-a-palette")])
        .await?;
    admin_http
        .submit(
            "/admin/config/registration",
            &[("registration_mode", "not-a-mode")],
        )
        .await?;
    admin_http
        .submit(
            "/admin/config/pow",
            &[
                ("pow_register_minutes", "NaN"),
                ("pow_login_minutes", "-4"),
                ("pow_post_minutes", "999"),
            ],
        )
        .await?;
    admin_http
        .submit(
            "/admin/config/totp",
            &[("totp_enabled", "1"), ("totp_required", "root")],
        )
        .await?;
    assert_eq!(admin_http.get("/healthz").await?.body, "ok");
    let settings = admin_http.get("/admin/settings").await?;
    assert!(settings.body.contains(r#"data-palette="veil""#) || settings.body.contains("Ocean"));
    assert!(settings.body.contains(r#"<option value="open" selected>"#));
    assert!(settings.body.contains(r#"<option value="none" selected>"#));
    report.complete(
        step,
        &[
            "TOTP feature and policy enforcement",
            "invalid input normalization",
        ],
    );

    let step = report.step("postgresql_final_state");
    let expected = [
        ("theme_palette", "veil"),
        ("maintenance_enabled", "0"),
        ("registration_mode", "open"),
        ("registration_pow_enabled", "0"),
        ("registration_invite_enabled", "1"),
        ("totp_enabled", "1"),
        ("totp_required", "none"),
        ("pow_register_minutes", "0.00500"),
        ("pow_login_minutes", "0.00500"),
        ("pow_post_minutes", "10.00000"),
    ];
    for (key, value) in expected {
        assert_eq!(
            config(&pool, key).await?.as_deref(),
            Some(value),
            "database value for {key}"
        );
    }
    report.complete(step, &["PostgreSQL final state"]);
    report.succeed()?;
    Ok(())
}
