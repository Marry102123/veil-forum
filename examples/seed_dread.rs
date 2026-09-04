use veil_forum::{auth, markdown, store::Store};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./data/forum.db".into());
    let store = Store::open(&db).await?;
    println!("seed on {}", db);

    // ensure users
    let users = vec![
        ("alice", false),
        ("bob", false),
        ("carol", false),
        ("dread_admin", true),
        ("anon42", false),
        ("researcher", false),
        ("vendorX", false),
    ];
    let mut uid_map = std::collections::HashMap::new();
    for (name, is_admin) in users {
        let existing = store.get_user_by_username(name).await?;
        if let Some(u) = existing {
            uid_map.insert(name, u.id);
            continue;
        }
        let seed_password = std::env::var("VEIL_SEED_PASSWORD")
            .expect("set VEIL_SEED_PASSWORD (12-128 chars) before running this demo seed");
        if seed_password.chars().count() < 12 || seed_password.chars().count() > 128 {
            anyhow::bail!("VEIL_SEED_PASSWORD must contain 12-128 characters");
        }
        let hash = auth::hash_password(&seed_password)?;
        let id = store.create_user(name, &hash, is_admin).await?;
        uid_map.insert(name, id);
        println!("user {} -> {}", name, id);
    }
    // ensure boards
    let boards = vec![
        (
            "general",
            "General",
            "General discussion, community chat, and announcements",
            true,
            true,
        ),
        (
            "tech",
            "Technology",
            "Rust, Qubes, I2P, and Tor engineering",
            true,
            true,
        ),
        (
            "sec",
            "Security Research",
            "Operational security, threat models, and forensics",
            false,
            true,
        ),
        (
            "market",
            "Marketplace",
            "Vendor announcements and simulated requests",
            true,
            true,
        ),
        (
            "random",
            "Off Topic",
            "Memes, casual chat, and anonymous notes",
            true,
            true,
        ),
        (
            "qubes",
            "Qubes OS",
            "Qubes templates, VMs, and network isolation",
            true,
            false,
        ),
    ];
    let mut bid_map = std::collections::HashMap::new();
    for (slug, name, desc, anon, guest) in boards {
        if let Some(b) = store.get_board_by_slug(slug).await? {
            bid_map.insert(slug, b.id);
            continue;
        }
        let id = store.create_board(slug, name, desc, anon, guest).await?;
        bid_map.insert(slug, id);
        println!("board /{} -> {}", slug, id);
    }

    // helper to create thread with replies
    // titles per board - dread-like
    let mut rng = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut next_rand = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng
    };
    let alice = *uid_map.get("alice").unwrap();
    let bob = *uid_map.get("bob").unwrap();
    let carol = *uid_map.get("carol").unwrap();
    let anon42 = *uid_map.get("anon42").unwrap();
    let researcher = *uid_map.get("researcher").unwrap();
    let _vendor = *uid_map.get("vendorX").unwrap();
    let _admin = *uid_map.get("dread_admin").unwrap();

    type ThreadSeed = (&'static str, &'static str, &'static str);
    type BoardSeed = (&'static str, Vec<ThreadSeed>);
    let board_threads: Vec<BoardSeed> = vec![
        ("general", vec![
            ("[Announcement] veil-forum demo community is live", "alice", "This demo includes:\n\n- 1MB dread.css reduced to 19KB\n- no inline styles, pure dark theme\n- PoW Argon2id 0.02分\n\n> Share UI feedback in /tech.\n\n```rust\nprintln!(\"hello dread\");\n```\n\n| 功能 | 状态 |\n|---|---|\n| 暗色 | ✅ |\n| 响应式 | ✅ |\n"),
            ("New here: how do you approach anonymity?", "carol", "I am new here. Qubes plus Whonix, or Tails for temporary sessions?\n\nI use sys-net, sys-firewall, and sys-whonix isolation, but browser fingerprinting still worries me.\n\nLooking for a practical OPSEC checklist."),
            ("PoW tuning: is 0.02 minutes too low?", "researcher", "At 0.02 minutes it takes about 1.2 seconds on an M1, so spam is too cheap.\n\nSuggestions:\n- registration 0.05\n- posting 0.03\n- login 0.01\n\nWhat do you think?"),
            ("Help: my i2pd tunnel is stuck building", "bob", "Configuration:\n\n```ini\n[ssu2]\nenabled = true\nport = 4567\n```\n\nLog:`Tunnel build failed: no suitable peers`，40+ routers are visible. Do I need to add a floodfill manually?"),
            ("[Anonymous] My manager asked why I use Qubes today", "anon42", "I said it isolates my work environments. They looked at me like I was describing a monster.\n\nAnonymous mode can feel lonely, but it is safer."),
        ]),
        ("tech", vec![
            ("WASM PoW build notes for Rust 1.77", "alice", "argon2.wasm 在 CSP `wasm-unsafe-eval` 下才行，`worker-src 'self'` 必须加，否则 Worker  blocked。\n\n```js\nnew Worker('/static/pow-worker.js')\n```\n\n_踩坑记录留档_。"),
            ("Showcase: Qubes-Whonix gateway with a VPN hop", "researcher", "拓扑：`sys-net → sys-firewall → sys-vpn(mullvad) → sys-whonix`，泄露测试用 `check.torproject.org`。\n\n> 注意：`qvm-prefs sys-whonix netvm sys-vpn` 后重启。"),
            ("What is the most reliable way to run IRC inside I2P?", "bob", "想在 veil 内网做一个 ephemer 的 IRC for OpSec 讨论，ephemeral 还是 persistent 隧道？\n\n有人试过 i2pd SAM + ngircd 吗？"),
            ("Tor vs I2P: which transport should host a forum?", "carol", "Tor 慢但用户多，I2P 快但门槛高。\n\nveil 目前仅 127.0.0.1:8001，未来会考虑 onion / i2p 双栈。"),
            ("[Code review] is markdown.rs XSS filtering sufficient?", "alice", "目前用 `pulldown-cmark` + 自定义转义，禁 `img`/`raw html`。\n\n测试 payload：\n\n```html\n<script>alert(1)</script>\n[click](javascript:alert(1))\n```\n\n都已拦截。"),
            ("Question: how should we test CSRF in axum handlers?", "researcher", "现在表单只有 `_token` 占位，PoW 已防刷，但没有 CSRF token。\n\n要加 Double Submit 吗？"),
        ]),
        ("sec", vec![
            ("Forensics notes from a Qubes DisposableVM", "researcher", "开 `disp1234` 浏览后 `qvm-remove`，检查 `~/.local/share/qubes` 无残留。\n\n但 `sys-net` 日志仍有 DHCP 握手，算泄露吗？"),
            ("How do you back up GPG keys with Qubes Split-GPG?", "carol", "用 `split-gpg` + `vault` VM，`paperkey` 打印。\n\n问题：离线 vault 怎么防拍屏？"),
            ("[Advisory] a CDN misconfiguration exposed an origin IP", "vendorX", "고정 N... 观察 `X-Forwarded-For` 误配置，提醒大家检查 `nginx real_ip_header`。\n\n_匿名发布，已核验_"),
            ("Trusted time sources for offline systems", "bob", "Qubes 的 `sdwdate` 依赖 Tor，离线机怎么对时又不泄露？\n\n考虑 `tlsdate` + `onion` 时间源。"),
        ]),
        ("market", vec![
            ("[WTS] Hardened Qubes template consulting", "vendorX", "| 项目 | 价格 |\n|---|---|\n| debian-12-minimal 硬化 | 0.002 BTC |\n| whonix-workstation 定制 | 0.005 BTC |\n\n_仅技术咨询，不涉及违规_"),
            ("[REQ] Seeking a long-lived I2P floodfill node", "anon42", "需求：24h 在线、带宽 >5MB/s、愿意共享NetDb，提供 `router.info`。\n\n报酬面议。"),
            ("[ANN] Ten demo invitations are available", "dread_admin", "注册模式：`open` 期间无需邀请。\n\n后续切 `invite` 时会发码。关注 `/admin`。"),
        ]),
        ("random", vec![
            ("Meme: when you reduce forum CSS from 1 MB to 19 KB", "carol", "![meme](没有图，因为 CSP img-src 'none')\n\n文字 meme：`ship it`"),
            ("Anonymous note: why did you join a privacy forum?", "anon42", "1. 匿名倾诉\n2. 技术交流\n3. 找同类\n\n我 3。"),
            ("Today's strangest bug: default-src none blocked our own CSS", "alice", "调了半天发现 `style-src 'self'` 没加，`style.css` 被 CSP 拦成白板。😅"),
            ("Poll: what accent color should we use next?", "bob", "选项：\n\n- 紫 `#9B59B6` (dread)\n- 绿 `#2ECC71` (veil)\n- 橙 `#E67E22`\n\n跟帖投票。"),
        ]),
        ("qubes", vec![
            ("[Help] keyboard stopped working in Qubes 4.2 sys-usb", "carol", "更新后 `sys-usb` 启动失败，`qubes.InputKeyboard` 策略已加，`dom0` 日志 `qrexec policy denied`。"),
            ("Minimal TemplateVM: a debian-12-minimal checklist", "researcher", "装完 800MB，删后 420MB：\n\n```bash\napt purge pulseaudio cups exim4\n```\n"),
            ("In practice: qrexec SSH between AppVMs", "bob", "用 `qrexec` + `qubes.ConnectTCP` 打隧道：\n\n```bash\nqrexec-client-vm work qubes.ConnectTCP+2222\n```\n"),
            ("Encrypting Qubes backups on an offline drive", "alice", "用 `qvm-backup --compress --encrypt`，离线盘 LUKS + detached header。"),
        ]),
    ];

    let reply_templates = vec![
        (
            "Qubes isolation is the safer default; Tails is great for temporary sessions.",
            false,
        ),
        (
            "Also disable IPv6 in sys-net. It has caused leaks before.",
            false,
        ),
        ("Reproduced. +1.", false),
        ("`cargo update` 后 wasm 体积小了 30%。", false),
        ("Testing an anonymous reply label.", true),
        ("这个我踩过，`CSP` 把 `style-src` 拦了。", false),
        ("支持，建议直接上 0.05，垃圾贴成本翻倍。", false),
        ("The image is intentionally blocked by the CSP.", false),
        (
            "Boosting this. The signal-to-noise ratio is excellent.",
            false,
        ),
        ("```rust\nlet x = 42;\n```\n代码块测试", false),
        ("> 引用测试\n\n> 第二行引用\n\n正文回帖。", false),
        ("| a | b |\n|---|---|\n| 1 | 2 |\n\n表格测试", false),
        ("Bookmarking this for later.", true),
        ("The vendor has been verified by the community.", false),
        ("Reconfigured this way and it is stable now, thanks.", false),
    ];

    let mut created_threads: Vec<(i64, i64)> = vec![]; // (tid, board_id)
    let pin_candidates: std::collections::HashSet<&str> = [
        "[Announcement] veil-forum demo community is live",
        "[ANN] Ten demo invitations are available",
    ]
    .iter()
    .cloned()
    .collect();
    let lock_candidate = "Poll: what accent color should we use next?";

    for (board_slug, threads) in board_threads.iter() {
        let bid = *bid_map.get(board_slug).unwrap();
        for (title, author_name, md) in threads {
            let author = *uid_map.get(author_name).unwrap_or(&alice);
            let is_anon = title.contains("[树洞]") || title.contains("匿名树洞");
            let html = markdown::render(md);
            // create_thread inserts first post as OP, but we want replies separate, so thread's content is OP
            let tid = store
                .create_thread(bid, author, title, md, &html, is_anon)
                .await?;
            // after create, maybe pin/lock
            if pin_candidates.contains(*title) {
                store.set_thread_pinned(tid, true).await?;
                println!("pin {}", title);
            }
            if title.contains(lock_candidate) {
                // leave open for now, later lock after replies? We'll lock after seeding replies to show locked flair
            }
            created_threads.push((tid, bid));
            // add 2-7 replies per thread
            let n_replies = (next_rand() % 6) as usize + 2;
            for i in 0..n_replies {
                let (reply_md, anon) =
                    &reply_templates[(next_rand() as usize) % reply_templates.len()];
                let mut md_full = reply_md.to_string();
                // sprinkle some variation
                if i == 0 && *board_slug == "tech" {
                    md_full = format!("{}\n\n_回帖 #{} by 交易_ ", md_full, i + 1);
                }
                let reply_author = match next_rand() % 5 {
                    0 => alice,
                    1 => bob,
                    2 => carol,
                    3 => researcher,
                    _ => anon42,
                };
                let html2 = markdown::render(&md_full);
                store
                    .create_post(tid, bid, reply_author, *anon, &md_full, &html2)
                    .await?;
            }
            // randomly make some recent bump: update last_reply_at to recent hours ago
            let hours_ago = (next_rand() % 72) as i64;
            let bump_time = chrono::Utc::now() - chrono::Duration::hours(hours_ago);
            let bump_str = bump_time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
            sqlx::query("UPDATE threads SET last_reply_at=?, reply_count=(SELECT COUNT(*)-1 FROM posts WHERE thread_id=?) WHERE id=?")
                .bind(&bump_str).bind(tid).bind(tid).execute(&store.pool).await?;
            println!(
                "thread {} in /{} with {} replies, bump {}h ago",
                tid, board_slug, n_replies, hours_ago
            );
        }
    }
    // lock one thread
    for (tid, _) in &created_threads {
        if let Some(th) = store.get_thread(*tid).await? {
            if th.title.contains(lock_candidate) {
                store.set_thread_locked(*tid, true).await?;
                println!("lock tid {}", tid);
            }
        }
    }
    // add some extra hot threads with many replies for pagination test
    for _ in 0..4 {
        let bid = *bid_map.get("tech").unwrap();
        let tid = store
            .create_thread(
                bid,
                alice,
                &format!("Pagination load-test thread {}", next_rand() % 10000),
                "Pagination test content for Hot, Top, and vote sorting.",
                "<p>分页测试</p>",
                false,
            )
            .await?;
        for _ in 0..12 {
            let html = markdown::render("Pagination reply +1");
            store
                .create_post(tid, bid, bob, false, "Pagination reply +1", &html)
                .await?;
        }
        println!("extra hot tid {}", tid);
    }

    let (c_threads,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM threads")
        .fetch_one(&store.pool)
        .await?;
    let (c_posts,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts")
        .fetch_one(&store.pool)
        .await?;
    let (c_boards,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boards")
        .fetch_one(&store.pool)
        .await?;
    let (c_users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&store.pool)
        .await?;
    println!(
        "done: boards {} threads {} posts {} users {}",
        c_boards, c_threads, c_posts, c_users
    );
    Ok(())
}
