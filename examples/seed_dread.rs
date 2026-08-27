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
            "综合版",
            "默认综合讨论区，灌水与公告",
            true,
            true,
        ),
        (
            "tech",
            "技术讨论",
            "Rust / Qubes / I2P / Tor 技术",
            true,
            true,
        ),
        ("sec", "安全研究", "OpSec、威胁模型、取证", false, true),
        ("market", "集市", "Vendor 公告与求购（模拟）", true, true),
        ("random", "随机版", "Meme、灌水、匿名树洞", true, true),
        (
            "qubes",
            "Qubes OS",
            "QubesOS 模板、vm、网络隔离",
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
    let vendor = *uid_map.get("vendorX").unwrap();
    let admin = *uid_map.get("dread_admin").unwrap();

    let board_threads: Vec<(&str, Vec<(&str, &str, &str)>)> = vec![
        ("general", vec![
            ("[公告] veil-forum v2 Dread 主题上线", "alice", "本次更新：\n\n- 1MB dread.css 瘦身至 19KB\n- 去内联样式，纯 Dread-Lite\n- PoW Argon2id 0.02分\n\n> 欢迎在 /d/tech 反馈样式问题。\n\n```rust\nprintln!(\"hello dread\");\n```\n\n| 功能 | 状态 |\n|---|---|\n| 暗色 | ✅ |\n| 响应式 | ✅ |\n"),
            ("新人报道，大家平时怎么保证匿名性？", "carol", "萌新，Qubes + Whonix 还是直接 Tails？\n\n目前用 Qubes 的 sys-net/sys-firewall/sys-whonix 隔离，感觉还是指纹多。\n\n求 OpSec 清单。"),
            ("PoW 调参讨论：0.02 分钟会不会太低", "researcher", "实测 0.02min ≈ 1.2s @ M1，垃圾贴成本太低。\n\n建议：\n- 注册 0.05\n- 发帖 0.03\n- 登录 0.01\n\n大家觉得？"),
            ("求助：i2pd 隧道 building 失败", "bob", "配置：\n\n```ini\n[ssu2]\nenabled = true\nport = 4567\n```\n\n日志：`Tunnel build failed: no suitable peers`，已连 40+ router，需手动添加 floodfill？"),
            ("[树洞] 今天被老板问为什么用 Qubes", "anon42", "我说为了隔离工作环境，他一脸看怪物的表情。\n\nAnonymous 模式真的很孤独，但安全。"),
        ]),
        ("tech", vec![
            ("Rust 1.77 编译 veil-forum 的 WASM PoW 踩坑", "alice", "argon2.wasm 在 CSP `wasm-unsafe-eval` 下才行，`worker-src 'self'` 必须加，否则 Worker  blocked。\n\n```js\nnew Worker('/static/pow-worker.js')\n```\n\n_踩坑记录留档_。"),
            ("分享：Qubes-Whonix 网关 + Mullvad 透传", "researcher", "拓扑：`sys-net → sys-firewall → sys-vpn(mullvad) → sys-whonix`，泄露测试用 `check.torproject.org`。\n\n> 注意：`qvm-prefs sys-whonix netvm sys-vpn` 后重启。"),
            ("I2P 内网 IRC 怎么搭最稳", "bob", "想在 veil 内网做一个 ephemer 的 IRC for OpSec 讨论，ephemeral 还是 persistent 隧道？\n\n有人试过 i2pd SAM + ngircd 吗？"),
            ("Tor vs I2P：论坛该选哪个承载", "carol", "Tor 慢但用户多，I2P 快但门槛高。\n\nveil 目前仅 127.0.0.1:8001，未来会考虑 onion / i2p 双栈。"),
            ("[代码审计] markdown.rs 的 XSS 过滤够吗", "alice", "目前用 `pulldown-cmark` + 自定义转义，禁 `img`/`raw html`。\n\n测试 payload：\n\n```html\n<script>alert(1)</script>\n[click](javascript:alert(1))\n```\n\n都已拦截。"),
            ("问：axum 的 `Handler` 怎么测 CSRF", "researcher", "现在表单只有 `_token` 占位，PoW 已防刷，但没有 CSRF token。\n\n要加 Double Submit 吗？"),
        ]),
        ("sec", vec![
            ("Qubes DisposableVM 取证不留痕实测", "researcher", "开 `disp1234` 浏览后 `qvm-remove`，检查 `~/.local/share/qubes` 无残留。\n\n但 `sys-net` 日志仍有 DHCP 握手，算泄露吗？"),
            ("GPG 密钥在 Qubes Split-GPG 下怎么备份", "carol", "用 `split-gpg` + `vault` VM，`paperkey` 打印。\n\n问题：离线 vault 怎么防拍屏？"),
            ("[情报] 某暗网市场 CDN 泄露真实 IP", "vendorX", "고정 N... 观察 `X-Forwarded-For` 误配置，提醒大家检查 `nginx real_ip_header`。\n\n_匿名发布，已核验_"),
            ("可信时间源：不用联网怎么对时", "bob", "Qubes 的 `sdwdate` 依赖 Tor，离线机怎么对时又不泄露？\n\n考虑 `tlsdate` + `onion` 时间源。"),
        ]),
        ("market", vec![
            ("[WTS] Qubes 定制模板 (付费咨询)", "vendorX", "| 项目 | 价格 |\n|---|---|\n| debian-12-minimal 硬化 | 0.002 BTC |\n| whonix-workstation 定制 | 0.005 BTC |\n\n_仅技术咨询，不涉及违规_"),
            ("[REQ] 求 I2P 长期在线 floodfill 节点", "anon42", "需求：24h 在线、带宽 >5MB/s、愿意共享NetDb，提供 `router.info`。\n\n报酬面议。"),
            ("[ANN] veil-forum 邀请码开放 10 枚", "dread_admin", "注册模式：`open` 期间无需邀请。\n\n后续切 `invite` 时会发码。关注 `/admin`。"),
        ]),
        ("random", vec![
            ("meme：当你把论坛 CSS 从 1MB 压到 19KB", "carol", "![meme](没有图，因为 CSP img-src 'none')\n\n文字 meme：`ship it`"),
            ("匿名树洞：你为什么来暗网论坛", "anon42", "1. 匿名倾诉\n2. 技术交流\n3. 找同类\n\n我 3。"),
            ("今日最离谱报错：`default-src 'none'` 把自己 css 都拦了", "alice", "调了半天发现 `style-src 'self'` 没加，`style.css` 被 CSP 拦成白板。😅"),
            ("投票：下一个主题色选什么", "bob", "选项：\n\n- 紫 `#9B59B6` (dread)\n- 绿 `#2ECC71` (veil)\n- 橙 `#E67E22`\n\n跟帖投票。"),
        ]),
        ("qubes", vec![
            ("[求助] Qubes 4.2 sys-usb 键盘失效", "carol", "更新后 `sys-usb` 启动失败，`qubes.InputKeyboard` 策略已加，`dom0` 日志 `qrexec policy denied`。"),
            ("TemplateVM 最小化：debian-12-minimal 清单", "researcher", "装完 800MB，删后 420MB：\n\n```bash\napt purge pulseaudio cups exim4\n```\n"),
            ("实战：AppVM 间 qrexec SSH", "bob", "用 `qrexec` + `qubes.ConnectTCP` 打隧道：\n\n```bash\nqrexec-client-vm work qubes.ConnectTCP+2222\n```\n"),
            ("Qubes 备份到离线盘加密方案", "alice", "用 `qvm-backup --compress --encrypt`，离线盘 LUKS + detached header。"),
        ]),
    ];

    let reply_templates = vec![
        ("确实，Qubes 隔离才是最稳的，Tails 适合临时。", false),
        ("补充：记得在 `sys-net` 关 IPv6，泄露过。", false),
        ("已复现，+1。", false),
        ("`cargo update` 后 wasm 体积小了 30%。", false),
        ("匿名回帖测试，看看显示是不是 Anonymous。", true),
        ("这个我踩过，`CSP` 把 `style-src` 拦了。", false),
        ("支持，建议直接上 0.05，垃圾贴成本翻倍。", false),
        ("图挂了，`img-src 'none'` 正常。", false),
        ("顶一下，信息密度终于对了。", false),
        ("```rust\nlet x = 42;\n```\n代码块测试", false),
        ("> 引用测试\n\n> 第二行引用\n\n正文回帖。", false),
        ("| a | b |\n|---|---|\n| 1 | 2 |\n\n表格测试", false),
        ("路过，mark。", true),
        ("vendor 验证过，靠谱。", false),
        ("已按此方案重配，稳了，谢。", false),
    ];

    let mut created_threads: Vec<(i64, i64)> = vec![]; // (tid, board_id)
    let pin_candidates: std::collections::HashSet<&str> = [
        "[公告] veil-forum v2 Dread 主题上线",
        "[ANN] veil-forum 邀请码开放 10 枚",
    ]
    .iter()
    .cloned()
    .collect();
    let lock_candidate = "投票：下一个主题色选什么";

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
                &format!("分页压测帖 {}", next_rand() % 10000),
                "分页测试正文，用于测试 Hot/Top 排序和投票数。",
                "<p>分页测试</p>",
                false,
            )
            .await?;
        for _ in 0..12 {
            let html = markdown::render("分页回帖 +1");
            store
                .create_post(tid, bid, bob, false, "分页回帖 +1", &html)
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
