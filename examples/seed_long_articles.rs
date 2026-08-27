use veil_forum::{markdown, store::Store};

const ARTICLES: &[(&str, &str, &str)] = &[
    (
        "[排版测试] 一次完整的 Qubes 网络隔离复盘",
        "alice",
        r#"## 背景

这是一篇用于检查主题页长内容排版的文章。真实的技术讨论往往不会只有两三行，而是包含背景、决策过程、失败记录和最后的操作清单。页面需要让这些内容保持可读，同时不能把右侧栏或其他回复挤出主栏。

## 我的拓扑

`sys-net` 只负责硬件网络，`sys-firewall` 负责基础规则，工作环境通过独立的 VPN 网关进入 Whonix。每个层级都有明确职责，排查时先确认链路，再确认 DNS、时间同步和应用层连接。

> 重要：不要把“浏览器能打开网页”当作网络隔离已经正确。还需要分别验证默认路由、DNS 请求、IPv6、时钟同步和异常断网行为。

## 检查清单

1. 确认 AppVM 使用预期的 NetVM。
2. 确认防火墙规则没有允许意外的出站路径。
3. 关闭不需要的 IPv6 通道。
4. 在网关停止后确认工作环境无法继续联网。

## 结论

这类文章的段落长度会随着说明自然变化。排版最重要的是稳定的行宽、清楚的标题层级和不被截断的代码块。"#,
    ),
    (
        "[排版测试] 从日志到结论：一次漫长的故障记录",
        "researcher",
        r#"## 现象

服务启动成功，首页也能访问，但提交回帖时偶尔出现超时。第一次观察到问题是在高延迟网络环境下，第二次则发生在浏览器后台标签页恢复之后。下面保留完整记录，故意使用较长段落来观察换行和卡片高度变化。

### 时间线

| 时间 | 事件 | 结果 |
| --- | --- | --- |
| 09:10 | 启动服务 | 正常 |
| 09:14 | 打开主题页 | 正常 |
| 09:21 | 提交长回复 | 延迟 |
| 09:27 | 重试请求 | 成功 |

日志中的关键行：

```text
request received: POST /t/32/reply
pow challenge: valid
database write: committed
response: 303 See Other
```

排查时不要只看最后一条错误。需要把请求生命周期拆开，分别确认浏览器是否提交了完整表单、PoW 是否完成、数据库事务是否提交，以及重定向之后页面是否真的读取到了新数据。

### 复盘

最终发现问题来自测试环境里多个服务进程同时尝试监听同一端口。修复后，编译、重启、健康检查和页面抓取都应作为一个连续流程执行。"#,
    ),
    (
        "[排版测试] 超长文本与代码块的窄栏适配",
        "bob",
        r#"这篇文章专门测试窄主栏中的连续文字、行内代码和很长的不可断 URL。

`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.invalid/path/to/a/very/long/resource?with=many&parameters=true`

### 观察点

- 普通中文段落应该自然换行。
- 行内代码不应该撑破卡片。
- 代码块应该能够横向滚动，而不是撑宽页面。
- 引用和表格应该保持在主栏内部。

```rust
fn render_long_article(input: &str) -> String {
    let normalized = input.trim();
    format!("<article>{}</article>", normalized)
}
```

> 如果一篇长文让右侧栏消失，或者页面出现横向滚动条，那么问题通常是 `min-width`、`overflow-wrap` 或代码块的 `overflow` 没有正确设置。

文章末尾再补一段较长的说明，用来测试连续多段之间的节奏。内容应该足够密集，但标题、元信息、正文和回复操作仍然需要保持明确的视觉层级。"#,
    ),
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./data/forum.db".into());
    let store = Store::open(&db).await?;
    let board = store
        .get_board_by_slug("general")
        .await?
        .expect("general board");
    let author_names = ["alice", "researcher", "bob"];

    for (idx, (title, author_name, body)) in ARTICLES.iter().enumerate() {
        let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM threads WHERE title = ?")
            .bind(*title)
            .fetch_one(&store.pool)
            .await?;
        if exists > 0 {
            println!("exists: {}", title);
            continue;
        }
        let author = store
            .get_user_by_username(author_name)
            .await?
            .expect("seed author");
        let html = markdown::render(body);
        let thread_id = store
            .create_thread(board.id, author.id, title, body, &html, false)
            .await?;
        let reply_author = store
            .get_user_by_username(author_names[(idx + 1) % author_names.len()])
            .await?
            .expect("reply author");
        let reply = format!("补充测试：这篇长文的第 {} 条独立回复也用于观察引用、元信息和卡片间距。\n\n> 长内容应保持统一主栏宽度。", idx + 1);
        let reply_html = markdown::render(&reply);
        store
            .create_post(
                thread_id,
                board.id,
                reply_author.id,
                false,
                &reply,
                &reply_html,
            )
            .await?;
        println!("created: {} -> /t/{}", title, thread_id);
    }
    Ok(())
}
