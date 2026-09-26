# 项目代理规则

## 测试策略

- 复杂功能优先使用端到端（E2E）测试验证，E2E 是本项目的主要且默认测试机制。
- 编写或修改业务代码后，绝不新增单元测试。不要为 getter、常量、简单函数、内部实现细节或已由 E2E 覆盖的行为添加测试。
- 只有在端到端路径无法可靠隔离、且失败会造成可观察的安全、并发、持久化或协议风险时，才保留针对跨层边界的集成回归测试。删除只重复 E2E 或只验证实现细节的测试。
- 删除测试前，先确认它不能捕获 E2E 未覆盖的真实 bug，并在变更说明中记录删除理由。
- 必须孤立测试某个系统时，先在测试设计或提交说明中列出该系统所有可能的失败方式，再开始编写测试代码。覆盖这些失败方式，而不是测试私有实现细节。
- E2E 测试必须从用户或运维可观察的入口运行，覆盖真实数据库、HTTP/进程边界、错误路径和最终结果。不要用 mock 替代核心系统行为。
- 每次 E2E 验证结束时，生成一个可验证、可重复的产物，例如带版本、时间、输入摘要、结果和日志位置的报告或归档。产物不得包含密码、Token、私钥或其他凭证，并应能由同一条命令重新生成和校验。
- 测试命令、依赖服务、清理步骤和产物校验方式必须写入项目文档或 CI，避免只能由原作者复现。

### 本地验证环境

- 本地 PostgreSQL 通过 Unix socket 位于 `/var/run/postgresql`；本机 OS 用户
  对应的数据库角色需要 `CREATEDB`，`sqlx::test` 才能为每个用例创建隔离数据库。
- 验证用的临时数据库在用完后用
  `sudo -n -u postgres psql -c 'DROP DATABASE IF EXISTS <name>'` 清理。
- E2E 报告与基线产物一律写入 `target/`，不进入版本库。

### 构建产物位置

- 本机 Rust 构建产物**不落在仓库的 `target/`**，而是写到外部 USB 硬盘
  `/mnt/newsmy/rust-build/target`（466G NTFS，标签 Newsmy，源自 `sys-usb:sda2`）。
  根分区只有 28G，构建留在上面会撑爆。
- 生效机制是 **`~/.cargo/config.toml` 的 `build.target-dir`**，这是权威来源。
  它由 cargo 在任何进程里读取，**不依赖 shell 环境**，因此 cron、systemd、
  非登录 shell（`bash -c`）同样生效。不要只靠 `CARGO_TARGET_DIR`：它只在
  登录/交互 shell 里存在，其他执行方式会静默退回仓库内的 `target/`。
  `~/.bashrc` 与 `~/.profile` 里的 `CARGO_TARGET_DIR` 仅作为可见性便利保留。
- `~/bin/mount-newsmy.sh` 负责重新附加块设备并挂载；Qubes 在 VM 重启后会丢弃
  设备附加，shell 启动时经 `~/.config/rust-newsmy.sh` 自动恢复挂载并导出环境变量。
  重新附加走 `qac`（AppVM 内没有 `qvm-device`），失败时脚本会打印 dom0 侧的
  `qvm-device block attach` 恢复命令。挂载点存在但未挂载时，先跑该脚本再编译。
- 校验当前构建去向（**不要只看环境变量**）：
  `cargo metadata --format-version 1 --no-deps | grep -o '"target_directory":"[^"]*"'`
  应为 `/mnt/newsmy/rust-build/target`。
- 某个项目若自带 `.cargo/config.toml` 且含 `build.target-dir`，它**优先于**
  `~/.cargo/config.toml`，需单独改。
- 不要把仓库里的 `target/` 目录 `mv` 到该挂载点：NTFS 是 fuse（ntfs-3g），
  跨文件系统 `mv` 会退化成逐文件复制，几 GB 的构建树要几分钟且中途失败会留下
  半份副本。要腾地方就删掉重建。



## 工作流

- 修改测试后运行格式检查、静态检查和与变更相关的 E2E 验证，并检查最终差异中是否残留低价值单元测试。
- 未经用户明确授权，不执行 `git commit`、`git push`、发布或代发消息。
- 暂存改动必须逐项审阅后再 `git add`，不得用 `git add -A` 或 `git add .` 一次性扫入。提交前用 `git status --short` 和 `git diff --cached --name-only` 确认没有夹带无关文件。
- commit message 的作者与提交者固定为 `Marry102123 <Marry102123@users.noreply.github.com>`。除非用户明确要求，不添加 `Co-Authored-By`、`Co-authored-by`、`Signed-off-by` 或任何其他 trailer。

## 隐私与凭据

- 绝不把凭据写入仓库、配置、脚本、文档、测试、报告或 commit message。Token、API key、私钥、age identity、数据库口令一律走用户级设施（`gh auth`、GPG、环境变量），不落盘、不进历史。
- 绝不把个人隐私信息写入仓库或 git 元数据：真实邮箱、真实姓名、手机号、身份证件号、家庭住址、私人域名、SSH 主机别名、内网 IP、`/home/<用户名>/` 之类的本机绝对路径。示例数据必须明显是虚构的。
- 提交前扫描暂存内容，只看新增行：`git diff --cached -U0 | rg '^\+'`，确认没有真实凭据或个人信息。删除行里出现密钥通常是"从文件中移除"，不算泄露。
- 发布或推送前，审计完整 git 历史而不只是当前工作区：

  ```sh
  git log --all --format='%ae%n%ce' | sort -u          # 作者/提交者邮箱
  git grep -I -n -E '(ghp_|gho_|github_pat_|AKIA|BEGIN [A-Z ]*PRIVATE KEY)' $(git rev-list --all) --
  ```

  历史中的隐私信息会随每个 clone 分发，一旦推送就必须改写历史才能清除。
- 发现历史泄露时的处理顺序：先停止推送，用 `git bundle` 备份受影响的 ref 并记录全部 SHA，再改写，改写后逐项校验 commit message 与作者字段，最后才 force-push。改写已发布的 tag 会使该版本的来源不可验证，必须先取得用户明确同意。
- 仓库若为公开项目，假定所有内容都可被任何人检索：包括 commit 作者元数据、PR 作者、Release 正文、构建产物和 E2E 报告。
