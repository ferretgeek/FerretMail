# 贡献指南 / Contributing

先阅读 [`AGENTS.md`](./AGENTS.md)、[`技术文档.md`](./技术文档.md) 和相关测试。保持运行时标准库实现、只收不发、分域权限、限流、原子备份、显式错误与日志脱敏；不要提交真实域名、地址、Token、邮箱、邮件、附件、数据库、备份、日志或部署截图。

Read the project rules, technical reference, and relevant tests first. Preserve the standard-library runtime, receive-only scope, per-domain authorization, rate limits, atomic backup behavior, explicit errors, and redacted logs. Never submit real domains, addresses, tokens, mailboxes, messages, attachments, databases, backups, logs, or deployment screenshots.

提交前运行：

```bash
python -m py_compile ferret_mail_service.py
python -m unittest -v test_ferret_mail_service.py
```

安全问题按 [`SECURITY.md`](./SECURITY.md) 私密报告。功能或配置变化必须同步中英文 README、技术文档、部署教程、`.env.example` 与变更记录。

Report security issues privately through `SECURITY.md`. Behavior or configuration changes must update both languages, deployment/technical docs, `.env.example`, and the changelog.
