# 变更记录 / Changelog

## Unreleased

- 修复五项安全问题：受信代理客户端隔离、Webhook DNS 固定、租户安全备份独立保留与全局冷却、SMTP 全局在途字节预算，以及 fragment 到 HttpOnly 会话的接码链接。
- 旧 `/code/<token>` 链接现在返回 `410`；请重新导出为 `/code/#token=...`。
- Fixed five security findings: trusted-proxy client isolation, DNS-pinned webhooks, isolated/cooldown-bound tenant safety backups, a process-wide SMTP DATA byte budget, and fragment-to-HttpOnly alias share sessions.
- Legacy `/code/<token>` links now return `410`; re-export share links to use `/code/#token=...`.

- 补齐标准贡献、变更和卸载入口；不改变运行行为。

## 1.0.0 — 2026-08-07

- 首个脱敏公开版本：只收邮件、SQLite、响应式后台、分域权限、公开取件链接、API、Webhook、备份恢复、健康检查与安全部署文档。

First sanitized public release with receive-only SMTP ingestion, SQLite, a responsive panel, scoped authorization, pickup links, APIs, webhooks, backup/restore, health checks, and hardened deployment documentation.
