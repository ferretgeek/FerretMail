<p align="center">
  <img src="docs/images/social-preview.png" alt="Domain mail inbox — a receive-only mailbox for your own domain" width="100%">
</p>

# Domain mail inbox

[中文](README.md) · English

[![CI](https://github.com/ferretgeek/domain-mail-inbox/actions/workflows/ci.yml/badge.svg)](https://github.com/ferretgeek/domain-mail-inbox/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Standard library](https://img.shields.io/badge/dependencies-standard_library-2F6F6D)](ferret_mail_service.py)
[![Receive only](https://img.shields.io/badge/mail-receive_only-BB6A42)](#what-it-doesnt-do)
[![MIT](https://img.shields.io/badge/license-MIT-284B63)](LICENSE)

> Make your own domain actually receive mail — at any `name@yourdomain`.

## Why this exists

You own a domain. When signing up for things, you'd like a different address per site, so when one of them leaks your address you know exactly who did it.

Hosted mail providers can do that, but they either charge per mailbox or keep all your incoming mail on their servers. Running a full mail stack yourself (Postfix + Dovecot + antispam + certificates + …) is an entirely different scale of project — and you probably **don't need to send mail at all.**

So this project does half the job: **receive only.**

Any `anything@yourdomain` receives mail immediately, with no need to create it first. Then read messages, copy verification codes, inspect links, and download attachments in the web UI — or pull them over an HTTP API. All data stays on your machine in one SQLite file.

The whole service is **one Python file using only the standard library.**

## Interface

![Dashboard preview](docs/images/dashboard.png)

## What it does

- **Multi-domain receiving** — multiple root domains, subdomains, and automatically created aliases.
- **Finish the job in the browser** — search and read messages, copy codes, inspect links, download attachments.
- **Four themes** — Skyline, Moyu, and Minimal light palettes plus a `#17191d` deep-gray dark mode, remembered globally.
- **Scoped access** — issue per-domain admin tokens, or create a narrow public link that can only see one alias.
- **Interfaces for programs** — long-polling API, webhooks, DNS record checks, capacity quotas, rate limits, and operation logs.
- **Looks after itself** — automatic SQLite backups plus health checks on HTTP, SMTP, storage, and backup status.

## Quick start

```bash
cp .env.example .env
# Edit .env: at minimum set a long random PANEL_TOKEN, MAIL_DOMAIN, and PUBLIC_IP
set -a && . ./.env && set +a
python3 ferret_mail_service.py
```

For production, follow the [deployment guide](部署教程.md) to run as a non-root user under systemd, behind HTTPS, with restricted file permissions. Every variable is listed in [.env.example](.env.example).

## What a public deployment requires

Three unavoidable prerequisites — confirm them before you start:

1. **A static public IP with TCP port 25 reachable.** Many cloud providers and residential ISPs block port 25 by default and require a request to unblock.
2. **Correct MX / A records** (the service includes a DNS check to verify them).
3. **An HTTPS reverse proxy in front of the admin UI.**

## Worth noting technically

**One Python file, standard library only.** SMTP ingestion, the HTTP server, the responsive admin UI, SQLite storage, verification-code extraction, and backups all live there with no third-party runtime dependencies. The reasoning is the same as the game-server project: mail is something you install and hope not to touch for three years, and fewer dependencies is fewer things that rot.

**Share-link tokens never reach server logs.** Single-alias pickup links carry the capability token in the URL **fragment** (after `#`), which browsers never send to the server — so it can't appear in reverse-proxy or access logs. The page immediately exchanges it for an HttpOnly session cookie. Legacy path-token links need to be re-exported.

**Long polling instead of hammering.** A `wait` parameter lets callers block for new mail rather than issuing a `GET` every second. Combine it with each message's stable `id` for deduplication.

**The four health checks are separate.** HTTP, SMTP, storage, and backup status each report independently — "the service is up" and "backups are still running" are different questions, and merging them into one green light tells you nothing.

**Rate limits and quotas are per domain.** Capacity quotas, rate limits, and operation logs all work per domain, so one domain getting hammered doesn't take the others down.

## What it doesn't do

- **It doesn't send mail.** No outbound SMTP, no SPF/DKIM signing, not usable as a sending server.
- No IMAP, no calendar, not a full mail client.
- No spam scoring — you judge what arrives.
- Good for: personal domains, test environments, code archives, small internal tools.
  Not for: your primary mailbox, team collaboration, or any outbound mail service.

## Privacy and security

This repository contains no deployment database, message, credential, real domain, server address, or production log.

**Never commit** `.env`, SQLite files, backups, downloaded attachments, or screenshots from a live inbox.

## More documentation

[Deployment guide](部署教程.md) · [Technical reference](技术文档.md) · [Configuration template](.env.example) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

MIT License — see [LICENSE](LICENSE).
