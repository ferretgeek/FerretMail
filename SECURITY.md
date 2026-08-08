# Security Policy

## Supported version

Security fixes target the latest commit on `main`.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for this repository. Do not open a public issue containing credentials, production domains, server addresses, mail contents, access tokens, or an exploit that exposes them.

Include the affected endpoint or component, impact, reproduction steps using synthetic data, and any suggested mitigation. You may omit or redact any identifying deployment details.

## Deployment responsibilities

- Generate a unique administrator token of at least 32 random bytes.
- Keep environment files, databases, backups, and attachments readable only by the service account.
- Put the web UI behind HTTPS; do not expose the administrator token over plain HTTP.
- Restrict inbound ports to those required and keep the runtime patched.
- Keep independent, encrypted backups and test recovery.

If a real token has been exposed, rotate it immediately. Removing it from the current file does not invalidate the leaked value.
