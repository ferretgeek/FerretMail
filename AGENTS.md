# Project collaboration rules

- Read `README.md`, `技术文档.md`, and the relevant tests before changing behavior.
- Keep the project dependency-free at runtime unless a change has a clear, documented benefit.
- Never commit `.env`, databases, backups, messages, attachments, logs, tokens, real domains, server addresses, or live screenshots.
- Use only `example.com`, reserved documentation IP ranges, `localhost`, and obvious placeholder values in examples and tests.
- Preserve receive-only behavior, scoped authorization, rate limits, atomic backups, retention boundaries, and explicit error states.
- Run `python -m py_compile ferret_mail_service.py` and `python -m unittest -v test_ferret_mail_service.py` before delivery.
- Update bilingual `README.md` and relevant documentation when public behavior changes.
