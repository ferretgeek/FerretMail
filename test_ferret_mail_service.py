import asyncio
import importlib.util
import io
import json
import os
import pathlib
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from email.message import EmailMessage


TEST_ROOT = tempfile.TemporaryDirectory(prefix="ferret-mail-tests-")
TEST_PATH = pathlib.Path(TEST_ROOT.name)
os.environ.update(
    {
        "PANEL_TOKEN": "test-admin-token-" + "x" * 32,
        "MAIL_DOMAIN": "example.com",
        "MAIL_ROOT_DOMAINS": "example.com",
        "MAIL_EXTRA_DOMAINS": "",
        "PUBLIC_IP": "127.0.0.1",
        "DB_PATH": str(TEST_PATH / "inbox.sqlite3"),
        "BACKUP_DIR": str(TEST_PATH / "backups"),
        "HTTP_HOST": "127.0.0.1",
        "HTTP_PORT": "18710",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": "12525",
        "TRUSTED_HOSTS": "127.0.0.1,localhost,example.com,*.example.com",
        "CORS_ALLOWED_ORIGINS": "",
        "MIN_DISK_FREE_BYTES": str(64 * 1024 * 1024),
    }
)

MODULE_PATH = pathlib.Path(__file__).with_name("ferret_mail_service.py")
SPEC = importlib.util.spec_from_file_location("ferret_mail_service_under_test", MODULE_PATH)
mail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mail)


def reset_state():
    with mail.db() as con:
        con.execute("DELETE FROM attachments")
        con.execute("DELETE FROM mails")
        con.execute("DELETE FROM aliases")
        con.execute("DELETE FROM operation_logs")
        con.execute("DELETE FROM failed_mails")
        con.execute("DELETE FROM cleanup_runs")
        con.execute("DELETE FROM backup_runs")
        con.execute("DELETE FROM mail_domains WHERE domain<>?", (mail.DOMAIN,))
        con.execute("DELETE FROM domain_usage WHERE domain<>?", (mail.DOMAIN,))
        con.execute(
            """
            UPDATE mail_domains SET
                enabled=1,token_disabled=0,retention_hours=?,cleanup_max_mails=0,
                alias_limit=?,mail_limit=?,storage_limit_mb=?,webhook_url='',webhook_enabled=0
            WHERE domain=?
            """,
            (
                mail.RETENTION_HOURS,
                mail.DEFAULT_ALIAS_LIMIT,
                mail.DEFAULT_MAIL_LIMIT,
                mail.DEFAULT_STORAGE_LIMIT_MB,
                mail.DOMAIN,
            ),
        )
    for path in pathlib.Path(mail.BACKUP_DIR).glob("*"):
        if path.is_file():
            path.unlink()
    mail.invalidate_domain_cache()
    with mail._RATE_LOCK:
        mail._RATE_BUCKETS.clear()
    with mail._HEALTH_LOCK:
        mail._HEALTH_CACHE.update({"expires": 0.0, "data": None})
    with mail._INTEGRITY_LOCK:
        mail._INTEGRITY_STATE.update({"checked_at": 0, "ok": None, "message": "尚未检查"})


def message_bytes(subject="Your verification code is 123456", body="Code: 123456", attachment=False):
    msg = EmailMessage()
    msg["From"] = "sender@example.net"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment:
        msg.add_attachment(b"attachment-data", maintype="application", subtype="octet-stream", filename="test.bin")
    return msg.as_bytes()


class CoreTests(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_runtime_config_and_security_boundaries(self):
        mail.validate_runtime_config()
        original_hosts = mail.TRUSTED_HOSTS
        original_origins = mail.CORS_ALLOWED_ORIGINS
        try:
            mail.TRUSTED_HOSTS = {"panel.example.com", "*.trusted.example.com"}
            mail.CORS_ALLOWED_ORIGINS = {"https://app.example.com"}
            self.assertTrue(mail.host_allowed("panel.example.com:8710"))
            self.assertTrue(mail.host_allowed("a.trusted.example.com"))
            self.assertFalse(mail.host_allowed("example.com"))
            self.assertFalse(mail.host_allowed(""))
            self.assertTrue(mail.origin_allowed("https://app.example.com/"))
            self.assertFalse(mail.origin_allowed("https://panel.example.com"))
        finally:
            mail.TRUSTED_HOSTS = original_hosts
            mail.CORS_ALLOWED_ORIGINS = original_origins

    def test_code_extraction_positive_and_negative(self):
        self.assertEqual(mail.extract_code("登录验证码 ８２-４１-９０", "五分钟内有效"), "824190")
        self.assertEqual(mail.extract_code("Security code", "Your one-time code is A7K-29Q"), "A7K29Q")
        self.assertEqual(mail.extract_code("订单 20260807", "物流单号 12345678"), "")
        self.assertEqual(mail.extract_code("Notice", "No verification code is required. Order 654321."), "")

    def test_store_is_atomic_and_attachment_delete_trigger_works(self):
        ids = mail.store_mails(
            "sender@example.net",
            ["alpha@example.com", "beta@example.com"],
            message_bytes(attachment=True),
        )
        self.assertEqual(len(ids), 2)
        self.assertEqual(mail.mail_usage("example.com")[0], 2)
        self.assertEqual(mail.alias_count("example.com"), 2)
        with mail.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM attachments").fetchone()[0], 2)
            self.assertEqual(con.execute("SELECT verification_code FROM mails LIMIT 1").fetchone()[0], "123456")
            con.execute("DELETE FROM mails WHERE id=?", (ids[0],))
        with mail.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM attachments WHERE mail_id=?", (ids[0],)).fetchone()[0], 0)

        reset_state()
        mail.update_domain_settings("example.com", {"mail_limit": 1})
        with self.assertRaisesRegex(ValueError, "mail limit"):
            mail.store_mails(
                "sender@example.net",
                ["alpha@example.com", "beta@example.com"],
                message_bytes(),
            )
        with mail.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM mails").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM aliases").fetchone()[0], 0)

    def test_concurrent_delivery_keeps_usage_counters_consistent(self):
        original_log = mail.safe_log
        mail.safe_log = lambda _message: None
        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [
                    pool.submit(
                        mail.store_mail,
                        "sender@example.net",
                        f"user{i}@example.com",
                        message_bytes(subject=f"Code {100000 + i}", body=f"Verification code: {100000 + i}"),
                    )
                    for i in range(24)
                ]
                ids = [future.result(timeout=20) for future in futures]
        finally:
            mail.safe_log = original_log
        self.assertEqual(len(set(ids)), 24)
        self.assertEqual(mail.mail_usage("example.com")[0], 24)
        self.assertEqual(mail.alias_count("example.com"), 24)
        with mail.db() as con:
            actual = con.execute("SELECT COUNT(*) FROM mails WHERE domain='example.com'").fetchone()[0]
        self.assertEqual(actual, 24)

    def test_db_context_rolls_back_and_exclusive_maintenance_blocks_new_work(self):
        with self.assertRaises(RuntimeError):
            with mail.db() as con:
                con.execute(
                    "INSERT INTO aliases (email,domain,note,created_at) VALUES (?,?,?,?)",
                    ("rollback@example.com", "example.com", "test", mail.now_ms()),
                )
                raise RuntimeError("rollback")
        with mail.db() as con:
            self.assertIsNone(con.execute("SELECT 1 FROM aliases WHERE email='rollback@example.com'").fetchone())

        entered = threading.Event()
        completed = threading.Event()

        def reader():
            entered.set()
            with mail.db() as con:
                con.execute("SELECT 1").fetchone()
            completed.set()

        with mail.exclusive_db_maintenance():
            thread = threading.Thread(target=reader)
            thread.start()
            self.assertTrue(entered.wait(2))
            self.assertFalse(completed.wait(0.15))
        thread.join(2)
        self.assertTrue(completed.is_set())

    def test_backup_is_atomic_valid_and_restorable(self):
        mail.store_mail("sender@example.net", "before@example.com", message_bytes())
        backup = mail.create_backup("test")
        backup_path = pathlib.Path(backup["path"])
        self.assertTrue(backup_path.is_file())
        self.assertGreater(backup_path.stat().st_size, 0)
        self.assertFalse(list(pathlib.Path(mail.BACKUP_DIR).glob("*.tmp")))
        con = sqlite3.connect(backup_path)
        try:
            self.assertEqual(con.execute("PRAGMA quick_check(1)").fetchone()[0], "ok")
        finally:
            con.close()

        mail.store_mail("sender@example.net", "after@example.com", message_bytes())
        mail.restore_backup(backup_path.name)
        with mail.db() as con:
            addresses = {row[0] for row in con.execute("SELECT to_email FROM mails")}
        self.assertIn("before@example.com", addresses)
        self.assertNotIn("after@example.com", addresses)
        self.assertTrue(mail.database_integrity_check(force=True)["ok"])

    def test_dynamic_docs_do_not_leak_admin_token(self):
        self.assertNotIn(mail.PANEL_TOKEN, mail.api_docs_markdown("http://example.com"))
        self.assertNotIn(mail.PANEL_TOKEN, mail.usage_guide_markdown("http://example.com"))

    def test_html_mail_is_sanitized_and_rendered_in_a_restricted_iframe(self):
        unsafe = '<script>alert(1)</script><img src="https://tracker.example/x"><a href="javascript:alert(2)" onclick="x()">open</a>'
        cleaned = mail._safe_html(unsafe)
        self.assertNotIn("<script", cleaned.lower())
        self.assertNotIn("<img", cleaned.lower())
        self.assertNotIn("javascript:", cleaned.lower())
        self.assertNotIn("onclick", cleaned.lower())
        self.assertIn("open", cleaned)
        malformed = mail._safe_html('<scr<script>ipt>alert(3)</scr</script>ipt><p>still readable</p>')
        self.assertNotIn("<script", malformed.lower())
        self.assertIn("still readable", malformed)
        self.assertIn('sandbox="allow-popups allow-popups-to-escape-sandbox"', mail.MAIL_REVIEW_HTML)
        self.assertNotIn('sandbox="allow-scripts', mail.MAIL_REVIEW_HTML)
        self.assertNotIn("allow-same-origin", mail.MAIL_REVIEW_HTML)

    def test_safe_log_removes_control_characters_and_limits_length(self):
        output = io.StringIO()
        with redirect_stdout(output):
            mail.safe_log("ok\x00\x1b" + "x" * 3000)
        value = output.getvalue()
        self.assertNotIn("\x00", value)
        self.assertNotIn("\x1b", value)
        self.assertLessEqual(len(value.rstrip("\n")), 2000)


class HttpTests(unittest.TestCase):
    def setUp(self):
        reset_state()
        mail.database_integrity_check(force=True)
        mail.create_backup("test")
        self.server = mail.BoundedThreadingHTTPServer(("127.0.0.1", 0), mail.ApiHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, path, method="GET", headers=None, data=None):
        request = urllib.request.Request(self.base + path, method=method, headers=headers or {}, data=data)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def test_head_invalid_input_host_and_cors(self):
        status, headers, body = self.request("/mail", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(headers["Content-Length"]), 1000)

        status, _headers, body = self.request(
            "/ui-api/message?id=not-a-number",
            headers={"Authorization": mail.PANEL_TOKEN},
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["code"], 400)

        status, _headers, _body = self.request("/health", headers={"Host": "evil.example.net"})
        self.assertEqual(status, 421)

        original_origins = mail.CORS_ALLOWED_ORIGINS
        try:
            mail.CORS_ALLOWED_ORIGINS = set()
            status, _headers, _body = self.request("/", method="OPTIONS", headers={"Origin": "https://example.com"})
            self.assertEqual(status, 403)
            mail.CORS_ALLOWED_ORIGINS = {"https://app.example.com"}
            status, headers, body = self.request("/", method="OPTIONS", headers={"Origin": "https://app.example.com"})
            self.assertEqual(status, 204)
            self.assertEqual(body, b"")
            self.assertEqual(headers["Access-Control-Allow-Origin"], "https://app.example.com")
        finally:
            mail.CORS_ALLOWED_ORIGINS = original_origins

    def test_invalid_json_and_body_limit_return_explicit_errors(self):
        headers = {"Authorization": mail.PANEL_TOKEN, "Content-Type": "application/json"}
        status, _headers, body = self.request("/ui-api/aliases", method="POST", headers=headers, data=b"{bad json")
        self.assertEqual(status, 400)
        self.assertIn("valid UTF-8 JSON", json.loads(body)["message"])

        original_limit = mail.API_MAX_BODY_BYTES
        try:
            mail.API_MAX_BODY_BYTES = 8
            status, _headers, body = self.request("/ui-api/aliases", method="POST", headers=headers, data=b'{"long":true}')
            self.assertEqual(status, 413)
            self.assertEqual(json.loads(body)["code"], 413)
        finally:
            mail.API_MAX_BODY_BYTES = original_limit

    def test_domain_token_cannot_read_another_domains_message(self):
        mail.save_domain("other.example.com", "test")
        token = mail.set_domain_token("other.example.com")
        message_id = mail.store_mail("sender@example.net", "private@example.com", message_bytes())
        status, _headers, _body = self.request(
            f"/ui-api/message?id={message_id}",
            headers={"Authorization": token},
        )
        self.assertEqual(status, 403)


class SmtpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        reset_state()
        self.server = await asyncio.start_server(mail.smtp_handler, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def smtp_dialog(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        greeting = await asyncio.wait_for(reader.readline(), 3)
        self.assertTrue(greeting.startswith(b"220"))
        writer.write(b"EHLO test.local\r\n")
        await writer.drain()
        while True:
            line = await asyncio.wait_for(reader.readline(), 3)
            if line.startswith(b"250 "):
                break
        for command, expected in (
            (b"MAIL FROM:<sender@example.net>\r\n", b"250"),
            (b"RCPT TO:<smtp@example.com>\r\n", b"250"),
            (b"DATA\r\n", b"354"),
        ):
            writer.write(command)
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), 3)
            self.assertTrue(response.startswith(expected), response)
        writer.write(message_bytes() + b"\r\n.\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.readline(), 5)
        writer.write(b"QUIT\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), 3)
        writer.close()
        await writer.wait_closed()
        return response

    async def test_delivery_and_transient_vs_permanent_failure_codes(self):
        response = await self.smtp_dialog()
        self.assertTrue(response.startswith(b"250"), response)
        with mail.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM mails WHERE to_email='smtp@example.com'").fetchone()[0], 1)

        original_store = mail.store_mails
        try:
            mail.store_mails = lambda *_args, **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("database busy"))
            response = await self.smtp_dialog()
            self.assertTrue(response.startswith(b"451"), response)

            mail.store_mails = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("quota reached"))
            response = await self.smtp_dialog()
            self.assertTrue(response.startswith(b"552"), response)
        finally:
            mail.store_mails = original_store


def tearDownModule():
    mail._WEBHOOK_EXECUTOR.shutdown(wait=True, cancel_futures=True)
    TEST_ROOT.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
