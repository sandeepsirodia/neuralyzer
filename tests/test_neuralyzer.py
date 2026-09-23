"""Tests map 1:1 to SPEC.md expectations (E1..E12).

Fake secrets are assembled at runtime so no secret-shaped literal lives in the repo
(GitHub push protection would reject it, and rightly so).
"""
import hashlib
import io
import json
import os
import random
import string
import sys
import tempfile
import unittest
import warnings
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import neuralyzer as nz  # noqa: E402

R = random.Random(42)


def rnd(n, alphabet=string.ascii_letters + string.digits):
    return "".join(R.choice(alphabet) for _ in range(n))


UP = string.ascii_uppercase + string.digits
FAKE = {
    "anthropic": "sk-" + "ant-api03-" + rnd(90),
    "openai": "sk-" + "proj-" + rnd(60),
    "github": "gh" + "p_" + rnd(36),
    "gitlab": "gl" + "pat-" + rnd(20),
    "slack": "xo" + "xb-" + rnd(12, string.digits) + "-" + rnd(24),
    "stripe": "sk" + "_live_" + rnd(24),
    "google": "AI" + "za" + rnd(35),
    "aws": "AK" + "IA" + rnd(16, UP),
    "jwt": "ey" + "J" + rnd(20) + ".ey" + "J" + rnd(30) + "." + rnd(40),
}
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + rnd(64) + "\n" + rnd(64) + "\n-----END RSA PRIVATE KEY-----"
DB_PASS = rnd(18)
GENERIC = rnd(32)


def jline(content, ts="2026-09-01T10:00:00Z"):
    return json.dumps({"type": "tool_result", "timestamp": ts, "content": content}) + "\n"


def planted_transcript():
    lines = [jline("$ cat .env\n%s_KEY=%s" % (k.upper(), v)) for k, v in FAKE.items()]
    lines.append(jline("key file:\n" + PEM))  # E7: PEM newlines become \n escapes inside JSON
    lines.append(jline("DATABASE_URL=postgres://app:" + DB_PASS + "@db.internal:5432/prod"))
    lines.append(jline('curl -H "Authorization: Bearer ' + rnd(40) + '" https://api.example.com'))
    lines.append(jline('{"client_secret": "' + GENERIC + '"}'))
    return "".join(lines)


def lookalike_transcript():
    sha = hashlib.sha1(b"x").hexdigest()
    return "".join([
        jline("commit %s\nMerge: %s" % (sha, hashlib.sha256(b"y").hexdigest())),
        jline("request id 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b and session 0b9c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"),
        jline("data:image/png;base64," + "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="),
        jline('"integrity": "sha512-' + "q0wYy1RyHUeSZXZhQ8Bf6bxAOjm0hDN4E3Yb0cjc0sQqsXk7cOpkMCHnuWn6hW0ZtiNP3hGSRV3pZ9SLlE3JyQ==" + '"'),
        jline("Lorem ipsum dolor sit amet, the token budget is 4096 and max_tokens=8192. password reset flow."),
        jline('{"usage": {"input_tokens": 1234, "output_tokens": 567, "cache_read_input_tokens": 89}}'),
        jline("see src/auth/token_refresh.py and tests/test_password_hashing.py"),
    ])


class Base(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.dir = tempfile.mkdtemp()

    def write(self, name, text):
        p = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def run_cli(self, *argv, stdin=None):
        out = io.StringIO()
        if stdin is not None:
            with mock.patch("sys.stdin", io.StringIO(stdin)):
                code = nz.main(list(argv), out=out)
        else:
            code = nz.main(list(argv), out=out)
        return code, out.getvalue()


class TestSpec(Base):
    def test_e1_recall_every_type(self):
        p = self.write("s.jsonl", planted_transcript())
        found = nz.scan_file(p, set())
        types = {f["type"] for f in found}
        self.assertTrue(set(FAKE) <= types, set(FAKE) - types)
        for extra in ("private-key", "db-url", "auth-header", "generic"):
            self.assertIn(extra, types)
        values = {f["value"] for f in found}
        for v in list(FAKE.values()) + [DB_PASS, GENERIC]:
            self.assertIn(v, values)
        self.assertEqual({f["value"] for f in found if f["type"] == "anthropic"}, {FAKE["anthropic"]})

    def test_e2_no_false_positives(self):
        p = self.write("clean.jsonl", lookalike_transcript())
        self.assertEqual(nz.scan_file(p, set()), [])

    def test_e3_dry_run_changes_nothing(self):
        p = self.write("s.jsonl", planted_transcript())
        before = open(p, "rb").read()
        code, out = self.run_cli("scrub", p)
        self.assertEqual(open(p, "rb").read(), before)
        self.assertIn("would redact", out)

    def test_e4_apply_redacts_and_keeps_json_valid(self):
        p = self.write("s.jsonl", planted_transcript())
        self.run_cli("scrub", "--apply", p)
        text = open(p, encoding="utf-8").read()
        for v in list(FAKE.values()) + [DB_PASS, GENERIC]:
            self.assertNotIn(v, text)
        for line in text.splitlines():
            json.loads(line)
        self.assertIn("[REDACTED:anthropic]", text)
        self.assertIn("postgres://app:[REDACTED:db-url]@db.internal", text)

    def test_e5_idempotent(self):
        p = self.write("s.jsonl", planted_transcript())
        self.run_cli("scrub", "--apply", p)
        once = open(p, "rb").read()
        self.assertEqual(nz.scrub_file(p, set(), apply=True), 0)
        self.assertEqual(open(p, "rb").read(), once)

    def test_e6_crash_mid_write_leaves_original(self):
        p = self.write("s.jsonl", planted_transcript())
        before = open(p, "rb").read()
        with mock.patch("os.replace", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                nz.scrub_file(p, set(), apply=True)
        self.assertEqual(open(p, "rb").read(), before)
        self.assertEqual(os.listdir(self.dir), ["s.jsonl"])

    def test_e7_escaped_pem_and_quoted_secrets(self):
        p = self.write("s.jsonl", planted_transcript())
        self.run_cli("scrub", "--apply", p)
        text = open(p, encoding="utf-8").read()
        self.assertNotIn("PRIVATE KEY-----\\n" + PEM.split("\n")[1], text)
        self.assertIn("[REDACTED:private-key]", text)

    def test_e8_allowlist(self):
        p = self.write("s.jsonl", jline("GITHUB_TOKEN=" + FAKE["github"]))
        allow = self.write("allow", "# fixture token\n" + FAKE["github"] + "\n")
        code, out = self.run_cli("scan", "--allowlist", allow, p)
        self.assertEqual(code, 0)
        self.assertIn("0 secret(s)", out)

    def test_e9_rotate_dedupes(self):
        for i in range(40):
            self.write("proj/s%02d.jsonl" % i, jline("export OPENAI_API_KEY=" + FAKE["openai"]))
        code, out = self.run_cli("rotate", self.dir)
        self.assertEqual(out.count(nz.mask(FAKE["openai"])), 1)
        self.assertIn("(in 40 file(s))", out)
        self.assertIn("platform.openai.com/api-keys", out)

    def test_e10_hook_scrubs_only_ended_session(self):
        ended = self.write("a.jsonl", planted_transcript())
        other = self.write("b.jsonl", planted_transcript())
        other_before = open(other, "rb").read()
        code, _ = self.run_cli("hook", stdin=json.dumps({"transcript_path": ended, "hook_event_name": "SessionEnd"}))
        self.assertEqual(code, 0)
        self.assertNotIn(FAKE["anthropic"], open(ended).read())
        self.assertEqual(open(other, "rb").read(), other_before)

    def test_e10_hook_never_fails(self):
        self.assertEqual(self.run_cli("hook", stdin="not json")[0], 0)

    def test_e12_never_prints_full_secret(self):
        p = self.write("s.jsonl", planted_transcript())
        outputs = [self.run_cli(*a)[1] for a in (("scan", p), ("scan", "--json", p), ("rotate", p), ("scrub", p))]
        blob = "\n".join(outputs)
        for v in list(FAKE.values()) + [DB_PASS, GENERIC]:
            self.assertNotIn(v, blob)


class TestExtras(Base):
    def test_install_hook_idempotent_and_preserves_settings(self):
        s = self.write("settings.json", json.dumps({"model": "opus", "hooks": {"Stop": [{"hooks": []}]}}))
        self.run_cli("install-hook", "--settings", s)
        self.run_cli("install-hook", "--settings", s)
        data = json.load(open(s))
        self.assertEqual(data["model"], "opus")
        self.assertIn("Stop", data["hooks"])
        self.assertEqual(len(data["hooks"]["SessionEnd"]), 1)

    def test_backup_is_opt_in(self):
        p = self.write("s.jsonl", planted_transcript())
        self.run_cli("scrub", "--apply", p)
        self.assertFalse(os.path.exists(p + ".neuralyzer.bak"))

    def test_scan_exit_code(self):
        self.assertEqual(self.run_cli("scan", self.write("s.jsonl", planted_transcript()))[0], 1)
        self.assertEqual(self.run_cli("scan", self.write("c.jsonl", lookalike_transcript()))[0], 0)


if __name__ == "__main__":
    unittest.main()
