"""neuralyzer: make your AI agent forget the secrets it saw.

Finds and redacts secrets in local coding-agent transcripts
(Claude Code, Codex CLI). Zero dependencies, fully local.
"""
import argparse
import json
import math
import os
import re
import string
import sys
import tempfile
from collections import Counter

__version__ = "0.1.0"

HOME = os.path.expanduser("~")
DEFAULT_ROOTS = [
    os.path.join(HOME, ".claude", "projects"),
    os.path.join(HOME, ".claude", "history.jsonl"),
    os.path.join(HOME, ".codex", "sessions"),
    os.path.join(HOME, ".codex", "history.jsonl"),
]
EXTS = (".jsonl", ".json", ".log", ".txt")
REDACTED = "[REDACTED:{}]"

# (type, pattern, group holding the secret, flags). Order matters: first match wins on overlap.
_PATTERNS = [
    ("private-key", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z]+ )*PRIVATE KEY-----", 0, re.S),
    ("anthropic", r"sk-ant-[A-Za-z0-9_\-]{20,}", 0, 0),
    ("openai", r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{40,}", 0, 0),
    ("github", r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}", 0, 0),
    ("gitlab", r"gl(?:pat|dt|rt|oas|ptt|agent|imt|soat|cbt|ft|ffct)-[A-Za-z0-9_\-]{20,}", 0, 0),
    ("slack", r"xox[abposr]-[A-Za-z0-9\-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", 0, 0),
    ("stripe", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}", 0, 0),
    ("google", r"AIza[0-9A-Za-z_\-]{35}", 0, 0),
    ("aws", r"A[KS]IA[0-9A-Z]{16}(?![A-Z0-9])", 0, 0),  # preceding-char guard in find_secrets (lookbehind is 30x slower)
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 0, 0),
    ("db-url", r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/\"'@\\]+:([^@\s\"'\\/]{3,})@", 1, 0),
    ("auth-header", r"(?i)authorization\\?[\"']?\s*[:=]\s*\\?[\"']?(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=\-]{12,})", 1, 0),
    # generic runs on an ASCII-lowercased copy (same length, same offsets): 5x faster than (?i)
    ("generic", r"(?:api[_-]?key|secret|token|passw(?:or)?d|access[_-]?key)[a-z0-9_]*\\?[\"']?\s*[:=]\s*\\?[\"']?([a-z0-9_\-+/=.]{16,})", 1, 0),
]
_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_UPPER_DIGITS = set(string.ascii_uppercase + string.digits)
PATTERNS = [(t, re.compile(p, f), g) for t, p, g, f in _PATTERNS]

ROTATE_URLS = {
    "anthropic": "https://console.anthropic.com/settings/keys",
    "openai": "https://platform.openai.com/api-keys",
    "github": "https://github.com/settings/tokens",
    "gitlab": "https://gitlab.com/-/user_settings/personal_access_tokens",
    "slack": "https://api.slack.com/apps",
    "stripe": "https://dashboard.stripe.com/apikeys",
    "google": "https://console.cloud.google.com/apis/credentials",
    "aws": "https://console.aws.amazon.com/iam/home#/security_credentials",
}


def _entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _looks_random(v):
    # ponytail: entropy heuristic for generic key=value, add per-provider patterns when it misfires
    return (
        any(c.isdigit() for c in v)
        and any(c.isalpha() for c in v)
        and _entropy(v) >= 3.5
    )


def load_allowlist(paths=None):
    allowed = set()
    for p in paths or [".neuralyzer-allow", os.path.join(HOME, ".neuralyzer-allow")]:
        try:
            with open(p, encoding="utf-8") as f:
                allowed.update(line.strip() for line in f if line.strip() and not line.startswith("#"))
        except OSError:
            pass
    return allowed


def find_secrets(text, allow=frozenset()):
    """Return non-overlapping [(start, end, type, value)] sorted by start."""
    hits = []
    lowered = text.translate(_LOWER)
    for kind, rx, group in PATTERNS:
        for m in rx.finditer(lowered if kind == "generic" else text):
            start, end = m.span(group)
            value = text[start:end]
            if kind == "aws" and start and text[start - 1] in _UPPER_DIGITS:
                continue
            if kind == "generic" and not _looks_random(value):
                continue
            if value in allow or value.startswith("[REDACTED"):
                continue
            hits.append((start, end, kind, value))
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
    out, last_end = [], -1
    for h in hits:
        if h[0] >= last_end:
            out.append(h)
            last_end = h[1]
    return out


def mask(value):
    return value[:6] + "…" + value[-4:] if len(value) >= 16 else "****"


def redact(text, hits):
    parts, pos = [], 0
    for start, end, kind, _ in hits:
        parts.append(text[pos:start])
        parts.append(REDACTED.format(kind))
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.endswith(EXTS):
                        yield os.path.join(root, n)


def read(path):
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
        return f.read()


def _timestamp(line):
    try:
        return json.loads(line).get("timestamp", "")
    except (ValueError, AttributeError):
        return ""


def scan_file(path, allow):
    text = read(path)
    findings = []
    line_no, pos = 1, 0
    for start, _, kind, value in find_secrets(text, allow):  # sorted by start, so count incrementally
        line_no += text.count("\n", pos, start)
        pos = start
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", start)
        line = text[line_start: line_end if line_end != -1 else len(text)]
        findings.append({"type": kind, "value": value, "masked": mask(value), "file": path,
                         "line": line_no, "timestamp": _timestamp(line)})
    return findings


def _json_lines_ok(text):
    ok = set()
    for i, line in enumerate(text.splitlines()):
        try:
            json.loads(line)
            ok.add(i)
        except ValueError:
            pass
    return ok


def atomic_write(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".neuralyzer-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
            f.write(text)
        try:
            os.chmod(tmp, os.stat(path).st_mode & 0o777)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def scrub_file(path, allow, apply=False, backup=False):
    """Return number of secrets redacted (or that would be). Raises ValueError if JSONL would break."""
    text = read(path)
    hits = find_secrets(text, allow)
    if not hits or not apply:
        return len(hits)
    new = redact(text, hits)
    if path.endswith(".jsonl") and not _json_lines_ok(text) <= _json_lines_ok(new):
        raise ValueError("scrub would corrupt JSON lines in %s; left untouched" % path)
    if backup:
        atomic_write(path + ".neuralyzer.bak", text)
    atomic_write(path, new)
    return len(hits)


# ---------------------------------------------------------------- commands

def cmd_scan(args, out):
    allow = load_allowlist(args.allowlist)
    total = 0
    for path in iter_files(args.paths or DEFAULT_ROOTS):
        for f in scan_file(path, allow):
            total += 1
            if args.json:
                f = dict(f)
                del f["value"]
                out.write(json.dumps(f) + "\n")
            else:
                out.write("%s:%d  %-12s %s  %s\n" % (f["file"], f["line"], f["type"], f["masked"], f["timestamp"]))
    if not args.json:
        out.write("\n%d secret(s) found.%s\n" % (total, " Run `neuralyzer scrub --apply` to redact." if total else ""))
    return 1 if total else 0


def cmd_scrub(args, out):
    allow = load_allowlist(args.allowlist)
    total = files = errors = 0
    for path in iter_files(args.paths or DEFAULT_ROOTS):
        try:
            n = scrub_file(path, allow, apply=args.apply, backup=args.backup)
        except ValueError as e:
            errors += 1
            out.write("error: %s\n" % e)
            continue
        if n:
            files += 1
            total += n
            out.write("%s %d secret(s) in %s\n" % ("redacted" if args.apply else "would redact", n, path))
    verb = "Redacted" if args.apply else "Dry run: would redact"
    out.write("\n%s %d secret(s) in %d file(s).%s\n" % (
        verb, total, files, "" if args.apply or not total else " Add --apply to write."))
    return 2 if errors else 0


def cmd_rotate(args, out):
    allow = load_allowlist(args.allowlist)
    seen = {}
    for path in iter_files(args.paths or DEFAULT_ROOTS):
        for f in scan_file(path, allow):
            entry = seen.setdefault(f["value"], {"type": f["type"], "masked": f["masked"], "files": set()})
            entry["files"].add(path)
    if not seen:
        out.write("Nothing to rotate.\n")
        return 0
    out.write("Rotate these credentials. They sat in plaintext in your agent logs:\n\n")
    for kind in sorted({e["type"] for e in seen.values()}):
        out.write("## %s  %s\n" % (kind, ROTATE_URLS.get(kind, "")))
        for e in (e for e in seen.values() if e["type"] == kind):
            out.write("  [ ] %s  (in %d file(s))\n" % (e["masked"], len(e["files"])))
        out.write("\n")
    return 1


def cmd_hook(args, out, stdin=None):
    # Never break the user's session: swallow everything.
    try:
        data = json.load(stdin or sys.stdin)
        path = data.get("transcript_path")
        if path and os.path.isfile(path):
            scrub_file(path, load_allowlist(), apply=True)
    except Exception:
        pass
    return 0


def cmd_install_hook(args, out):
    path = args.settings or os.path.join(HOME, ".claude", "settings.json")
    try:
        with open(path, encoding="utf-8") as f:
            settings = json.load(f)
    except FileNotFoundError:
        settings = {}
    command = "neuralyzer hook"
    groups = settings.setdefault("hooks", {}).setdefault("SessionEnd", [])
    if any(h.get("command") == command for g in groups for h in g.get("hooks", [])):
        out.write("Hook already installed in %s\n" % path)
        return 0
    groups.append({"hooks": [{"type": "command", "command": command}]})
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    atomic_write(path, json.dumps(settings, indent=2) + "\n")
    out.write("Installed SessionEnd hook in %s. Every session is scrubbed when it ends.\n" % path)
    return 0


def main(argv=None, out=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="neuralyzer", description="Make your AI agent forget the secrets it saw.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, help_ in [("scan", "list secrets in agent transcripts (read-only)"),
                        ("scrub", "redact secrets (dry run unless --apply)"),
                        ("rotate", "checklist of credentials to rotate")]:
        s = sub.add_parser(name, help=help_)
        s.add_argument("paths", nargs="*", help="files/dirs (default: ~/.claude and ~/.codex transcripts)")
        s.add_argument("--allowlist", action="append", help="allowlist file (default: .neuralyzer-allow, ~/.neuralyzer-allow)")
        if name == "scan":
            s.add_argument("--json", action="store_true", help="JSON lines output")
        if name == "scrub":
            s.add_argument("--apply", action="store_true", help="actually write changes")
            s.add_argument("--backup", action="store_true", help="keep a .neuralyzer.bak copy (it will contain the secrets!)")
    sub.add_parser("hook", help="Claude Code SessionEnd hook entrypoint (reads JSON on stdin)")
    ih = sub.add_parser("install-hook", help="add the SessionEnd hook to ~/.claude/settings.json")
    ih.add_argument("--settings", help="settings.json path")
    args = p.parse_args(argv)
    return {"scan": cmd_scan, "scrub": cmd_scrub, "rotate": cmd_rotate,
            "hook": cmd_hook, "install-hook": cmd_install_hook}[args.cmd](args, out)


if __name__ == "__main__":
    sys.exit(main())
