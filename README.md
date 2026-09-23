# neuralyzer

**Make your AI agent forget the secrets it saw.**

Every time Claude Code or Codex runs `cat .env`, `env`, or `aws configure list`, the output is written *verbatim* to a transcript on your disk, and it stays there indefinitely:

```
~/.claude/projects/**/*.jsonl
~/.codex/sessions/**
```

API keys, database passwords, bearer tokens: all sitting in plaintext, synced to your backups, readable by any process running as you. People have [asked Anthropic to fix this](https://github.com/anthropics/claude-code/issues/50014) ([#58043](https://github.com/anthropics/claude-code/issues/58043), [#95680](https://github.com/anthropics/claude-code/issues/95680)). Until they do, there's this.

```console
$ uvx --from git+https://github.com/sandeepsirodia/neuralyzer neuralyzer scan

~/.claude/projects/-Users-me-api/3f2b….jsonl:212  anthropic    sk-ant…9f2c  2026-08-14T10:02:11Z
~/.claude/projects/-Users-me-api/3f2b….jsonl:212  db-url       Qx81zP…u2Lk  2026-08-14T10:02:11Z
~/.codex/sessions/2026/09/01/rollout-….jsonl:88   github       ghp_Za…41Rn  2026-09-01T16:40:55Z

3 secret(s) found. Run `neuralyzer scrub --apply` to redact.
```

## Install

```bash
uv tool install git+https://github.com/sandeepsirodia/neuralyzer   # or: pipx install git+https://…
```

Zero dependencies. One Python file. Nothing leaves your machine.

## Use

| Command | What it does |
|---|---|
| `neuralyzer scan` | Read-only. Lists every secret (masked) with file, line, and when it was captured |
| `neuralyzer scrub` | Dry run: shows what would be redacted |
| `neuralyzer scrub --apply` | Replaces each secret with `[REDACTED:<type>]`, in place |
| `neuralyzer rotate` | Checklist of every unique leaked credential, grouped by provider, with rotation links |
| `neuralyzer install-hook` | Adds a Claude Code `SessionEnd` hook: every session is scrubbed the moment it ends |

All commands take optional paths; the default is the Claude Code and Codex transcript locations.

## Detects

Anthropic, OpenAI, GitHub, GitLab, Slack (tokens + webhooks), Stripe, Google API keys, AWS access keys, JWTs, PEM private keys, passwords in database URLs (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://`…), `Authorization: Bearer|Basic|Token` headers, and high-entropy values assigned to `api_key` / `secret` / `token` / `password` fields.

False positive? Add the exact value to `.neuralyzer-allow` (per project) or `~/.neuralyzer-allow`.

## Safety guarantees (each one is a test)

- **Dry run by default.** Nothing is written without `--apply`.
- **Atomic writes.** Temp file + rename, so a crash mid-scrub leaves the original intact.
- **Never corrupts transcripts.** Every JSONL line that parsed before still parses after, or the file is left untouched. Your `claude --resume` keeps working.
- **Idempotent.** Scrubbing twice changes nothing the second time.
- **Never prints a secret.** Output shows only masked values (`sk-ant…9f2c`).
- **No backups by default.** A backup of a secret-laden file is itself a leak. Opt in with `--backup`.
- **Fast.** 1 GB of transcripts scanned in ~23 s on an M-series laptop.

## Why "neuralyzer"?

It's the flashy memory-wiper from *Men in Black*. Your agent saw something it shouldn't have. 📸

## Scrubbing isn't rotating

If a key was in your transcripts, assume it was exposed (cloud backups, dotfile syncs, other tools reading `~/.claude`). Run `neuralyzer rotate` and actually rotate them.

## Development

```bash
python -m unittest discover -s tests -v
```

Tests map 1:1 to the expectations in [SPEC.md](SPEC.md). Fake secrets are built at runtime so no secret-shaped string ever lands in this repo.

MIT © Sandeep Sirodia
