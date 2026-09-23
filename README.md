<h1 align="center">neuralyzer</h1>

<p align="center">
  <em>Your AI agent saw your API keys. Now it never forgets them. Let's fix that.</em>
</p>

<p align="center">
  <a href="https://github.com/sandeepsirodia/neuralyzer/actions/workflows/ci.yml"><img src="https://github.com/sandeepsirodia/neuralyzer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/dependencies-0-111111?style=flat-square" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/works%20with-Claude%20Code%20·%20Codex-111111?style=flat-square" alt="Works with Claude Code and Codex">
  <img src="https://img.shields.io/badge/license-MIT-111111?style=flat-square" alt="MIT">
</p>

<p align="center">
  <strong>13 kinds of secret · 1 GB scanned in ~23 s · 100% local · 0 dependencies</strong>
</p>

---

Remember that time your agent ran `cat .env` to "check the config"?

It worked. You moved on. But every byte of that output was written, verbatim, to a file on your disk:

```
~/.claude/projects/-Users-you-api/3f2b9c….jsonl
```

It's still there. So is the `env` dump from last Tuesday. So is the database URL with the password in it. Your agent keeps a perfect diary, and your keys are in it, in plaintext, synced to every backup you own.

**neuralyzer is the flashy thing from *Men in Black*.** Point it at the diary. 📸 The agent forgets.

## Before / after

<table>
<tr>
<td width="50%">

**Before**

```console
$ neuralyzer scan
…/3f2b9c.jsonl:212  anthropic  sk-ant…9f2c
…/3f2b9c.jsonl:212  db-url     Qx81zP…u2Lk
…/rollout-0901.jsonl:88  github  ghp_Za…41Rn

3 secret(s) found.
```

</td>
<td width="50%">

**After**

```console
$ neuralyzer scrub --apply
redacted 2 secret(s) in …/3f2b9c.jsonl
redacted 1 secret(s) in …/rollout-0901.jsonl

$ neuralyzer scan
0 secret(s) found.
```

</td>
</tr>
</table>

Your transcript still works, and `claude --resume` still works. The key is just `[REDACTED:anthropic]` now.

## Try it (10 seconds, read-only)

```bash
uvx --from git+https://github.com/sandeepsirodia/neuralyzer neuralyzer scan
```

Nothing is changed. Nothing leaves your machine. You'll just *see*.

## Keep it

```bash
uv tool install git+https://github.com/sandeepsirodia/neuralyzer   # or: pipx install git+https://…
neuralyzer install-hook                                            # scrub every session when it ends
```

That's it. From now on, every Claude Code session gets neuralyzed the moment it closes.

## The four commands

| | |
|---|---|
| `neuralyzer scan` | Show me what's leaked (masked, read-only) |
| `neuralyzer scrub --apply` | Make it forget |
| `neuralyzer rotate` | Checklist of every leaked key, grouped by provider, with the page where you rotate it |
| `neuralyzer install-hook` | Do this automatically, forever |

## "Scrubbing isn't rotating"

Correct, and that's why `rotate` exists. If a key sat in a plaintext file that got backed up, synced, or read by some other tool, treat it as exposed. neuralyzer stops the bleeding; `rotate` tells you which bandages to change.

## What it catches

Anthropic · OpenAI · GitHub · GitLab · Slack (tokens + webhooks) · Stripe · Google · AWS · JWTs · PEM private keys · passwords inside `postgres://` / `mysql://` / `mongodb+srv://` / `redis://` URLs · `Authorization: Bearer …` headers · and high-entropy values sitting next to words like `api_key`, `secret`, `token`, `password`.

Not a secret? Put the exact value in `.neuralyzer-allow` and it'll leave it alone.

## Why you can trust it with your transcripts

Every promise below is a test in [`tests/`](tests/):

- **Dry run by default.** Nothing is written without `--apply`.
- **Crash-safe.** Temp file plus rename. Pull the plug mid-scrub and your original is intact.
- **Never breaks your sessions.** Every JSONL line that parsed before still parses after, or the file isn't touched.
- **Never prints a secret.** Only masked values like `sk-ant…9f2c` ever hit your terminal.
- **No backups by default,** because a backup of a file full of keys is just… another file full of keys.
- **Idempotent.** Run it twice; the second run does nothing.

## Why this exists

People have been asking Anthropic for this: [#50014](https://github.com/anthropics/claude-code/issues/50014), [#58043](https://github.com/anthropics/claude-code/issues/58043), [#95680](https://github.com/anthropics/claude-code/issues/95680). Until it's built in, there's this: one Python file, zero dependencies, readable in ten minutes.

<details>
<summary><b>Development</b></summary>

```bash
python -m unittest discover -s tests -v
```

Tests map 1:1 to [SPEC.md](SPEC.md). Fake secrets are assembled at runtime, so no secret-shaped string ever lands in this repo. The ~23 s/GB figure was measured on synthetic transcripts on an M-series laptop.

</details>

<p align="center"><sub>MIT © Sandeep Sirodia · If neuralyzer found something scary on your machine, a ⭐ helps the next person find it too.</sub></p>
