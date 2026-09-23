# neuralyzer — SPEC

> Make your AI agent forget the secrets it saw.

Coding agents write every tool call and output verbatim to local transcripts (`~/.claude/projects/**/*.jsonl`, `~/.codex/sessions`, …). Any API key the agent ever `cat`-ed or `env`-ed sits there in plaintext indefinitely. neuralyzer finds those secrets, redacts them, and tells you which keys to rotate.

Demand evidence: anthropics/claude-code issues #50014, #58043, #95680.

## Who it's for
Every Claude Code / Codex user, especially on shared machines, laptops that sync to the cloud, or machines that are backed up.

## Must have (v1)
1. **`neuralyzer scan`**: read-only. Lists findings: secret type, masked value (`sk-ant-…9f2c`), file, line, first-seen timestamp.
2. **`neuralyzer scrub`**: replaces secrets in place with `[REDACTED:<type>]`.
   - Dry-run by default; `--apply` required to write.
   - Atomic write (temp file + rename). Backup is opt-in (`--backup`), because a backup of a secret-laden file is itself a leak.
   - Every JSONL line stays valid JSON after scrubbing.
3. **`neuralyzer rotate`**: a checklist of unique secrets found, grouped by provider, with the provider's rotation URL.
4. **Claude Code hook** (`SessionEnd`): scrubs the session file that just ended. Installed via one command or a plugin.
5. **Detection:** regex for known formats (Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, Google, JWT, private-key blocks, DB URLs with passwords, `Authorization:` headers), plus an entropy check for `key=value` / `"api_key": "…"` fields.
6. **Allowlist file** (`.neuralyzer-allow`) for known false positives.
7. **Zero runtime dependencies** (Python stdlib or a single Go binary).

## Won't do (v1)
- Cursor (stores history in SQLite): v2.
- Rotating keys automatically via provider APIs.
- Uploading anything anywhere. Fully local.

## Expectations → test cases
Fixtures: `tests/fixtures/` holds synthetic transcripts with planted fake secrets, plus look-alike non-secrets.

| ID | Given | When | Then |
|---|---|---|---|
| E1 | Transcript with one planted secret of each supported type | `scan` | Every planted secret is reported with the correct type (100% recall on fixtures) |
| E2 | Transcript containing git SHAs, UUIDs, base64 images, npm integrity hashes, lorem text | `scan` | Zero findings (false-positive guard) |
| E3 | Any fixture | `scrub` without `--apply` | File bytes unchanged (hash equal) |
| E4 | Fixture with secrets | `scrub --apply` | Secret strings are no longer in the file; every line still parses with `json.loads` |
| E5 | Already-scrubbed file | `scrub --apply` again | No changes (idempotent) |
| E6 | `scrub --apply` is killed mid-write (simulate an exception before rename) | Inspect the file | Original file is intact; no partial file left behind |
| E7 | Secret split across a JSON-escaped string (`\"sk-ant-…\"`, `\n` inside a PEM block) | `scrub --apply` | Still detected and redacted |
| E8 | Value listed in `.neuralyzer-allow` | `scan` | Not reported |
| E9 | Same secret appears in 40 files | `rotate` | Listed once, with a count of 40 and the rotation URL |
| E10 | Hook installed; session ends | Session file checked | Secrets in that session are redacted; other sessions untouched |
| E11 | 1 GB of transcripts | `scan` | Finishes in < 30 s on a laptop (benchmark test, not a unit test) |
| E12 | Any output (`scan`, `rotate`, logs) | Inspect stdout/stderr | A full secret value is never printed, only masked |

## Done when
- E1–E12 pass. README shows a real count from the author's own machine ("found N secrets in my own logs").
- GIF: `scan` finds keys, then `scrub --apply`, then `scan` again shows 0.
