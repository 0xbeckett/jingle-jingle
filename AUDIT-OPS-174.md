# OPS-174 — Security & Integration Audit: frgmt0/jingle-jingle

Audited: 2026-07-14, commit `9914a1d` (head of `main`). Every file in the repo was read.

## What it is

Not empty — it's **jingle**, a complete ~2.5k-line Rust CLI: an *agent-native credential keychain*.
Agents store passwords/TOTP seeds/API keys in an encrypted vault and **use** them (env-injection
via `jingle exec`, clipboard, TOTP codes) without secret values ever entering the agent's context.
The public repo description "Keys" refers to this. Built today via a Claude agent PR, merged by the owner.

## Overall verdict: **SAFE** (to integrate, with the caveats below)

- **No malicious code, no leaked secrets, no suspicious dependencies.** All 17 deps come from
  crates.io and are mainstream (clap, serde, chacha20poly1305, zeroize…). No git/path sources,
  no build.rs, no `unsafe`, and **zero network code** — the binary never talks to the network.
- Crypto is sound: XChaCha20-Poly1305 with header bound as AAD, fresh random nonce per write,
  HKDF-SHA256 from a full-entropy 0600 keyfile, atomic writes, zeroize-on-drop.
- The threat model explicitly targets prompt injection against agents: no bulk-export command
  exists, secrets never on argv, untrusted metadata framed/sanitized, hash-chained audit log,
  burst tripwire. `tests/redaction.rs` enforces "no command leaks secret bytes". CI green on
  Linux/macOS/Windows.
- `.claude/skills/verify/SKILL.md` and `CLAUDE.md` were checked for prompt-injection content:
  both are benign (build/verify instructions and a defensive agent contract).

## Findings (severity-ranked — nothing above Medium, no Critical/High)

1. **MEDIUM (design limit, not a bug)** — `jingle exec` is a full bypass for a *deliberately*
   steered agent: anyone allowed to run it can read any unlocked secret via
   `jingle exec -s x=V -- sh -c 'echo $V'` (`src/commands/egress.rs:89`). The invariant protects
   against *accidental* context leakage, not a prompt-injected agent that actively extracts.
   Mitigations exist (`lock` + `--confirm-locked`, audit, tripwire) — use them for high-value entries.
2. **LOW** — Keyfile + vault are same-user readable (`~/.config/jingle/key`); any process running
   as that user (including an agent's shell) can decrypt everything offline. The CLAUDE.md rule
   against touching the keyfile is advisory only. Acknowledged in README "Honest limits".
3. **LOW** — The burst tripwire (`src/audit.rs:99`) only *warns* on stderr; it never blocks.
   A compromised agent can ignore it.
4. **LOW** — Audit log is tamper-*evident*, not tamper-proof, and `append` has no file locking:
   concurrent jingle processes can race and produce spurious chain breaks (`src/audit.rs:54-94`).
5. **LOW** — CI actions pinned to tags/branches, not SHAs; the test job uses
   `dtolnay/rust-toolchain@master` — a mutable ref (`.github/workflows/ci.yml:46`).
6. **INFO** — `copy` puts secrets on the OS clipboard (session-readable; acknowledged); the
   auto-clear helper carries the secret's SHA-256 in its env (same-user readable only).
7. **INFO** — `exec` writes its "ok" audit record before spawning the child, so a failed spawn
   still logs as ok (`src/commands/egress.rs:163-178`).

## Integration with Beckett

**Fit is good — the tool was designed for exactly Beckett's shape of work** (agents creating
accounts on registries/forges and needing to use credentials without holding them).

- **What it touches:** local files only (keyfile, vault, audit log). It adds **no new exec or
  network capability** — `jingle exec` runs commands, but Beckett workers already have Bash;
  jingle only adds *secrets in the child env*, which is the point.
- **Credential handover is the real decision:** whatever goes in the vault is readable by any
  process running as the beckett user (finding 2). Suitable for **agent-created account
  credentials** (npm bots, forge accounts, SaaS signups). Do **not** migrate Beckett's core
  keychain/owner credentials into it wholesale — keep those in the existing beckett secret flow.
- **Clean integration:**
  - Install as a plain CLI (`cargo install`), one vault under the beckett user; per-worker/test
    isolation via `JINGLE_DATA_DIR`/`JINGLE_KEYFILE` (already documented in its verify skill).
  - Allowlist the non-egress commands (`add/set/list/show/lock/audit/generate --entry`) freely;
    treat `exec`, `copy`, `totp`, and `generate --print` as the egress surface.
  - `jingle lock` every high-value entry so egress requires `--confirm-locked <name>`.
  - Periodically run `jingle audit --json` and surface chain breaks / burst warnings.

**Recommendation: integrate (safe), scope the vault to agent-created accounts, lock anything
valuable, and keep owner-level credentials out of it.**
