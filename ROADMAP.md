# Roadmap

ZVS uses [Pride Versioning](https://pridever.org/) — `PROUD.DEFAULT.SHAME`.

## Current: 2.1.0

Channel-based architecture, mempool streaming, OTP system works end-to-end.

Known weaknesses:
- `responded: HashSet<TxId>` lives in memory — restart = forgot everything
- Hardcoded lightwalletd URL (`zec.rocks:443`)
- No tests (deleted at 1.4.4)
- No reconnection logic if gRPC drops

---

## 3.0.0 — Persistent deduplication & failsafe

The next proud version. ZVS should survive restarts without double-sending or forgetting requests.

- Persist responded set to `wallet.db` or a dedicated store
- On startup, reload what was already handled
- Graceful shutdown: flush pending state before exit
- Crash recovery: detect incomplete OTP sends and either retry or skip safely
- Idempotent OTP sending: same request always produces same OTP (HMAC-based), so accidental re-sends are harmless

---

## Likely default/shame versions along the way

| Version | Type | What |
|---------|------|------|
| 2.2.0 | Default | Configurable lightwalletd URL via `keys.toml` |
| 2.3.0 | Default | gRPC reconnection logic on disconnect |
| 2.3.1 | Shame | Whatever breaks when we touch the gRPC layer |
| 2.4.0 | Default | Bring back tests for `otp_rules` and `memo_rules` |
| 2.4.1 | Shame | The bugs the tests find |

---

## 4.0.0 — Wallet separation

Split the single `Wallet` into two isolated concerns: a **reading wallet** (receives, decrypts, validates) and a **sending wallet** (signs, broadcasts). The developer/operator only has access to one at a time.

Right now `Wallet` holds the full `UnifiedSpendingKey` — it can read *and* spend. That's a single point of compromise. The idea:

- **Reading wallet** — operates with the UFVK only. Decrypts memos, monitors mempool, validates requests. Cannot spend. This is what runs 24/7.
- **Sending wallet** — holds the USK. Only activated when an OTP response needs to go out. Cryptographically gated: the reading wallet produces a signed request that the sending wallet verifies before unlocking spend capability.
- **Key separation** — the spending key could live in a separate process, on a separate machine, or behind a hardware boundary. The reading side never touches it.
- **Cryptographic handoff** — the reading wallet signs a "send request" (txid + OTP + amount + recipient) with a shared HMAC or asymmetric key. The sending wallet only acts on valid, authenticated requests. Replay protection via nonce or txid uniqueness.

This is the "don't trust the hot box" architecture — even if the always-online reader is compromised, the attacker can't spend funds without the sending side's cooperation.

---

## Beyond 4.0.0

Ideas, not promises:

- **Multi-service support** — run multiple verification rules beyond OTP
- **Monitoring dashboard** — web UI for balance, recent requests, uptime
- **Rate limiting** — per-sender throttling to prevent spam
- **Pool management** — auto-shield or consolidate UTXOs for fee efficiency
