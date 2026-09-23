# Zcash Verification Service — Project Overview

## What it is

`zfa-backend` is an **on-chain OTP relayer** for [ZcashMe](https://zcash.me). It is a
background worker (not an API server) that:

1. Watches the Zcash mempool for shielded "login payments."
2. Derives a deterministic 6-digit OTP from each payment.
3. Sends the OTP back to the payer via an encrypted transaction memo.

A separate consumer application creates login sessions, renders a payment QR code,
and verifies the OTP locally. The worker and the consumer app share a secret HMAC
key so both compute the same code without communicating.

## Core flow

```
Consumer app server             response ledger        ZFA worker
───────────────────             ───────────────        ──────────
creates app session                                     connects to lightwalletd/Zaino
renders ZIP-321 QR              incoming txid ──→       watches GetMempoolStream
verifies OTP locally            response txid          decrypts + sends OTP response
```

1. Connect to a lightwalletd (or Zaino) gRPC endpoint.
2. Sync confirmed blocks to recover wallet state.
3. Stream `GetMempoolStream` for real-time auth payment detection.
4. Trial-decrypt incoming transactions with the wallet UFVK.
5. Validate the ZFA memo format: `DO NOT MODIFY:{zvs/session_id,return-address}`.
6. Derive `OTP = HMAC-SHA256(otp_key, session_id ‖ return_address)[0..4] mod 10^6`.
7. Send a shielded response transaction with the OTP in the memo: `(ZFA OTP)847291`.
8. Record durable idempotence state so a crash never sends two responses.

## Tech stack

- **Language:** Rust (edition 2021, rust-version 1.88), async via `tokio`.
- **Zcash:** librustzcash crates pinned to the ironwood/NU6.3 line (same as `zecd`):
  `zcash_client_backend 0.24.0-rc.6`, `zcash_client_sqlite 0.22.0-rc.6`,
  `zcash_keys 0.16`, `zcash_primitives 0.30`, `orchard 0.15`.
- **gRPC:** `tonic` (TLS via native roots) talking to lightwalletd/Zaino.
- **Storage:** SQLite — `data.sqlite` (wallet DB, owned by `zcash_client_sqlite`),
  `responses.sqlite` (worker-local response ledger), plus a compact-block cache.
- **Key custody:** `age` encryption for the on-disk seed, `secrecy` for in-memory
  secrets, `bip0039` for the mnemonic.
- **OTP:** `hmac` + `sha2` + `subtle` (constant-time compare).

## Directory layout

```
src/
  main.rs            CLI entry point; resolves config and locks datadir
  lib.rs             init_wallet + run() (spawns the wallet actor)
  config.rs          CLI flags, hardcoded operational defaults, OTP key derivation
  network.rs         ZNetwork (main/test/regtest) implementing zcash Parameters
  otp.rs             deterministic 6-digit OTP generation + constant-time verify
  memo.rs            strict 512-byte ZFA memo parser
  lock.rs            single-instance datadir lock (host-local advisory lock)
  lwd.rs             thin lightwalletd/Zaino gRPC client wrapper
  sync.rs            block sync + reorg recovery (scan_cached_blocks)
  response_ledger.rs durable idempotence state machine for OTP responses
  backoff.rs         exponential backoff with full jitter for reconnects
  error.rs           ZfaError type + ProposalError alias
  wallet/
    actor.rs         single-writer actor: sync loop + mempool watcher + OTP sender
    keys.rs          in-memory seed custody (SeedKeeper, OtpSecret), age identity
    store.rs         on-disk [seed] table (age-encrypted mnemonic + birthday)
    binding.rs       binds data.sqlite account UFVK to the seed-derived UFVK
    open.rs          opens/initializes the zcash_client_sqlite databases
tests/
  regtest_auth.rs        e2e: auth payment → OTP response cycle
  regtest_idempotence.rs idempotence + crash-recovery test
integrations/
  README.md + examples/  OIDC integration guides (Better Auth, NextAuth, Clerk, raw OIDC)
```

## Configuration

Operational settings are **hardcoded**; the only on-disk config is the wallet's
encrypted seed. CLI flags override a few values.

| Flag | Default | Purpose |
|------|---------|---------|
| `--datadir` | `./zfa-data` | Data directory |
| `--network` | `main` | `main`, `test`, or `regtest` |
| `--lwd-url` | `https://zec.rocks:443` | lightwalletd/Zaino gRPC endpoint |
| `--mnemonic` | — | Restore from mnemonic (requires `--birthday`) |
| `--birthday` | chain tip | Earliest block that may contain funds |
| `--keys-file` | same as `--conf` | `[seed]` table from external file (k8s Secret) |

| Env | Purpose |
|-----|---------|
| `RUST_LOG` | Log level (default: `info`) |
| `ZFA_REGTEST_NU63_HEIGHT` | NU6.3 activation height for regtest |

## Key management

- The **wallet seed** is the root of trust. From it the worker derives a 32-byte
  OTP HMAC key: `HMAC-SHA256(seed, "zvs-otp")`.
- The seed is stored **age-encrypted** (not password-protected) in `zfa.toml`;
  an age identity file (`identity.txt`) opens it. Two separate files — getting one
  alone does not unlock the seed.
- In memory the seed is held in a zeroizing `SecretVec`. The Unified Spending
  Key is derived fresh per operation and never cached.
- At startup the worker verifies the seed-derived UFVK matches the wallet DB's
  account UFVK; a mismatch means the DB was swapped and the worker refuses to start.

## Runtime behavior

- **Single-writer actor:** one process owns the wallet DB. A host-local advisory
  lock on `<datadir>/.lock` prevents a second worker on the same host (does **not**
  span hosts — the datadir must be host-local).
- **Sync loop:** downloads compact blocks in batches (10,000) and scans them,
  with reorg recovery (rewind + truncate cache).
- **Mempool watcher:** streams `GetMempoolStream`; the stream closes on each new
  block, so the loop re-syncs and reopens.
- **Response ledger state machine:** `claimed → created → broadcasting → broadcast`.
  A crash mid-broadcast is recovered by rebroadcasting the exact same transaction
  on restart (idempotence — never two responses for one payment).
- **Graceful shutdown** on SIGINT/SIGTERM.

## Deployment

- `Dockerfile` builds a release binary and runs it on `debian:bookworm-slim`.
  Mounts `/app/zfa-data` and `/root/.zcash-params`.
- First run auto-initializes: generates a 24-word mnemonic, creates an age
  identity, writes `zfa.toml`, and prints the OTP HMAC key (hex) for provisioning
  the consumer application.
- Restore from an existing mnemonic: `zfa-backend --mnemonic "..." --birthday N`.

## Testing

- Unit tests in each module (memo parsing, OTP vectors, ledger state machine,
  backoff, lock).
- Two regtest end-to-end tests (`tests/`) that spin up zebrad + lightwalletd +
  zallet + the worker. They skip unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN`, and
  `ZALLET_BIN` are set.

## License

MIT
