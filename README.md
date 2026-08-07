# Zcash Verification Service

An on-chain OTP relayer for [ZcashMe](https://zcash.me). Watches the Zcash
mempool for shielded login payments, derives a deterministic 6-digit OTP, and
sends it back via an encrypted transaction memo.

A participating consumer application can create sessions, renders a payment QR code, and verifies the
OTP locally.

## What it does

1. Connects to a lightwalletd (or Zaino) gRPC endpoint.
2. Syncs confirmed blocks to recover wallet state.
3. Streams `GetMempoolStream` for real-time auth payment detection.
4. Trial-decrypts incoming transactions with the wallet UFVK.
5. Validates the ZFA memo format (`DO NOT MODIFY:{zvs/session_id,return-address}`).
6. Derives `OTP = HMAC-SHA256(otp_key, session_id ‖ return_address)[0..4] mod 10^6`.
7. Sends a shielded response transaction with the OTP in the memo: `(ZFA OTP)847291`.
8. Records durable idempotence state so a crash never sends two responses.

## Quick start

```bash
cargo build --release
./target/release/zfa-backend
```

First run auto-initializes: generates a 24-word mnemonic, creates an age
identity, writes `zfa.toml`, and prints the OTP HMAC key (hex) for provisioning
the consumer application.

Restore from an existing mnemonic:

```bash
./target/release/zfa-backend --mnemonic "word1 word2 ... word24" --birthday 3150000
```

## Configuration

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
| `ZFA_ALLOW_CORE_DUMPS` | `1` to disable core-dump suppression |
| `ZFA_REGTEST_NU63_HEIGHT` | NU6.3 activation height for regtest |

## Keys

The wallet seed is the root of trust. From it, the worker derives a 32-byte
key. The worker and the consumer application both have this key.

When a payment comes in, the worker uses the key, the session ID, and the
return address to make a six-digit code. The consumer application uses the same
key and the same inputs. Both get the same code. This is the agreement — two
parties, no communication, same result.

The user types the code into the website. The consumer application checks it.
This is the verification. If the code is correct, the authentication is
complete. The payment proved the user owns the address. The handshake is done.

The seed is locked with [age](https://age-encryption.org), not a password. No
person is available to type a password. An identity file opens the seed. The
identity file and the locked seed are two separate files. If someone gets one
file, the seed is still locked.

In memory, the worker pins the seed to RAM and erases it when done. At
startup, the worker checks the seed against the wallet database. If they do
not agree, the worker does not start.

## License

MIT
