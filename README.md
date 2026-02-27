# ZVS - Zcash Verification Service

A two-factor authentication (2FA) service using shielded Zcash transactions. Users send verification requests via encrypted transaction memos, and ZVS responds with HMAC-derived one-time passwords (OTPs).

## How It Works

1. **User sends verification request** - A shielded Zcash transaction with a memo containing the verification payload
2. **ZVS monitors the blockchain** - Connects to a lightwalletd server and scans for incoming transactions
3. **OTP generation** - For valid verification requests, ZVS generates an HMAC-SHA256 based 6-digit OTP
4. **Response transaction** - ZVS sends the OTP back to the user via a shielded transaction memo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   USER                                         ZVS (service wallet)         │
│                                                                             │
│   ┌─────────┐      tx with memo:               ┌─────────┐                  │
│   │         │  "{zvs/1234567890123456,u1...}"  │         │                  │
│   │  Wallet │ ──────────────────────────────►  │  Wallet │                  │
│   │         │                                  │         │                  │
│   └─────────┘                                  └────┬────┘                  │
│        ▲                                            │                       │
│        │                                            │ 1. Decrypt memo       │
│        │                                            │ 2. Parse session ID   │
│        │                                            │ 3. HMAC(secret, session)│
│        │                                            │ 4. Generate OTP       │
│        │                                            ▼                       │
│        │                                       ┌─────────┐                  │
│        │       tx with memo: "847291"          │  Build  │                  │
│        │       (50,000 zats)                   │   tx    │                  │
│        └────────────────────────────────────── │         │                  │
│                                                └─────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Requirements

- Rust toolchain (edition 2021)
- Access to a lightwalletd server

## Configuration

ZVS reads secrets from `zvs_data/keys.toml`:

```toml
mnemonic = "word1 word2 ... word24"
otp_secret = "a71440d829e0403019d195a78afd89efe4c18a4e"
birthday_height = 3150000
```

| Field | Description |
|-------|-------------|
| `mnemonic` | 24-word BIP39 mnemonic phrase |
| `otp_secret` | Secret key for HMAC-based OTP generation (hex-encoded) |
| `birthday_height` | Block height when the wallet was created |

Set `RUST_LOG=debug` to increase log verbosity (default: `info`).

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

On startup, ZVS will display:
- The wallet's unified address
- Current balance
- Pending verification requests with their OTPs
- Then enter the monitoring loop

## Architecture

Two concurrent tasks share the wallet via `Arc<Mutex>`:

```
┌─────────────────────────┐                          ┌─────────────────────────┐
│   MEMPOOL MONITOR       │                          │   BACKGROUND SYNC       │
│                         │                          │                         │
│ • Streams mempool txs   │                          │ • Periodic block sync   │
│ • Decrypts memos (UFVK) │    Arc<Mutex<Wallet>>    │ • Enhances transactions │
│ • Validates requests    │◄────────────────────────►│ • Catches missed txs    │
│ • Sends OTP inline      │                          │ • Sends OTP inline      │
└─────────────────────────┘                          └─────────────────────────┘
                              ProcessedStore
                          (dedup across restarts)
```

- **Mempool Monitor**: Streams unconfirmed transactions in real-time, decrypts memos with the UFVK, and sends OTP responses immediately.
- **Background Sync**: Periodically syncs the wallet to chain tip (every 30s), processes any verification requests discovered during block scanning.
- **ProcessedStore**: Persistent deduplication — prevents re-sending OTPs after restarts by tracking processed txids on disk.

### Source Files

```
src/
├── main.rs       # Entry point, keys.toml config, task spawning
├── wallet.rs     # Local wallet operations (keys, DB, proving, signing)
├── sync.rs       # Block sync with lightwalletd, in-memory block cache
├── mempool.rs    # Real-time mempool streaming and processing
├── memo_rules.rs # Memo format validation and parsing
├── otp_rules.rs  # HMAC-based OTP generation and transaction requests
└── otp_send.rs   # Shared OTP send logic and processed store
```

### Core Components

- **`Wallet`** - Local-only wallet: keys, database, proving, signing (no network I/O)
- **`MemBlockCache`** - In-memory cache for compact blocks during sync
- **`DecryptedMemo`** - Decrypted memo with txid and value from a received transaction
- **`VerificationRequest`** - Validated request ready for OTP generation
- **`ProcessedStore`** - Persistent txid tracker to prevent duplicate OTPs

### Response Format

OTP response memos contain just the 6-digit code:
```
XXXXXX
```

- `XXXXXX` - 6-digit OTP derived from HMAC-SHA256(secret, session_id)

## Protocol

### Verification Request

Send a shielded transaction to the ZVS wallet address with:
- Memo format: `{zvs/session_id,u-address}` (see Memo Format below)
- Minimum payment: 200,000 zatoshis (0.002 ZEC)

### Verification Response

ZVS responds with a shielded transaction containing:
- Memo: 6-digit OTP code (e.g., `847291`)
- Amount: 50,000 zatoshis (0.0005 ZEC)

## Web App Integration

Web applications can independently verify OTPs by sharing the `OTP_SECRET` with ZVS:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Web App      │     │   User Wallet   │     │      ZVS        │
│ (has OTP_SECRET)│     │                 │     │ (has OTP_SECRET)│
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
    1. Generate                  │                       │
       session_id                │                       │
         │                       │                       │
    2. Show memo ───────────────►│                       │
       to user                   │                       │
         │                  3. Send tx ─────────────────►│
         │                     with memo                 │
         │                       │                  4. Parse memo
         │                       │                     Generate OTP
         │                       │◄──────────────────────│
         │                       │  5. Send OTP in tx    │
         │                       │                       │
    6. User enters  ◄────────────│                       │
       OTP from wallet           │                       │
         │                       │                       │
    7. Web app computes          │                       │
       HMAC(secret, session_id)  │                       │
       and verifies match        │                       │
```

### Memo Format

```
zvs/session_id,u-address
```

- `zvs/` - Prefix identifying a verification request (lowercase)
- `session_id` - Exactly 16 digits for OTP entropy
- `u-address` - User's unified address for OTP response

Example:
```
zvs/1234567890123456,u1abc123...
```

### Browser OTP Generation

```javascript
async function generateOTP(secretHex, sessionId) {
  const encoder = new TextEncoder();
  const secretBytes = hexToBytes(secretHex);
  const key = await crypto.subtle.importKey(
    'raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(sessionId));
  const bytes = new Uint8Array(signature);
  const code = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return String(code % 1000000).padStart(6, '0');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
```

## Security Considerations

- **Shielded transactions** - All communication uses Zcash shielded pools (Sapling/Orchard)
- **HMAC-SHA256** - OTPs are derived deterministically from session IDs
- **Processed store** - Persistent deduplication prevents re-sending OTPs after restarts

## Dependencies

Key dependencies:
- `zcash_client_backend` / `zcash_client_sqlite` - Zcash wallet functionality
- `zcash_proofs` - Zero-knowledge proof generation
- `tonic` - gRPC client for lightwalletd
- `hmac` / `sha2` - OTP generation
- `tokio` - Async runtime

## License

MIT
