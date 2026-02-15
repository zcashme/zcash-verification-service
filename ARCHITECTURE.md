# ZVS Architecture

## Overview

ZVS (Zcash Verification Service) is a real-time OTP verification service built on Zcash's shielded transaction protocol. It monitors the mempool for verification requests and responds with one-time passwords.

## Core Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         STARTUP                                  │
├─────────────────────────────────────────────────────────────────┤
│  1. Load config (env vars)                                       │
│  2. Connect to lightwalletd                                      │
│  3. Initialize wallet (SQLite DB)                                │
│  4. Full sync: birthday → chain tip (build spendable balance)   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      MAIN SERVICE LOOP                           │
├──────────────────────┬──────────────────────┬───────────────────┤
│   Mempool Stream     │   Periodic Catch-up  │   Retry Queue     │
│   (real-time)        │   (every N blocks)   │   (failed sends)  │
└──────────┬───────────┴──────────┬───────────┴─────────┬─────────┘
           │                      │                     │
           └──────────────────────┴─────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   VERIFICATION PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│  1. Decrypt memo (wallet viewing key)                            │
│  2. Validate memo (memo_rules.rs)                                │
│  3. Check payment ≥ MIN_PAYMENT (2000 zats)                     │
│  4. Generate OTP: HMAC(secret, session_id) → 6 digits           │
│  5. Send response tx (RESPONSE_AMOUNT + OTP memo)               │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

Environment variables (`.env`):

| Variable | Description | Example |
|----------|-------------|---------|
| `LIGHTWALLETD_URL` | gRPC endpoint for lightwalletd | `https://zec.rocks:443` |
| `SEED_HEX` | Wallet seed (hex encoded) | `f6ff4113...` |
| `BIRTHDAY_HEIGHT` | Block height when wallet was created | `3238000` |
| `OTP_SECRET` | HMAC secret for OTP generation | `a71440d8...` |
| `ZVS_DATA_DIR` | Directory for wallet.db (optional) | `./zvs_data` |

## Module Structure

```
src/
├── main.rs          # Entry point, service orchestration
├── wallet.rs        # Wallet operations (sync, send, decrypt)
├── scan.rs          # Mempool streaming from lightwalletd
└── memo_rules.rs    # Verification request validation
```

### main.rs - Service Runner

Responsibilities:
- Load configuration from environment
- Initialize wallet with SQLite persistence
- Orchestrate startup sequence (connect → sync → stream)
- Run main service loop with graceful shutdown

### wallet.rs - Wallet Operations

Responsibilities:
- Account management (create/load from seed)
- Address generation (Unified Address with Orchard + Sapling)
- Full block sync from birthday to chain tip
- Memo decryption using viewing keys
- Transaction creation and broadcasting
- Balance queries

Key types:
- `Wallet` - Main wallet struct wrapping SQLite DB
- `DecryptedMemo` - Extracted memo with txid and value
- `AccountBalance` - Wallet balance breakdown

### scan.rs - Mempool Streaming

Responsibilities:
- Connect to lightwalletd's `GetMempoolStream` gRPC endpoint
- Parse raw transactions from stream
- Invoke handler callback for each transaction
- Handle stream closure and reconnection

### memo_rules.rs - Verification Rules

Responsibilities:
- Define minimum payment threshold (`MIN_PAYMENT = 2000 zats`)
- Define response amount (`RESPONSE_AMOUNT = 1000 zats`)
- Validate memo format and extract verification data
- Currently: accepts "pineapple" as test memo

## Data Flow

### Incoming Verification Request

```
User Wallet                    Zcash Network                    ZVS
    │                               │                            │
    │  Send tx with memo            │                            │
    │  "pineapple" + 2000 zats     │                            │
    │──────────────────────────────►│                            │
    │                               │                            │
    │                               │  Mempool stream            │
    │                               │───────────────────────────►│
    │                               │                            │
    │                               │                            │ Decrypt memo
    │                               │                            │ Validate rules
    │                               │                            │ Generate OTP
    │                               │                            │
    │                               │  Send OTP response         │
    │                               │◄───────────────────────────│
    │                               │                            │
    │  Receive tx with OTP          │                            │
    │◄──────────────────────────────│                            │
```

### OTP Generation

```rust
fn generate_otp(secret: &[u8], session_id: &str) -> String {
    let mac = HMAC-SHA256(secret, session_id);
    let code = u32::from_be_bytes(mac[0..4]) % 1_000_000;
    format!("{:06}", code)
}
```

- Deterministic: same session_id always produces same OTP
- 6-digit numeric code
- Uses `OTP_SECRET` from environment

## Persistence (SQLite)

### Wallet Tables (via zcash_client_sqlite)

- `accounts` - Wallet accounts and keys
- `transactions` - All wallet transactions
- `received_notes` - Spendable Sapling/Orchard notes
- `nullifiers` - Spent note tracking

### ZVS Tables (custom)

```sql
-- Track responded verification requests
CREATE TABLE zvs_responses (
    id INTEGER PRIMARY KEY,
    request_txid BLOB NOT NULL UNIQUE,
    response_txid BLOB,
    session_id TEXT NOT NULL,
    otp TEXT NOT NULL,
    status TEXT NOT NULL,  -- 'pending', 'sent', 'confirmed', 'failed'
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Retry queue for failed sends
CREATE TABLE zvs_retry_queue (
    id INTEGER PRIMARY KEY,
    response_id INTEGER NOT NULL REFERENCES zvs_responses(id),
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER NOT NULL,
    last_error TEXT
);
```

## Error Handling

### Mempool Stream Errors

| Error Type | Action |
|------------|--------|
| Stream closed (new block) | Reconnect immediately (500ms delay) |
| Connection error | Reconnect with backoff (30s delay) |
| Parse error | Log and skip transaction |

### OTP Send Errors

| Error Type | Action |
|------------|--------|
| Insufficient balance | Queue for retry after sync |
| Network error | Queue for retry with backoff |
| Invalid address | Log error, mark as failed |

## Concurrency Model

Sequential startup, then event loop:

```
1. [BLOCKING] Full wallet sync
2. [LOOP]
   ├── Mempool stream handler (async)
   ├── Block catch-up timer (periodic)
   └── Retry queue processor (periodic)
```

Single-threaded tokio runtime handles all async operations.

## Security Considerations

- Wallet seed stored in environment variable (not in code)
- OTP secret separate from wallet seed
- SQLite database contains sensitive data (should be encrypted at rest)
- All network communication over TLS (lightwalletd)
- Shielded transactions provide sender/recipient privacy

## Future Improvements

1. **Memo Format**: Define structured verification request format
2. **Reply Address**: Extract return address from transaction
3. **Rate Limiting**: Prevent spam requests
4. **Monitoring**: Prometheus metrics endpoint
5. **Multi-account**: Support multiple verification accounts
