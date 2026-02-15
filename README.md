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
│   │         │      "VERIFY:session123:u1..."   │         │                  │
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
│        │       tx with memo:                   │  Build  │                  │
│        │       "OTP:847291:ref:abc123"         │   tx    │                  │
│        └────────────────────────────────────── │         │                  │
│                                                └─────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Requirements

- Rust toolchain (edition 2021)
- Access to a lightwalletd server
- Zcash Sapling parameters (for transaction proving)

### Fetching Sapling Parameters

Before running ZVS, you need the Sapling proving parameters:

```bash
./fetch-params.sh
```

Or manually download them to `~/.zcash-params/`.

## Configuration

ZVS is configured via environment variables. Create a `.env` file:

```env
# Required
LIGHTWALLETD_URL=https://mainnet.lightwalletd.com:9067
SEED_HEX=<your-wallet-seed-in-hex>
OTP_SECRET=<your-otp-secret-in-hex>

# Optional
BIRTHDAY_HEIGHT=1        # Wallet birthday height (default: 1)
ZVS_DATA_DIR=./zvs_data  # Data directory (default: ./zvs_data)
POLL_INTERVAL=30         # Block polling interval in seconds (default: 30)
RUST_LOG=info            # Log level (default: info)
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LIGHTWALLETD_URL` | Yes | gRPC URL of the lightwalletd server |
| `SEED_HEX` | Yes | Wallet seed phrase encoded as hex |
| `OTP_SECRET` | Yes | Secret key for HMAC-based OTP generation (hex-encoded) |
| `BIRTHDAY_HEIGHT` | No | Block height when the wallet was created (default: 1) |
| `ZVS_DATA_DIR` | No | Directory for wallet database (default: `./zvs_data`) |
| `POLL_INTERVAL` | No | Seconds between blockchain polls (default: 30) |

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

The service splits into two concurrent tasks communicating via a channel:

```
┌─────────────────────────┐         mpsc channel         ┌─────────────────────────┐
│   MEMPOOL MONITOR       │  ──── VerificationRequest ──→ │   RESPONSE SENDER       │
│   (uses UFVK only)      │                               │   (owns Wallet)         │
│                         │                               │                         │
│ • Streams mempool       │                               │ • Receives requests     │
│ • Decrypts memos        │                               │ • Syncs before send     │
│ • Validates format      │                               │ • Creates OTP tx        │
│ • Queues valid requests │                               │ • Broadcasts response   │
└─────────────────────────┘                               └─────────────────────────┘
```

- **Mempool Monitor**: Uses only the UFVK (viewing key) to decrypt incoming memos. No wallet ownership needed.
- **Response Sender**: Owns the wallet, syncs before each send, creates and broadcasts OTP response transactions.

### Source Files

```
src/
├── main.rs       # CLI runner, mempool monitor, response sender
├── wallet.rs     # Wallet operations and sync
├── scan.rs       # Mempool streaming
├── sync.rs       # Block sync utilities
├── memo_rules.rs # Memo validation rules
└── otp_rules.rs  # OTP generation and response formatting
```

### Core Components

- **`ZVS`** - Main service struct handling wallet operations and blockchain monitoring
- **`MemoryBlockSource`** - In-memory cache for compact blocks during sync
- **`ReceivedMemo`** - Parsed memo data from received transactions
- **`VerificationData`** - Extracted session ID and reply address from verification requests

### Response Format

OTP response memos contain just the 6-digit code:
```
XXXXXX
```

- `XXXXXX` - 6-digit OTP derived from HMAC-SHA256(secret, session_id)

## Protocol

### Verification Request

Send a shielded transaction to the ZVS wallet address with a memo containing:
- Currently: `pineapple` (test mode)

### Verification Response

ZVS responds with a shielded transaction containing:
- Memo: `ZVS:otp:123456:req:abc123...` format
- Amount: 10,000 zatoshis (0.0001 ZEC)

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
- **No external state** - Request tracking uses the blockchain itself via memo correlation

## Dependencies

Key dependencies:
- `zcash_client_backend` / `zcash_client_sqlite` - Zcash wallet functionality
- `zcash_proofs` - Zero-knowledge proof generation
- `tonic` - gRPC client for lightwalletd
- `hmac` / `sha2` - OTP generation
- `tokio` - Async runtime

## License

MIT
