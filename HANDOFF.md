# ZVS Handoff - Current State

## Project Overview

ZVS (Zcash Verification Service) sends OTPs for received transactions with memos matching verification rules. It monitors the mempool in real-time and responds instantly.

## What's Complete

### Phase 1: Detection Pipeline ✅

```
✅ Stream mempool (scan.rs)
✅ Decrypt memos (wallet.rs)
✅ Validate memo format ("pineapple" test)
✅ Check payment >= 2000 zats
✅ Generate OTP (HMAC-SHA256)
✅ Log what we WOULD send (dry run mode)
```

**Files modified:**
- `src/main.rs` - Main runner with mempool streaming loop
- `src/sync.rs` - `fetch_birthday()` for wallet initialization
- `src/scan.rs` - Mempool streaming from lightwalletd
- `src/wallet.rs` - Local wallet operations (decrypt, balance, address)
- `src/memo_rules.rs` - Validation rules (MIN_PAYMENT, validate_memo)
- `src/otp_rules.rs` - OTP generation (generate_otp, build_otp_memo)

**Run it:**
```bash
cargo run
```

**Expected output when verification request arrives:**
```
=== VERIFICATION REQUEST ===
Session: pineapple
Payment: 2000 zats ✓
Request tx: abc123...
Generated OTP: 847291
Response memo: ZVS:otp:847291:req:abc123...
Reply to: u1tdkyje8l5grq8h...
[DRY RUN] Would send 1000 zats to u1tdkyje8l5grq8h...
============================
```

---

## What's Next

### Phase 2: Wallet Sync ⬜

The wallet needs to sync blocks to:
- Know spendable balance
- Track spent notes (avoid double-spend)
- Confirm OTP responses were mined

**Approach:** Use raw `zcash_client_backend` primitives.

**Break into small problems:**

| # | Problem | Function | Complexity |
|---|---------|----------|------------|
| 1 | Get chain tip height | `client.get_latest_block()` | Easy |
| 2 | Tell wallet about chain tip | `db.update_chain_tip(height)` | Easy |
| 3 | Get scan ranges needed | `db.suggest_scan_ranges()` | Easy |
| 4 | Download subtree roots | `client.get_subtree_roots()` | Medium |
| 5 | Download compact blocks | `client.get_block_range()` | Medium |
| 6 | Scan blocks for our txs | `scan_cached_blocks()` | Hard |

**Reference implementation:** `zcash-devtool/src/commands/wallet/sync.rs`

**Key functions to implement in `sync.rs`:**
```rust
// Problem 1: Get chain tip
pub async fn get_chain_tip(client: &mut Client) -> Result<BlockHeight>

// Problem 2: Update chain tip
pub fn update_chain_tip(db: &mut WalletDb, height: BlockHeight) -> Result<()>

// Problem 3-6: Full sync
pub async fn sync_to_tip(client: &mut Client, db: &mut WalletDb) -> Result<()>
```

---

### Phase 3: Transaction Sending ⬜

Once wallet is synced, we can send OTP responses.

**Already implemented in `otp_rules.rs`:**
- `create_otp_transaction_request()` - Creates ZIP-321 request
- `create_change_strategy()` - Fee strategy for transactions

**Need to add to `wallet.rs`:**
```rust
pub async fn send_otp_response(
    &mut self,
    client: &mut Client,
    recipient: &str,
    otp: &str,
    request_txid: &str,
) -> Result<TxId>
```

**Flow:**
1. Create transaction request with OTP memo
2. Propose transfer (input selection)
3. Create and sign transaction
4. Broadcast via lightwalletd

---

### Phase 4: Robustness ⬜

- SQLite deduplication table (track responded requests)
- Retry queue for failed sends
- Periodic block catch-up (not just startup sync)

---

## Environment Variables

```bash
LIGHTWALLETD_URL=https://zec.rocks:443
SEED_HEX=<wallet seed hex>
BIRTHDAY_HEIGHT=3238000
OTP_SECRET=<hmac secret hex>
ZVS_DATA_DIR=./zvs_data  # optional
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         STARTUP                                  │
├─────────────────────────────────────────────────────────────────┤
│  1. Load config (.env)                                           │
│  2. Connect to lightwalletd                                      │
│  3. Fetch birthday tree state                                    │
│  4. Initialize wallet (SQLite)                                   │
│  5. [Phase 2] Sync to chain tip                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      MAIN SERVICE LOOP                           │
├─────────────────────────────────────────────────────────────────┤
│   Mempool Stream (real-time)                                     │
│     ↓                                                            │
│   Decrypt memo → Validate → Generate OTP                        │
│     ↓                                                            │
│   [Phase 3] Send OTP response transaction                        │
│     ↓                                                            │
│   [Phase 4] Record in dedup table                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
src/
├── main.rs        # Entry point, service orchestration
├── wallet.rs      # Local wallet ops (keys, decrypt, balance)
├── scan.rs        # Mempool streaming
├── sync.rs        # Wallet sync with lightwalletd [Phase 2]
├── memo_rules.rs  # Validation (MIN_PAYMENT, validate_memo)
└── otp_rules.rs   # OTP generation and response creation
```

---

## Commits

```
6c575f3 feat: implement mempool streaming with channel-based processing
aee6f6f feat: add sync module and architecture documentation
6f7fc4b feat: wire up memo validation and OTP generation
```

---

## Testing

**Manual test:**
1. Run `cargo run`
2. Send transaction to ZVS wallet address with "pineapple" memo (≥2000 zats)
3. Watch for verification request log

**Debug mempool traffic:**
```bash
RUST_LOG=debug cargo run
```
