# ZVS Mempool Streaming Refactor - Handoff

## What Was Done

### Removed Block Syncing Code

**main.rs:**
- Removed `POLL_INTERVAL` env var
- Removed `run_service()` block polling loop
- Added placeholder `run_mempool_service()` that calls `wallet.stream_mempool()` (not implemented)

**wallet.rs:**
- Removed `MemoryBlockSource` struct
- Removed `SyncResult` struct
- Removed `sync()` method
- Removed `download_blocks()` method
- Removed `get_chain_state_at()` method
- Removed `get_scanned_height()` method
- Removed `fetch_pending_memos()` method
- Removed `get_all_memos()` method
- Cleaned up unused imports

**Kept in wallet.rs:**
- `get_chain_height()` - needed for broadcast
- `fetch_birthday_static()` - needed for wallet init
- `fetch_and_process_transaction()` - fetches tx by txid (may be useful)
- Transaction creation/broadcast methods

---

## What Needs To Be Done

### 1. Implement Mempool Streaming in `scan.rs`

The lightwalletd gRPC API provides:

```protobuf
// Returns full raw transactions - can decrypt memos
rpc GetMempoolStream(Empty) returns (stream RawTransaction) {}
```

**RawTransaction format:**
```rust
RawTransaction {
    data: Vec<u8>,  // Full serialized transaction
    height: u64,    // 0 = mempool, other = mined height
}
```

**Existing decryption functions in scan.rs:**
```rust
decrypt_sapling_memo(tx: &Transaction, ufvk: &UnifiedFullViewingKey, block_height: BlockHeight) -> Result<Option<String>>
decrypt_orchard_memo(tx: &Transaction, ufvk: &UnifiedFullViewingKey) -> Result<Option<String>>
```

### 2. Implementation Pattern (from Zashi)

```
┌──────────────────────────────────────────────────┐
│  watchMempool() loop                             │
├──────────────────────────────────────────────────┤
│  Connect to GetMempoolStream                     │
│       ↓                                          │
│  Process each RawTransaction                     │
│       ↓                                          │
│  Parse: Transaction::read(data, branch_id)       │
│       ↓                                          │
│  Decrypt memo (Sapling/Orchard)                  │
│       ↓                                          │
│  If relevant → handle_memo()                     │
│       ↓                                          │
│  Stream ends (block mined)                       │
│       ↓                                          │
│  ├─ Success: wait 500ms → reconnect              │
│  └─ Failure: wait 30s (backoff) → reconnect      │
└──────────────────────────────────────────────────┘
```

### 3. Key Code Snippets

**Connecting to mempool stream:**
```rust
use zcash_client_backend::proto::service::Empty;

let mut stream = client
    .get_mempool_stream(Empty {})
    .await?
    .into_inner();

while let Some(raw_tx) = stream.next().await {
    let raw_tx = raw_tx?;
    // Process transaction...
}
```

**Parsing mempool transaction:**
```rust
// height=0 means mempool, use current network upgrade
let block_height = BlockHeight::from_u32(2_600_000); // Post-NU5
let branch_id = BranchId::for_height(&MainNetwork, block_height);

let tx = Transaction::read(&raw_tx.data[..], branch_id)?;
let txid_hex = hex::encode(tx.txid().as_ref());
```

**Decrypting memo:**
```rust
let ufvk = usk.to_unified_full_viewing_key();

// Try Sapling
if let Some(memo) = decrypt_sapling_memo(&tx, &ufvk, block_height)? {
    // Found memo in Sapling output
}

// Try Orchard
if let Some(memo) = decrypt_orchard_memo(&tx, &ufvk)? {
    // Found memo in Orchard output
}
```

### 4. Fix main.rs

Current `run_mempool_service()` calls `wallet.stream_mempool()` which doesn't exist.

Either:
- Add `stream_mempool()` to `Wallet` struct
- Or refactor main.rs to call mempool streaming from `scan.rs`

---

## Testing

Test script exists: `./test_mempool.sh`

```bash
./test_mempool.sh
```

This streams raw mempool transactions from zec.rocks:443 using grpcurl.

---

## Proto Reference

File: `librustzcash/zcash_client_backend/lightwallet-protocol/walletrpc/service.proto`

```protobuf
// Returns compact transactions - NO decryption possible
rpc GetMempoolTx(GetMempoolTxRequest) returns (stream CompactTx) {}

// Returns FULL raw transactions - decryption possible
rpc GetMempoolStream(Empty) returns (stream RawTransaction) {}
```

Use `GetMempoolStream` for shielded memo decryption.
