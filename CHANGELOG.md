# Changelog

Intenral change-tracking to ZVS (Zcash Verification Service) is documented here.

## [2.1.0] — 2025-03-26

### Default
- Update README to reflect channel-based architecture

## [2.0.0] — 2025-03-26

### Proud — Channel architecture
- Eliminate `Arc<Mutex<Wallet>>` with channel-based message passing
- Clean, mutex-free design

## [1.7.7] — 2025-03-26

### Default
- Replace `.env` with `keys.toml` for secrets config
- Replace `ProcessedStore` with in-memory `RespondedSet`
- Merge `otp_send` module into `otp_rules`

## [1.6.7] — 2025-03-25

### Shame
- Untrack `zvs-notify.py` (contained hardcoded tokens)

## [1.6.6] — 2025-03-25

### Shame
- Replace OTP queue with shared function — one commit after building it

## [1.6.5] — 2025-03-25

### Default
- OTP queue with producer-consumer architecture

## [1.5.5] — 2025-03-25

### Shame
- Fix: log `reply_to` address in payment-too-low warning

## [1.5.4] — 2025-03-25

### Default
- Event-driven architecture with clean module separation
- Rewrite notification sidecar in Python
- Inline gRPC client connection, remove `client.rs`

## [1.4.4] — 2025-03-24

### Shame
- Remove unit tests from `otp_rules` and `memo_rules`

## [1.4.3] — 2025-03-24

### Default
- Support BIP39 mnemonic seed phrases
- Cache `LocalTxProver` on Wallet struct

## [1.3.3] — 2025-03-24

### Shame
- Split into two tasks, drew architecture diagram, immediately merged back to single event loop

## [1.3.2] — 2025-03-24

### Default
- New memo format `zvs/session_id,u-address`
- Background sync every N blocks for instant OTP responses
- Simplify OTP memo to contain only 6-digit code

## [1.2.2] — 2025-03-23

### Shame
- Remove orphaned `verification.rs`

## [1.2.1] — 2025-03-23

### Default
- Mempool streaming with channel-based processing
- Wallet sync with in-memory block cache
- `send_transaction` method with bundled prover
- Use `Zatoshis` type instead of raw `u64` for amounts

## [1.1.1] — 2025-03-22

### Shame
- Remove rusqlite dependency, stub wallet queries
- Remove dead code from scan, verification, and wallet modules

## [1.1.0] — 2025-03-22

### Default
- Rewrite README with comprehensive project documentation
- Reduce minimum send amount to 1000 zatoshis
- Gitignore and dependency cleanup

## [1.0.0] — 2025-03-22

### Proud — It works end-to-end!
- Implement actual OTP transaction sending
- Receive payment, validate memo, send OTP back
- Display balance, pending requests, and OTPs on startup

## [0.5.2] — 2025-03-21

### Default
- Display balance, pending requests, and OTPs on startup

## [0.4.2] — 2025-03-21

### Shame
- Remove separate `zvs_state.db` that didn't need to exist

## [0.4.1] — 2025-03-21

### Default
- Full memo decryption from transactions
- OTP generation and persistent state tracking

## [0.3.1] — 2025-03-20

### Default
- Real-time block monitoring and CLI subcommands

## [0.2.1] — 2025-03-20

### Default
- Integrate `zcash_client_sqlite` for full wallet functionality
- HANDOFF.md documenting librustzcash learnings

## [0.1.1] — 2025-03-19

### Shame
- WIP sqlite migration, switched to Orchard, removed sqlite, added it back

## [0.1.0] — 2025-03-19

### Default
- Realtime block scanning loop
- Memo parsing and validation rules
- `zcash_client_backend` integration

## [0.0.0] — 2025-03-19

### Genesis
- Initial ZVS (Zcash Verification Service) setup
