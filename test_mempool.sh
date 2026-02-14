#!/bin/bash
# Test mempool stream from lightwalletd

PROTO_DIR="librustzcash/zcash_client_backend/lightwallet-protocol/walletrpc"
PROTO_FILE="$PROTO_DIR/service.proto"
SERVER="zec.rocks:443"

echo "Testing GetMempoolStream on $SERVER..."
echo "Press Ctrl+C to stop"
echo ""

grpcurl \
  -proto "$PROTO_FILE" \
  -import-path "$PROTO_DIR" \
  "$SERVER" \
  cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream
