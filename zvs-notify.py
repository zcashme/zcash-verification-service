#!/usr/bin/env python3
"""ZVS Telegram notification sidecar.

Tails the zvs.service journal and forwards matching events to Telegram.

Usage:
    journalctl -u zvs -f -o cat | python3 zvs-notify.py
"""

import json
import os
import re
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

TOKEN = os.environ.get("ZVS_TELEGRAM_TOKEN", "REDACTED")
CHAT_IDS = os.environ.get("ZVS_TELEGRAM_CHAT_IDS", "6522296361,604726529").split(",")
LOG_DIR = Path(os.environ.get("ZVS_LOG_DIR", "/home/ubuntu/zcash-verification-service/logs"))

SUPABASE_URL = "https://fpwrazvgrmatlajjzdiq.supabase.co"
SUPABASE_KEY = "sb_publishable_IzToZbZsOrwTIhmMOhWoiQ__AJp--Kr"

SEND_URL = f"https://api.telegram.org/bot{TOKEN}/sendMessage"


LOG_DIR.mkdir(parents=True, exist_ok=True)

_log_handle = None
_log_date = None


def log(line: str) -> None:
    global _log_handle, _log_date
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    if _log_date != today:
        if _log_handle:
            _log_handle.close()
        _log_date = today
        _log_handle = open(LOG_DIR / f"{today}.log", "a")
    _log_handle.write(f"{now.strftime('%H:%M:%S')} {line}\n")
    _log_handle.flush()


def send(msg: str) -> None:
    for chat_id in CHAT_IDS:
        data = urllib.parse.urlencode({"chat_id": chat_id.strip(), "text": msg}).encode()
        try:
            urllib.request.urlopen(SEND_URL, data, timeout=10)
        except Exception:
            pass


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract(pattern: str, text: str) -> str:
    """Extract first capture group from text, or return '?' on failure."""
    m = re.search(pattern, text)
    return m.group(1) if m else "?"


def resolve_username(address: str) -> str | None:
    """Reverse-lookup a unified address to a Zcash.me username via Supabase."""
    if not address or address == "?":
        return None
    try:
        # PostgREST query: SELECT name FROM zcasher WHERE address = eq.<address> LIMIT 1
        query = urllib.parse.urlencode({"address": f"eq.{address}", "select": "name", "limit": "1"})
        url = f"{SUPABASE_URL}/rest/v1/zcasher?{query}"
        req = urllib.request.Request(url, headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        })
        resp = urllib.request.urlopen(req, timeout=5)
        rows = json.loads(resp.read())
        if rows and rows[0].get("name"):
            return rows[0]["name"]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Verification request state — accumulated across the multi-line log block
# ---------------------------------------------------------------------------

class VerificationState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.session_id = None
        self.payment = None
        self.request_txid = None
        self.otp = None
        self.reply_to = None
        self.username = None
        self.ts_init = None

    def parse_line(self, line: str):
        """Parse a single line from the verification request block."""
        if "Session:" in line:
            self.session_id = extract(r"Session:\s*(.+)", line)
            self.ts_init = timestamp()
        elif "Payment:" in line:
            self.payment = extract(r"Payment:\s*(\d+)", line)
        elif "Request tx:" in line:
            self.request_txid = extract(r"Request tx:\s*(\S+)", line)
        elif "Generated OTP:" in line:
            self.otp = extract(r"Generated OTP:\s*(\S+)", line)
        elif "Reply to:" in line:
            self.reply_to = extract(r"Reply to:\s*(\S+)", line)
            self.username = resolve_username(self.reply_to)

    @property
    def user_line(self) -> str:
        if self.username:
            return f"\U0001f44b Zcash.me/{self.username}"
        return f"\U0001f501 Reply-to: {self.reply_to}"

    def format_success(self, response_txid: str, elapsed_sec: int) -> str:
        return (
            f"\U0001f7e2 OTP Verified & Sent\n"
            f"\n"
            f"\U0001f9d1\u200d\U0001f4bb Session ID: {self.session_id}\n"
            f"\U0001fa99 Payment amount: {self.payment} zats\n"
            f"\n"
            f"\u2705 OTP was generated ({self.otp}) and the response "
            f"was sent successfully ({elapsed_sec} seconds).\n"
            f"\n"
            f"\u23f3 {self.ts_init}: Session initialized and OTP generated\n"
            f"\u231b {timestamp()}: OTP response sent successfully\n"
            f"\n"
            f"\u27a1\ufe0f Request transaction ID: {self.request_txid}\n"
            f"\u2b05\ufe0f Response transaction ID: {response_txid}\n"
            f"\n"
            f"{self.user_line}"
        )

    def format_tx_failed(self, error: str) -> str:
        return (
            f"\U0001f534 TX Creation Failed\n"
            f"\n"
            f"\U0001f9d1\u200d\U0001f4bb Session ID: {self.session_id}\n"
            f"\U0001fa99 Payment amount: {self.payment} zats\n"
            f"\U0001f510 Generated OTP: {self.otp}\n"
            f"\n"
            f"\u274c Failed to create transaction request\n"
            f"{error}\n"
            f"\n"
            f"\u27a1\ufe0f Request transaction ID: {self.request_txid}\n"
            f"{self.user_line}"
        )

    def format_send_failed(self, error: str) -> str:
        return (
            f"\U0001f534 OTP Send Failed\n"
            f"\n"
            f"\U0001f9d1\u200d\U0001f4bb Session ID: {self.session_id}\n"
            f"\U0001fa99 Payment amount: {self.payment} zats\n"
            f"\U0001f510 Generated OTP: {self.otp}\n"
            f"\n"
            f"\u274c Failed to send OTP response\n"
            f"{error}\n"
            f"\n"
            f"\u27a1\ufe0f Request transaction ID: {self.request_txid}\n"
            f"{self.user_line}"
        )


def main() -> None:
    state = VerificationState()
    collecting = False
    init_time = None

    for line in sys.stdin:
        line = line.rstrip("\n")
        log(line)

        # --- Buffer multi-line verification request block ---
        if "=== VERIFICATION REQUEST ===" in line and not collecting:
            collecting = True
            state.reset()
            init_time = datetime.now(timezone.utc)
            continue

        if collecting:
            if "============================" in line:
                collecting = False
            else:
                state.parse_line(line)
            continue

        # --- OTP success ---
        # "Transaction created: <txid> (reply to <request_txid>)"
        if "Transaction created:" in line:
            state.response_txid = extract(r"Transaction created:\s*(\S+)", line)
            continue

        # "OTP response broadcast (reply to <request_txid>)"
        if "OTP response broadcast" in line:
            response_txid = getattr(state, "response_txid", "?")
            elapsed = 0
            if init_time:
                elapsed = int((datetime.now(timezone.utc) - init_time).total_seconds())
            send(state.format_success(response_txid, elapsed))
            state.reset()
            init_time = None
            continue

        # --- OTP failures ---
        if "Failed to create OTP response transaction" in line:
            error = extract(r"Failed to create OTP response transaction:\s*(.*)", line)
            send(state.format_tx_failed(error))
            state.reset()
            init_time = None
            continue

        if "Broadcast failed:" in line:
            error = extract(r"Broadcast failed:\s*(.*)", line)
            send(state.format_send_failed(error))
            state.reset()
            init_time = None
            continue

        if "Broadcast rejected:" in line:
            error = extract(r"Broadcast rejected:\s*(.*)", line)
            send(state.format_send_failed(error))
            state.reset()
            init_time = None
            continue

        # --- Standalone events ---
        if "Incoming transaction:" in line:
            zats = extract(r"(\d+) zats", line)
            memo = extract(r'memo="([^"]*)"', line)
            txid = extract(r"tx=(\S+)", line)
            send(
                f"\U0001f4e5 Incoming Transaction\n"
                f"\n"
                f"\U0001fa99 Amount: {zats} zats\n"
                f"\U0001f4dd Memo: {memo}\n"
                f"\u27a1\ufe0f Transaction ID: {txid}"
            )
            continue

        if "Payment too low:" in line:
            zats = extract(r"(\d+) zats", line)
            minimum = extract(r"< (\d+)", line)
            txid = extract(r"tx=(\S+)", line)
            reply_to = extract(r"reply_to=(\S+)\)?", line)
            who = resolve_username(reply_to)
            who_line = f"\U0001f44b Zcash.me/{who}" if who else f"\U0001f501 Reply-to: {reply_to}"
            send(
                f"\u26a0\ufe0f Payment Too Low\n"
                f"\n"
                f"\U0001fa99 Received: {zats} zats (minimum: {minimum})\n"
                f"\u27a1\ufe0f Transaction ID: {txid}\n"
                f"\n"
                f"{who_line}"
            )
            continue

        if "Failed to connect to lightwalletd" in line:
            send(f"\U0001f534 Connection Lost\n\n{line}")
            continue

        if "Background sync failed" in line:
            send(f"\U0001f534 Sync Failed\n\n{line}")
            continue

        if "Mempool stream error" in line:
            send(f"\U0001f534 Stream Error\n\n{line}")
            continue


if __name__ == "__main__":
    main()
