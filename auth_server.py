"""
auth_server.py — Garena Auth Server untuk AUTH_URL
Menerima: GET /token?uid=xxx&password=xxx
Return:   {"token": "eyJhbGci..."}

Deploy di Railway/Render sebagai service terpisah.
"""

from flask import Flask, request, jsonify
import requests
import hmac
import hashlib
import base64
import json
import os

app = Flask(__name__)

# ── Konstanta Garena ──────────────────────────────────────────────────────────
# Set MASTER_KEY_HEX di Railway environment variables (optional, sudah ada default)
MASTER_KEY = bytes.fromhex(os.environ.get("MASTER_KEY_HEX", "32656534343831396539623435393838343531343130363762323831363231383746433064356437616639643866376530306331653534373135623764316533"))

GARENA_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
HEADERS = {
    "Accept-Encoding": "gzip",
    "Connection":      "Keep-Alive",
    "Content-Type":    "application/x-www-form-urlencoded",
    "Host":            "100067.connect.garena.com",
    "User-Agent":      "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
}

# ── Ambil JWT dari FF token ───────────────────────────────────────────────────

def get_ff_jwt(access_token: str) -> str | None:
    """Extract JWT dari FF login response menggunakan access_token."""
    try:
        # Decode JWT payload dari access_token (token Garena sudah berisi info)
        # Return access_token langsung — ini yang dipakai sebagai Bearer di API
        return access_token
    except Exception:
        return None


def garena_token(uid: str, password: str) -> str | None:
    """Hit Garena auth dan return access_token."""
    try:
        body = {
            "uid":           uid,
            "password":      password,
            "response_type": "token",
            "client_type":   "2",
            "client_secret": MASTER_KEY,
            "client_id":     "100067",
        }
        r = requests.post(GARENA_URL, headers=HEADERS, data=body, timeout=15)
        rj = r.json()

        if "access_token" in rj:
            return rj["access_token"]
        else:
            print(f"[AUTH] Garena error for uid {uid}: {rj}")
            return None
    except Exception as e:
        print(f"[AUTH] Exception for uid {uid}: {e}")
        return None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/token")
def get_token():
    uid      = request.args.get("uid")
    password = request.args.get("password")

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    token = garena_token(uid, password)

    if token:
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Failed to get token from Garena"}), 500


@app.route("/")
def home():
    return jsonify({"status": "Auth server running"})


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
