#!/usr/bin/env python3
"""Deploy a Worker bundle to Cloudflare via curl (urllib stalls in the proxy
CONNECT phase from this VM — see ~/workspace/custom-connectors/custom.cloudflare/CONNECTOR.md).

The credential is never printed or stored: a surrogate Authorization header
is written to a 0600-permission temp curl config, used once, then deleted.

Usage:
  python3 scripts/deploy-curl.py deploy --name agent-games-gatekeeper \
      --account-id <id> --script-path dist/worker.js
  python3 scripts/deploy-curl.py get-script --name <name> --account-id <id>
  python3 scripts/deploy-curl.py enable-subdomain --name <name> --account-id <id>
  python3 scripts/deploy-curl.py subdomain --account-id <id>
  python3 scripts/deploy-curl.py verify
  python3 scripts/deploy-curl.py put-secret --name <name> --account-id <id> \
      --secret-name AGENT_GAMES_HMAC_SECRET --secret-value <value>
      (sets a Worker secret; the value is sent in the request body only)
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import dynamic_credential_entry

CONNECTOR = "custom.cloudflare"
BASE = "https://api.cloudflare.com/client/v4"


def surrogate():
    entry = dynamic_credential_entry(CONNECTOR, "access_token")
    return str(entry["surrogate"]).strip()


def build_multipart(script_bytes):
    boundary = "----muse-cloudflare-deploy-" + secrets.token_hex(12)
    metadata = json.dumps(
        {"main_module": "worker.js", "compatibility_date": "2026-11-08"}
    ).encode()
    parts = []
    parts.append(
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="metadata"\r\n'
        b"Content-Type: application/json\r\n\r\n" + metadata + b"\r\n"
    )
    parts.append(
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
        b"Content-Type: application/javascript+module\r\n\r\n" + script_bytes + b"\r\n"
    )
    parts.append(b"--" + boundary.encode() + b"--\r\n")
    return b"".join(parts), "multipart/form-data; boundary=" + boundary


def run_curl(method, path, body_file=None, content_type=None):
    """Run one curl call with the surrogate auth. Returns (http_status, text)."""
    cfg_fd, cfg_path = tempfile.mkstemp(prefix="cf-curl-", suffix=".conf")
    try:
        os.fchmod(cfg_fd, 0o600)
        with os.fdopen(cfg_fd, "w") as f:
            f.write('header = "Authorization: Bearer %s"\n' % surrogate())
        cmd = ["curl", "-sS", "-K", cfg_path, "-X", method, "--max-time", "120",
               "-w", "\n%{http_code}", BASE + path]
        if body_file is not None:
            cmd += ["--data-binary", "@" + body_file]
        if content_type is not None:
            cmd += ["-H", "Content-Type: " + content_type]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print("curl failed: " + proc.stderr.strip(), file=sys.stderr)
            raise SystemExit(1)
        out = proc.stdout
        text, _, status = out.rpartition("\n")
        return int(status.strip()), text
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=[
        "verify", "deploy", "get-script", "enable-subdomain", "subdomain",
        "put-secret",
    ])
    parser.add_argument("--name", default="agent-games-gatekeeper")
    parser.add_argument("--script-path", default="dist/worker.js")
    parser.add_argument("--account-id", default=None)
    parser.add_argument("--secret-name", default=None)
    parser.add_argument("--secret-value", default=None)
    args = parser.parse_args()

    if args.command == "verify":
        status, text = run_curl("GET", "/user/tokens/verify")
        print(f"HTTP {status}\n{text}")
        return

    account_id = args.account_id
    if not account_id:
        status, text = run_curl("GET", "/accounts?per_page=50")
        data = json.loads(text)
        accounts = data.get("result", [])
        if len(accounts) != 1:
            print("pass --account-id explicitly; accounts: " +
                  ", ".join(a.get("id", "?") for a in accounts))
            raise SystemExit(1)
        account_id = accounts[0]["id"]

    if args.command == "deploy":
        with open(args.script_path, "rb") as f:
            script_bytes = f.read()
        body, ctype = build_multipart(script_bytes)
        fd, body_path = tempfile.mkstemp(prefix="cf-body-", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(body)
            status, text = run_curl(
                "PUT",
                f"/accounts/{account_id}/workers/scripts/{args.name}",
                body_file=body_path, content_type=ctype,
            )
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass
        print(f"HTTP {status}\n{text}")
        return
    if args.command == "get-script":
        status, text = run_curl(
            "GET", f"/accounts/{account_id}/workers/scripts/{args.name}")
        print(f"HTTP {status}\n{text[:2000]}")
        return
    if args.command == "enable-subdomain":
        fd, body_path = tempfile.mkstemp(prefix="cf-body-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"enabled": True}))
            status, text = run_curl(
                "POST",
                f"/accounts/{account_id}/workers/scripts/{args.name}/subdomain",
                body_file=body_path, content_type="application/json",
            )
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass
        print(f"HTTP {status}\n{text}")
        return
    if args.command == "subdomain":
        status, text = run_curl(
            "GET", f"/accounts/{account_id}/workers/subdomain")
        print(f"HTTP {status}\n{text}")
        return
    if args.command == "put-secret":
        if not args.secret_name or args.secret_value is None:
            print("put-secret needs --secret-name and --secret-value")
            raise SystemExit(1)
        fd, body_path = tempfile.mkstemp(prefix="cf-body-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({
                    "name": args.secret_name,
                    "text": args.secret_value,
                    "type": "secret_text",
                }))
            status, text = run_curl(
                "PUT",
                f"/accounts/{account_id}/workers/scripts/{args.name}/secrets",
                body_file=body_path, content_type="application/json",
            )
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass
        print(f"HTTP {status}\n{text}")
        return


if __name__ == "__main__":
    main()
