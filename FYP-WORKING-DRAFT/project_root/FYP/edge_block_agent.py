#!/usr/bin/env python3
"""
Minimal edge-side block agent for ELAI.

Run this on the monitored Ubuntu or edge VM as root. The dashboard can then
request block actions over HTTP, and this agent applies local firewall rules.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import subprocess

HOST = os.environ.get("EDGE_BLOCK_AGENT_HOST", "0.0.0.0")
PORT = int(os.environ.get("EDGE_BLOCK_AGENT_PORT", "8787"))
TOKEN = os.environ.get("EDGE_BLOCK_AGENT_TOKEN", "").strip()
CHAIN = os.environ.get("EDGE_BLOCK_CHAIN", "INPUT")
IPTABLES_BIN = os.environ.get("EDGE_BLOCK_IPTABLES_BIN", "/usr/sbin/iptables")


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def require_auth(handler: BaseHTTPRequestHandler) -> bool:
    if not TOKEN:
        return True

    auth_header = handler.headers.get("Authorization", "")
    expected = f"Bearer {TOKEN}"
    return auth_header == expected


def run_iptables(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [IPTABLES_BIN, *args],
        capture_output=True,
        text=True,
        check=False,
    )


def ensure_drop_rule(ip_address: str) -> tuple[bool, str]:
    check = run_iptables(["-C", CHAIN, "-s", ip_address, "-j", "DROP"])
    if check.returncode == 0:
        return True, f"{ip_address} is already blocked"

    add = run_iptables(["-I", CHAIN, "1", "-s", ip_address, "-j", "DROP"])
    if add.returncode != 0:
        message = (add.stderr or add.stdout or "iptables insert failed").strip()
        return False, message

    return True, f"{ip_address} blocked on {CHAIN}"


def remove_drop_rule(ip_address: str) -> tuple[bool, str]:
    check = run_iptables(["-C", CHAIN, "-s", ip_address, "-j", "DROP"])
    if check.returncode != 0:
        return True, f"{ip_address} was not blocked"

    delete = run_iptables(["-D", CHAIN, "-s", ip_address, "-j", "DROP"])
    if delete.returncode != 0:
        message = (delete.stderr or delete.stdout or "iptables delete failed").strip()
        return False, message

    return True, f"{ip_address} unblocked on {CHAIN}"


class BlockRequestHandler(BaseHTTPRequestHandler):
    server_version = "ELAIEdgeBlockAgent/1.0"

    def do_GET(self) -> None:
        if self.path == "/health":
            return json_response(
                self,
                200,
                {
                    "success": True,
                    "message": "edge block agent ready",
                    "chain": CHAIN,
                    "port": PORT,
                },
            )

        json_response(self, 404, {"success": False, "message": "Not found"})

    def do_POST(self) -> None:
        if self.path not in ("/block-ip", "/unblock-ip"):
            return json_response(self, 404, {"success": False, "message": "Not found"})

        if not require_auth(self):
            return json_response(
                self,
                401,
                {"success": False, "message": "Unauthorized"},
            )

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return json_response(
                self,
                400,
                {"success": False, "message": "Invalid content length"},
            )

        raw_body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            return json_response(
                self,
                400,
                {"success": False, "message": "Invalid JSON payload"},
            )

        ip_address = str(payload.get("ipAddress", "")).strip()
        if not ip_address:
            return json_response(
                self,
                400,
                {"success": False, "message": "ipAddress is required"},
            )

        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return json_response(
                self,
                400,
                {"success": False, "message": "ipAddress is invalid"},
            )

        if self.path == "/block-ip":
            success, message = ensure_drop_rule(ip_address)
        else:
            success, message = remove_drop_rule(ip_address)
        status = 200 if success else 500
        return json_response(
            self,
            status,
            {
                "success": success,
                "message": message,
                "blockedIp": ip_address,
                "chain": CHAIN,
            },
        )

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), BlockRequestHandler)
    print(f"[ELAI Edge Agent] Listening on http://{HOST}:{PORT}")
    server.serve_forever()
