#!/usr/bin/env python3
"""
Minimal edge-side block agent for ELAI.

Run this on the monitored Ubuntu or edge VM as root. The dashboard can then
request block actions over HTTP, and this agent applies local firewall rules.

─────────────────────────────────────────────────────────────────────────────
OVERVIEW — WHERE THIS FITS IN THE ELAI ARCHITECTURE
─────────────────────────────────────────────────────────────────────────────

  ┌──────────────┐   detect   ┌────────────────┐   POST /block-ip   ┌──────────────────────┐
  │  Kali VM     │ ─────────► │  inference.py  │ ──────────────────► │  edge_block_agent.py │
  │  (attacker)  │            │  (Layer 1/2/3) │                     │  (this file, :8787)  │
  └──────────────┘            └───────┬────────┘                     └──────────┬───────────┘
                                      │ POST /api/alerts                         │ iptables -I INPUT
                                      ▼                                          ▼
                              ┌───────────────┐                        ┌─────────────────────┐
                              │  elai-dashboard│                        │  Linux kernel       │
                              │  (Node.js :4000│                        │  firewall (DROP)    │
                              └───────────────┘                        └─────────────────────┘

  The dashboard UI also calls POST /block-ip directly when an analyst clicks
  the "Block" button — so blocking can be triggered both automatically by
  inference.py and manually by an operator through the React frontend.

ENDPOINTS
─────────────────────────────────────────────────────────────────────────────
  GET  /health      — liveness probe; returns agent status, chain, and port
  POST /block-ip    — insert an iptables DROP rule for the given source IP
  POST /unblock-ip  — remove the DROP rule for the given source IP

REQUEST BODY (POST /block-ip and /unblock-ip)
─────────────────────────────────────────────────────────────────────────────
  Content-Type: application/json
  {
    "ipAddress": "192.168.56.102",   // required; must be a valid IPv4 or IPv6 address
    "reason":    "SQL injection"     // optional; informational only, not stored
  }

AUTHENTICATION
─────────────────────────────────────────────────────────────────────────────
  Set EDGE_BLOCK_AGENT_TOKEN in the environment.  When set, every POST request
  must include the header:
      Authorization: Bearer <token>
  When the env var is empty the agent runs without authentication (lab / local
  loopback use only — never expose an unauthenticated agent to a routed network).

RUNNING
─────────────────────────────────────────────────────────────────────────────
  # Minimal (lab defaults, no auth):
  sudo python3 edge_block_agent.py

  # Production-style (with auth token, custom port, named chain):
  sudo EDGE_BLOCK_AGENT_TOKEN=secret EDGE_BLOCK_AGENT_PORT=8787 python3 edge_block_agent.py

  # Via the systemd unit supplied in deployment/ubuntu/:
  sudo systemctl enable --now elai-edge-block-agent

DEPENDENCIES
─────────────────────────────────────────────────────────────────────────────
  • Python 3.9+ (http.server.ThreadingHTTPServer available since 3.7)
  • /usr/sbin/iptables (or the path set in EDGE_BLOCK_IPTABLES_BIN)
  • Must run as root (or with CAP_NET_ADMIN) so iptables writes succeed
─────────────────────────────────────────────────────────────────────────────
"""

# ─── Standard library — no third-party dependencies required ─────────────────
# http.server provides a zero-dependency WSGI-free HTTP server.
# BaseHTTPRequestHandler — base class; subclassed by BlockRequestHandler below.
# ThreadingHTTPServer   — spawns a new thread per connection so a slow dashboard
#                         POST does not block the health-check endpoint or a
#                         concurrent unblock request.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ipaddress   # Validate that "ipAddress" values are real IP addresses before
                   # passing them to iptables (prevents shell injection via malformed input)

import json        # Serialise / deserialise HTTP request and response bodies

import os          # Read configuration from environment variables so the agent
                   # can be tuned via /etc/elai/inference.env without code changes

import subprocess  # Execute iptables as a subprocess; check=False so the caller
                   # inspects returncode rather than catching CalledProcessError

# ─────────────────────────────────────────────────────────────────────────────
# RUNTIME CONFIGURATION — all tuneable via environment variables
# ─────────────────────────────────────────────────────────────────────────────

# Interface address the HTTP server binds to.
# "0.0.0.0" listens on all interfaces — suitable when inference.py and the
# dashboard are on separate VMs (e.g. 192.168.56.101 → 192.168.56.103).
# Set to "127.0.0.1" when inference.py and the dashboard share the same Ubuntu VM
# so the agent is not reachable from the network at all.
HOST = os.environ.get("EDGE_BLOCK_AGENT_HOST", "0.0.0.0")

# TCP port the agent listens on.  Must match EDGE_BLOCK_AGENT_URL in:
#   • /etc/elai/inference.env  (used by inference.py's block_ip_on_edge())
#   • elai-dashboard/.env      (used by the dashboard's manual block button)
PORT = int(os.environ.get("EDGE_BLOCK_AGENT_PORT", "8787"))

# Shared secret for Bearer token authentication.
# When empty the agent accepts all requests without checking the Authorization
# header — acceptable for loopback-only deployments, but always set a token
# in any multi-VM lab or production environment.
TOKEN = os.environ.get("EDGE_BLOCK_AGENT_TOKEN", "").strip()

# iptables chain where DROP rules are inserted.
# "INPUT" drops inbound packets from the blocked IP before any application
# running on this VM sees them — the correct choice for protecting a single
# host (the edge VM or the Ubuntu VM itself).
# Use "FORWARD" instead if this VM acts as a router/gateway and you want to
# block traffic passing *through* it to a downstream segment.
CHAIN = os.environ.get("EDGE_BLOCK_CHAIN", "INPUT")

# Absolute path to the iptables binary.
# On some Ubuntu 22.04 systems iptables is a symlink to iptables-legacy or
# iptables-nft under /usr/sbin/.  Override with EDGE_BLOCK_IPTABLES_BIN if
# your distribution places it elsewhere (e.g. /sbin/iptables on older Debian).
IPTABLES_BIN = os.environ.get("EDGE_BLOCK_IPTABLES_BIN", "/usr/sbin/iptables")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    """
    Write a complete JSON HTTP response through a BaseHTTPRequestHandler.

    Encodes 'payload' as UTF-8 JSON, then sends:
      • the HTTP status line
      • Content-Type: application/json
      • Content-Length (required by HTTP/1.1 for keep-alive correctness)
      • the body bytes

    All handlers call this function as their sole response path so the wire
    format is consistent across every endpoint and error case.

    Parameters
    ----------
    handler : BaseHTTPRequestHandler
        The active request handler instance (provides send_response etc.).
    status  : int
        HTTP status code (200, 400, 401, 404, 500).
    payload : dict
        Data to serialise.  Always contains at minimum {"success": bool}.
    """
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def require_auth(handler: BaseHTTPRequestHandler) -> bool:
    """
    Validate the Bearer token on an incoming request.

    Returns True (request is authorised) in two cases:
      1. TOKEN is empty — the agent is running in unauthenticated mode.
      2. The "Authorization" header matches "Bearer <TOKEN>" exactly.

    Returns False (request is rejected) when TOKEN is set but the header is
    absent, malformed, or contains the wrong secret.

    Note: comparison is NOT constant-time.  For a production deployment with
    exposure to untrusted networks, replace with hmac.compare_digest().
    """
    if not TOKEN:
        return True   # Auth disabled; any caller is permitted

    auth_header = handler.headers.get("Authorization", "")
    expected = f"Bearer {TOKEN}"
    return auth_header == expected


# ─────────────────────────────────────────────────────────────────────────────
# IPTABLES WRAPPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def run_iptables(args: list[str]) -> subprocess.CompletedProcess:
    """
    Execute IPTABLES_BIN with the supplied argument list and return the result.

    Design decisions:
      • capture_output=True — captures both stdout and stderr so callers can
        include the iptables error message in the HTTP response body.
      • text=True           — decodes stdout/stderr as UTF-8 strings so callers
        can do simple string operations without manual .decode() calls.
      • check=False         — iptables exits 1 for "rule not found" (used in -C
        checks) which is a normal condition, not an error.  Raising an exception
        there would require a try/except in every caller; returncode inspection
        is cleaner.

    The IPTABLES_BIN variable makes it trivial to swap in ip6tables, iptables-legacy,
    or a mock binary for unit tests without changing this function.
    """
    return subprocess.run(
        [IPTABLES_BIN, *args],   # Unpack args into the command list after the binary
        capture_output=True,
        text=True,
        check=False,
    )


def ensure_drop_rule(ip_address: str) -> tuple[bool, str]:
    """
    Idempotently insert an iptables DROP rule for 'ip_address' on CHAIN.

    Workflow:
      1. Run  iptables -C <CHAIN> -s <ip> -j DROP
         -C (check) exits 0 if the rule already exists, 1 if it does not.
      2. If the rule already exists → return (True, "already blocked") immediately.
         This makes the endpoint idempotent: calling /block-ip twice for the same
         IP is safe and produces the same firewall state.
      3. Run  iptables -I <CHAIN> 1 -s <ip> -j DROP
         -I inserts at position 1 (top of the chain) so the DROP rule is evaluated
         before any ACCEPT rules that may exist lower in the chain.
      4. If the insert fails → return (False, <stderr>) so the HTTP response body
         surfaces the iptables error to the operator.
      5. On success → return (True, "blocked on <CHAIN>").

    Returns
    -------
    (success: bool, message: str)
    """
    check = run_iptables(["-C", CHAIN, "-s", ip_address, "-j", "DROP"])
    if check.returncode == 0:
        return True, f"{ip_address} is already blocked"   # Rule present — nothing to do

    add = run_iptables(["-I", CHAIN, "1", "-s", ip_address, "-j", "DROP"])
    if add.returncode != 0:
        # Prefer stderr (iptables validation errors), fall back to stdout, then a generic message
        message = (add.stderr or add.stdout or "iptables insert failed").strip()
        return False, message

    return True, f"{ip_address} blocked on {CHAIN}"


def remove_drop_rule(ip_address: str) -> tuple[bool, str]:
    """
    Idempotently remove a DROP rule for 'ip_address' from CHAIN.

    Workflow:
      1. Run  iptables -C <CHAIN> -s <ip> -j DROP
         If the rule does NOT exist (returncode != 0) → return (True, "was not blocked").
         Treating an absent rule as success makes /unblock-ip idempotent.
      2. Run  iptables -D <CHAIN> -s <ip> -j DROP
         -D deletes the first matching rule.  If the same IP was blocked more than
         once (unlikely with ensure_drop_rule's idempotency check but possible via
         manual iptables commands), only one rule is removed per call.
      3. On delete failure → return (False, <stderr>).
      4. On success → return (True, "unblocked on <CHAIN>").

    Returns
    -------
    (success: bool, message: str)
    """
    check = run_iptables(["-C", CHAIN, "-s", ip_address, "-j", "DROP"])
    if check.returncode != 0:
        return True, f"{ip_address} was not blocked"   # Rule absent — nothing to remove

    delete = run_iptables(["-D", CHAIN, "-s", ip_address, "-j", "DROP"])
    if delete.returncode != 0:
        message = (delete.stderr or delete.stdout or "iptables delete failed").strip()
        return False, message

    return True, f"{ip_address} unblocked on {CHAIN}"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP REQUEST HANDLER
# ─────────────────────────────────────────────────────────────────────────────

class BlockRequestHandler(BaseHTTPRequestHandler):
    """
    Per-connection HTTP request handler for the ELAI edge block agent.

    Inherits from BaseHTTPRequestHandler; each inbound TCP connection
    instantiates a new BlockRequestHandler in its own thread (courtesy of
    ThreadingHTTPServer).

    Supported routes:
      GET  /health      — liveness probe (no auth required)
      POST /block-ip    — add DROP rule (auth required if TOKEN is set)
      POST /unblock-ip  — remove DROP rule (auth required if TOKEN is set)

    All other paths return 404.  All response bodies are JSON.
    """

    # Overrides the default Python version string in the "Server:" response
    # header.  Keeps the banner informative without advertising the Python version
    # to potential scanners.
    server_version = "ELAIEdgeBlockAgent/1.0"

    def do_GET(self) -> None:
        """
        Handle GET requests.

        Only /health is supported.  It returns a 200 with agent metadata so
        orchestration tools (systemd watchdog, uptime monitors, the dashboard's
        connectivity check) can confirm the agent is alive and identify its
        configured chain and port without needing to attempt a real block action.

        Any other path gets a 404.
        """
        if self.path == "/health":
            return json_response(
                self,
                200,
                {
                    "success": True,
                    "message": "edge block agent ready",
                    "chain": CHAIN,    # Lets the caller confirm which iptables chain is in use
                    "port": PORT,      # Echo back the listening port for diagnostic clarity
                },
            )

        json_response(self, 404, {"success": False, "message": "Not found"})

    def do_POST(self) -> None:
        """
        Handle POST /block-ip and POST /unblock-ip requests.

        Validation pipeline (each step returns early on failure):
          ① Route check   — reject unknown paths with 404
          ② Auth check    — reject missing/wrong Bearer token with 401
          ③ Length parse  — reject non-integer Content-Length with 400
          ④ Body read     — read exactly Content-Length bytes from the socket
          ⑤ JSON decode   — reject malformed JSON with 400
          ⑥ IP extract    — reject absent ipAddress field with 400
          ⑦ IP validate   — reject non-IP strings with 400 (prevents iptables injection)
          ⑧ Firewall op   — call ensure_drop_rule or remove_drop_rule
          ⑨ Response      — 200 on success, 500 if iptables returned non-zero

        The ipaddress.ip_address() validation at step ⑦ is the critical security
        gate: it ensures only well-formed IPv4/IPv6 strings reach subprocess,
        making shell-injection via a crafted "ipAddress" value impossible.
        """
        # ── ① Route check ──────────────────────────────────────────────────
        if self.path not in ("/block-ip", "/unblock-ip"):
            return json_response(self, 404, {"success": False, "message": "Not found"})

        # ── ② Auth check ───────────────────────────────────────────────────
        if not require_auth(self):
            return json_response(
                self,
                401,
                {"success": False, "message": "Unauthorized"},
            )

        # ── ③ Content-Length parse ─────────────────────────────────────────
        # A missing or non-integer Content-Length header is rejected rather than
        # defaulting to 0, which would silently swallow partial bodies.
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return json_response(
                self,
                400,
                {"success": False, "message": "Invalid content length"},
            )

        # ── ④ Body read ────────────────────────────────────────────────────
        # If Content-Length is 0 or the header was absent, default to an empty
        # JSON object so the JSON decode step can still run and produce a clean
        # "ipAddress is required" error rather than a decode error.
        raw_body = self.rfile.read(content_length) if content_length else b"{}"

        # ── ⑤ JSON decode ──────────────────────────────────────────────────
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            return json_response(
                self,
                400,
                {"success": False, "message": "Invalid JSON payload"},
            )

        # ── ⑥ IP field extraction ──────────────────────────────────────────
        # .get() returns None for a missing key; str() + .strip() normalises
        # None → "" and removes leading/trailing whitespace from valid values.
        ip_address = str(payload.get("ipAddress", "")).strip()
        if not ip_address:
            return json_response(
                self,
                400,
                {"success": False, "message": "ipAddress is required"},
            )

        # ── ⑦ IP validation ────────────────────────────────────────────────
        # ipaddress.ip_address() accepts both IPv4 ("1.2.3.4") and IPv6
        # ("::1") strings and raises ValueError for anything else.  Passing an
        # unvalidated string to iptables via subprocess could allow an attacker
        # who can reach this endpoint to inject arbitrary iptables arguments.
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return json_response(
                self,
                400,
                {"success": False, "message": "ipAddress is invalid"},
            )

        # ── ⑧ Firewall operation ────────────────────────────────────────────
        # Dispatch to the correct helper based on the request path.
        # Both helpers return (bool, str) and are safe to call regardless of
        # the current firewall state (idempotent check-then-act pattern).
        if self.path == "/block-ip":
            success, message = ensure_drop_rule(ip_address)
        else:
            success, message = remove_drop_rule(ip_address)

        # ── ⑨ Response ─────────────────────────────────────────────────────
        # 200 on any successful firewall operation (including "already blocked").
        # 500 only when iptables itself returned a non-zero exit code, meaning
        # the requested firewall state could NOT be achieved.
        status = 200 if success else 500
        return json_response(
            self,
            status,
            {
                "success": success,
                "message": message,
                "blockedIp": ip_address,  # Echo back so the caller can confirm the IP it sent
                "chain": CHAIN,           # Echo back so multi-chain deployments are traceable
            },
        )

    def log_message(self, format: str, *args) -> None:
        """
        Suppress the default per-request log line printed to stderr.

        BaseHTTPRequestHandler.log_message() writes one line per request to
        stderr (e.g. '127.0.0.1 - - [12/May/2026 10:00:00] "POST /block-ip HTTP/1.1" 200 -').
        In production this is captured by journald via the systemd unit's
        StandardError=journal directive.  Overriding with a no-op keeps the
        terminal clean during interactive testing while preserving the ability
        to re-enable logging by removing this override.
        """
        return   # Intentional no-op — suppress default HTTP access log to stderr


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ThreadingHTTPServer — subclass of HTTPServer that mixes in ThreadingMixIn.
    # Each accepted connection is dispatched to a new daemon thread, so a slow
    # dashboard POST (e.g. waiting on iptables while the chain has many rules)
    # does not block the health-check endpoint or a concurrent unblock call.
    #
    # (HOST, PORT) — the (address, port) tuple passed to socket.bind().
    # HOST = "0.0.0.0" binds to all interfaces; change to "127.0.0.1" for
    # loopback-only operation when inference.py and the dashboard share one VM.
    server = ThreadingHTTPServer((HOST, PORT), BlockRequestHandler)
    print(f"[ELAI Edge Agent] Listening on http://{HOST}:{PORT}")

    # serve_forever() enters a select() loop that accepts connections until the
    # process receives SIGINT (Ctrl-C) or SIGTERM (systemd stop).
    # The systemd unit sets Restart=always so an unexpected crash is recovered
    # automatically within RestartSec=5 seconds.
    server.serve_forever()
