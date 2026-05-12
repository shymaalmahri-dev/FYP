import argparse      # Parse --target-ip, --scenario, and --delay from the command line
import socket         # Raw TCP connections for send_tcp_payload() and the echo server
import threading      # Run the echo server in a background daemon thread
import time           # time.sleep() pacing between payloads and between scenarios
from typing import Callable   # Type hint for the scenario dispatch dict values

# ─── Optional Scapy import ───────────────────────────────────────────────────
# Scapy is used to craft and send spoofed IP packets (forged source IP, custom
# TCP flags) that look like real attacker traffic coming from a remote machine.
#
# When scapy is available:
#   send_spoofed_tcp_packet() builds an IP/TCP/Raw packet with src=TEST_ATTACKER_IP
#   and injects it directly into the NIC via a raw socket.  inference.py sees the
#   packet with a foreign source IP and evaluates it normally.
#
# When scapy is NOT available (no root, or package missing):
#   SCAPY_AVAILABLE = False; all spoofed-packet functions fall back to plain
#   send_tcp_payload() which uses a local socket.  The packets will be seen by
#   inference.py as self-traffic (src = LOCAL_VM_IP) and silently dropped by the
#   "if attacker_ip == LOCAL_VM_IP: return" guard.  The test still exercises the
#   echo server and prints useful output, but no alerts will fire.
try:
    from scapy.all import IP, TCP, Raw, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# OVERVIEW — WHAT THIS FILE DOES
# ─────────────────────────────────────────────────────────────────────────────
#
# test_inference_traffic.py is a self-contained traffic generator for the ELAI
# lab.  It lets developers and operators validate the full detection pipeline
# without needing a separate Kali VM or attack tools like hping3 / sqlmap.
#
# HOW IT WORKS
# ─────────────────────────────────────────────────────────────────────────────
#   1. An echo server is started on TEST_SERVER_PORT (9000) so TCP connections
#      actually complete — inference.py uses a live sniff loop and needs real
#      packets on the wire, not just connection attempts.
#
#   2. For each selected scenario a function crafts a realistic HTTP-style
#      payload and sends it via a spoofed Scapy packet (src=TEST_ATTACKER_IP)
#      so inference.py's "if attacker_ip == LOCAL_VM_IP: return" guard does not
#      silently discard the test traffic.
#
#   3. inference.py's three detection layers each have a target scenario:
#        Layer 2 DPI       → sqli, cmdi, xss, path  (payload signature hits)
#        Layer 3 Behavior  → scan                    (horizontal port spread)
#        Layer 1 ML        → syn                     (SYN-flood pattern)
#        Baseline          → normal                  (should NOT trigger alerts)
#
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
#   # Run the default balanced demo set (all 7 scenarios) against the local VM:
#   sudo python3 test_inference_traffic.py
#
#   # Run only SQL injection and port scan against a remote inference host:
#   sudo python3 test_inference_traffic.py --target-ip 192.168.56.101 \
#        --scenario sqli --scenario scan
#
#   # Run all scenarios with a 2-second gap between them:
#   sudo python3 test_inference_traffic.py --scenario all --delay 2.0
#
# REQUIREMENTS
# ─────────────────────────────────────────────────────────────────────────────
#   • Python 3.9+
#   • sudo / root — required for Scapy raw socket injection
#   • pip install scapy  (optional but strongly recommended; see note above)
#   • inference.py must be running and sniffing the same interface
# ─────────────────────────────────────────────────────────────────────────────


# ─── Module-level constants ───────────────────────────────────────────────────

# Port on which the local echo server listens.
# All Layer 2 DPI payloads are sent to this port because inference.py only
# inspects TCP payloads, and a real TCP connection ensures the full handshake
# completes so the payload bytes appear in the captured stream.
# Port 9000 is chosen to avoid conflicts with the dashboard (:4000) and the
# block agent (:8787) while still being a plausible web-service port.
TEST_SERVER_PORT = 9000

# Well-known ports used by test_port_scan().
# This list mirrors the port set that real horizontal scanners (nmap default,
# masscan) commonly probe.  Hitting more than 10 unique ports in a 15-second
# window is the Layer 3 Stealth_Horizontal_Port_Scan threshold in inference.py.
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995]

# Default scenario execution order when the user does not pass --scenario.
# The order is deliberate: normal traffic first (baseline) → DPI attacks →
# behavioral attack → ML-targeted attack.  This mirrors the order an analyst
# would expect to see events escalate in a real demo.
DEFAULT_SCENARIOS = ["normal", "sqli", "cmdi", "xss", "path", "scan", "syn"]

# Fake attacker IP embedded in all spoofed Scapy packets.
# 198.51.100.0/24 is part of RFC 5737 documentation range — routable-looking
# but guaranteed never to be a real host on the lab network, so it cannot
# accidentally match LOCAL_VM_IP or any configured ALLOW_SRC_IPS filter.
# inference.py will see this IP as the packet source and process it normally.
TEST_ATTACKER_IP = "198.51.100.77"


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — LOCAL IP DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def get_local_ip():
    """
    Discover the primary non-loopback IPv4 address of this machine.

    Uses the UDP connect trick: connect a datagram socket to a non-routable
    address (10.255.255.255) to force the kernel to select an outgoing interface,
    then read the chosen source IP from getsockname().  No packet is actually
    sent — the socket never reaches the network.

    Returns "127.0.0.1" as a last resort if the connect fails (e.g. no default
    route is configured).  main() warns the user when this happens because
    inference.py will treat 127.0.0.1 traffic as self-traffic and drop it.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# ECHO SERVER
# ─────────────────────────────────────────────────────────────────────────────

def start_echo_server(host: str, port: int):
    """
    Start a lightweight TCP echo server on (host, port) in a daemon thread.

    Why this is necessary:
      Scapy's send() injects packets at Layer 3 (raw IP socket), bypassing the
      kernel's TCP stack.  The target host's kernel will therefore never complete
      a TCP handshake for the spoofed packets — it will send RST replies because
      no socket is listening on the spoofed destination port.

      However, inference.py's sniff() captures packets at Layer 2 (before the
      kernel's TCP processing), so it sees the injected packets regardless of
      whether a real socket accepts them.  The echo server's main purpose is to
      make the non-spoofed send_tcp_payload() calls succeed: those use the
      kernel socket API and require a listening server to complete the connect().

    SO_REUSEADDR:
      Allows the server socket to bind to a port that is in TIME_WAIT state from
      a previous run.  Without this, restarting the test within ~60 seconds of
      the previous run fails with "Address already in use".

    Daemon thread:
      daemon=True means the thread does not prevent the Python process from
      exiting when main() finishes.  server.close() in the finally block sends
      an OSError to server.accept() which breaks the loop cleanly.

    Returns the server socket so main() can call server.close() in the finally block.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)   # Accept up to 10 queued connections before refusing new ones
    print(f"[Test] Echo server listening on {host}:{port}")

    def loop():
        while True:
            try:
                conn, addr = server.accept()
                data = conn.recv(4096)
                if data:
                    print(f"[Test] Server received {len(data)} bytes from {addr}")
                    # Minimal HTTP 200 response so HTTP-formatted payloads get a clean reply
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                conn.close()
            except Exception:
                break   # server.close() causes accept() to raise OSError → exit loop

    threading.Thread(target=loop, daemon=True).start()
    return server


# ─────────────────────────────────────────────────────────────────────────────
# TRANSPORT PRIMITIVES
# ─────────────────────────────────────────────────────────────────────────────

def send_tcp_payload(target_ip: str, target_port: int, payload: str):
    """
    Send a UTF-8 payload over a standard kernel TCP socket connection.

    This is the NON-spoofed send path.  The kernel assigns the local machine's
    real IP as the source, so inference.py will see src_ip == LOCAL_VM_IP and
    silently drop the packet.  This function is therefore only useful as:
      a) a fallback when Scapy is unavailable
      b) the transport for send_normal_baseline() where triggering an alert is
         NOT the goal — we just want to exercise the echo server path

    ConnectionRefusedError is caught and printed rather than raised because a
    refused connection still emits a TCP RST packet onto the wire, which
    inference.py may capture.  The test scenario is not considered failed.

    The recv(1024) call drains the server's HTTP response so the kernel closes
    the connection cleanly and does not leave a FIN_WAIT state that could delay
    the next connection.
    """
    try:
        with socket.create_connection((target_ip, target_port), timeout=3) as sock:
            sock.sendall(payload.encode("utf-8"))
            try:
                sock.recv(1024)   # Drain response; ignore content
            except Exception:
                pass
        print(f"[Test] Sent payload to {target_ip}:{target_port}")
    except ConnectionRefusedError:
        print(f"[Test] Connection refused for {target_ip}:{target_port} (packet likely still emitted)")
    except Exception as exc:
        print(f"[Test] Error sending payload to {target_ip}:{target_port}: {exc}")


def send_spoofed_tcp_packet(
    target_ip: str,
    target_port: int,
    payload: str = "",
    flags: str = "PA",
    source_ip: str = TEST_ATTACKER_IP,
    source_port: int = 44444,
):
    """
    Craft and inject a forged IP/TCP packet using Scapy's raw socket interface.

    This is the PRIMARY send path for all attack scenarios.  It bypasses the
    kernel's TCP stack entirely and writes the packet directly to the NIC so:
      • The source IP is TEST_ATTACKER_IP (198.51.100.77), not the local VM IP.
      • inference.py sees the packet as foreign traffic and does NOT drop it.
      • The kernel on the target side sends a RST back (no real socket accepts
        the spoofed SYN/PSH), but by the time that happens scapy's sniff() on
        inference.py has already captured and processed the injected packet.

    Parameters
    ----------
    target_ip    Destination IP — should be LOCAL_VM_IP so inference.py is
                 listening on the correct interface for it.
    target_port  Destination port — 9000 (echo server) for DPI payloads,
                 well-known ports for the scan scenario.
    payload      Application-layer bytes placed in a Raw Scapy layer.
                 Empty string → no Raw layer (pure TCP header only, used for SYN).
    flags        TCP flag string: "S" = SYN, "PA" = PSH+ACK (data), "SA" = SYN+ACK.
                 "PA" is used for DPI payloads because inference.py's DPI check
                 requires payload bytes, which only appear in PSH segments.
    source_ip    Forged source IP address.  Defaults to TEST_ATTACKER_IP.
    source_port  Forged source port.  Each attack function passes a unique port
                 (41001–41004) to help distinguish individual payloads in Wireshark.

    Fallback:
      When SCAPY_AVAILABLE is False, delegates to send_tcp_payload() with a
      warning.  The traffic will be treated as self-traffic by inference.py.
    """
    if not SCAPY_AVAILABLE:
        print("[Test] Scapy unavailable, falling back to a local socket send. This may be ignored by inference as self-traffic.")
        send_tcp_payload(target_ip, target_port, payload or "X" * 40)
        return

    # Build the IP/TCP stack; Scapy's / operator layers the protocols
    packet = IP(src=source_ip, dst=target_ip) / TCP(
        sport=source_port,
        dport=target_port,
        flags=flags,
        seq=1000,   # Fixed sequence number — fine for single-packet tests
    )
    if payload:
        packet = packet / Raw(payload.encode("utf-8"))   # Attach application-layer bytes

    try:
        send(packet, verbose=False)   # verbose=False suppresses Scapy's per-packet print
        print(f"[Test] Sent spoofed packet from {source_ip}:{source_port} to {target_ip}:{target_port} with flags={flags}")
    except Exception as exc:
        print(f"[Test] Error sending spoofed packet: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO FUNCTIONS — one per detection scenario
# ─────────────────────────────────────────────────────────────────────────────
# Each function follows the same pattern:
#   1. Print a one-liner declaring the scenario and which layer should fire.
#   2. Build a realistic HTTP-formatted payload string.
#   3. Send it via send_spoofed_tcp_packet() (or send_tcp_payload() for normal).
#
# The "Expected layer" notes in the print statements mirror the detection logic
# in inference.py's analyze_packet() and are the ground truth for manual
# verification: run the scenario, observe which layer label appears in the
# inference.py terminal output, and compare.


def send_normal_baseline(target_ip: str):
    """
    Send three benign HTTP-style payloads to establish a normal traffic baseline.

    Expected inference.py outcome:
      • Layer 1 ML classifies all three as "Normal" with high confidence.
      • No alert is emitted (or a "Normal Sample" event appears in the 20 %
        pass-through sample, logged to suspicious.log at severity "low").
      • Layer 2 DPI returns "Clean" (no attack keywords in payload).
      • Layer 3 Behavior returns "Clean" (only one port hit, low rate).

    Uses send_tcp_payload() (non-spoofed) because the goal is legitimate-looking
    traffic, and the local socket path exercises the echo server correctly.
    A 0.2 s delay between payloads prevents them from being merged into a single
    flow by the rolling-window state in inference.py.
    """
    print("[Test] Scenario: normal baseline traffic | Expected result: ideally no alert")
    payloads = [
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",          # Plain HTTP GET
        "PING /health HTTP/1.1\r\nHost: example.com\r\n\r\n",   # Health-check style request
        "temperature=23.5&status=ok",                             # IoT telemetry style payload
    ]

    for payload in payloads:
        send_tcp_payload(target_ip, TEST_SERVER_PORT, payload)
        time.sleep(0.2)   # Brief pause so each packet gets its own IAT measurement


def test_sql_injection(target_ip: str):
    """
    Send a realistic SQL injection payload targeting inference.py's Layer 2 DPI.

    The payload contains both "select … from" style keywords (covered by one
    DPI rule) AND the classic ' OR '1'='1' -- bypass pattern (covered by the
    "1=1" rule).  Either match is sufficient to trigger a Layer 2 DPI hit.

    Expected inference.py outcome:
      • layer_2_dpi() returns "SQL_Injection"
      • Severity: "critical" (from SEVERITY_MAP in inference.py)
      • Block attempted: yes (should_block=True for Layer 2 hits)
      • Alert category: "malicious"

    source_port=41001 uniquely identifies this scenario in packet captures.
    flags="PA" (PSH + ACK) is required because Layer 2 DPI inspects
    packet[TCP].payload; a bare SYN has no payload bytes.
    """
    print("[Test] Scenario: SQL injection payload | Expected layer: Layer 2 DPI")
    payload = (
        "GET /search?q=1=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: elai-test\r\n"
        "Content-Length: 48\r\n\r\n"
        "username=admin&password=123' OR '1'='1' --"   # Classic SQLi bypass
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41001)


def test_command_injection(target_ip: str):
    """
    Send a command injection payload targeting inference.py's Layer 2 DPI.

    The payload body contains "wget x" which matches the DPI rule:
      if "wget " in payload or "curl " in payload: return "Command_Injection"

    The && chaining pattern ("ping 1.1.1.1 && wget x") is realistic for a
    POST /run endpoint that naively passes user input to os.system().

    Expected inference.py outcome:
      • layer_2_dpi() returns "Command_Injection"
      • Severity: "critical"
      • Block attempted: yes

    source_port=41002 differentiates this packet from the SQLi scenario.
    """
    print("[Test] Scenario: command injection payload | Expected layer: Layer 2 DPI")
    payload = (
        "POST /run HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 26\r\n\r\n"
        "cmd=ping 1.1.1.1 && wget x"   # wget trigger for Layer 2 DPI
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41002)


def test_xss_injection(target_ip: str):
    """
    Send a reflected XSS payload targeting inference.py's Layer 2 DPI.

    The payload contains "<script>" which matches:
      if "<script>" in payload: return "XSS_Injection"

    The POST /comment endpoint framing is realistic for a stored-XSS attack
    on a web application's user comment input that lacks output encoding.

    Expected inference.py outcome:
      • layer_2_dpi() returns "XSS_Injection"
      • Severity: "critical"
      • Block attempted: yes

    source_port=41003 differentiates this packet.
    """
    print("[Test] Scenario: XSS payload | Expected layer: Layer 2 DPI")
    payload = (
        "POST /comment HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 40\r\n\r\n"
        "<script>alert('owned')</script>"   # XSS trigger string
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41003)


def test_directory_traversal(target_ip: str):
    """
    Send a directory traversal / LFI payload targeting inference.py's Layer 2 DPI.

    The query string contains "cat /etc/passwd" which matches:
      if "cat /etc/passwd" in payload: return "Directory_Traversal"

    This pattern is typical of a path traversal attempt that breaks out of the
    web root to read sensitive system files via a vulnerable file-download endpoint.

    Expected inference.py outcome:
      • layer_2_dpi() returns "Directory_Traversal"
      • Severity: "critical"
      • Block attempted: yes

    source_port=41004 differentiates this packet.
    """
    print("[Test] Scenario: directory traversal payload | Expected layer: Layer 2 DPI")
    payload = (
        "GET /download?file=cat /etc/passwd HTTP/1.1\r\n"   # LFI via shell command in URL
        "Host: example.com\r\n\r\n"
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41004)


def test_port_scan(target_ip: str):
    """
    Simulate a horizontal port scan across SCAN_PORTS targeting inference.py's Layer 3.

    The Layer 3 behavioral rule in inference.py fires when:
      len(layer3_state[src_ip]["ports"]) > 10   (unique destination ports)
    over a 15-second rolling window.

    SCAN_PORTS has 14 entries (> 10 threshold), so after the final packet
    Layer 3 should return "Stealth_Horizontal_Port_Scan".

    With Scapy available:
      Sends SYN packets (flags="S") — the most common real-world scanner flag.
      Each packet uses a unique source port (42000 + index) to look like a real
      scanner that cycles ephemeral ports.  Payload is empty because SYN has no data.

    Without Scapy (fallback):
      Uses raw socket connect() attempts.  These appear as LOCAL_VM_IP traffic
      in inference.py and will be dropped by the self-traffic guard.  The test
      still prints output but no Layer 3 alert will fire.

    The 0.08 s delay between ports (80 ms) places all 14 packets within a ~1.1 s
    window — well within the 15 s Layer 3 window — ensuring they accumulate in
    the same layer3_state[src_ip] entry.
    """
    print("[Test] Scenario: horizontal port scan | Expected layer: Layer 3 behavior")
    for index, port in enumerate(SCAN_PORTS):
        if SCAPY_AVAILABLE:
            send_spoofed_tcp_packet(
                target_ip,
                port,
                payload="",         # SYN packets carry no application data
                flags="S",          # SYN-only flag — standard stealth scan signature
                source_port=42000 + index,   # Unique source port per probe
            )
        else:
            # Fallback: kernel socket connect — will appear as self-traffic
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((target_ip, port))
                print(f"[Test] Connected to {target_ip}:{port}")
                sock.close()
            except ConnectionRefusedError:
                print(f"[Test] Scan packet to {target_ip}:{port} (refused)")
            except Exception as exc:
                print(f"[Test] Scan packet to {target_ip}:{port} ({exc})")
        time.sleep(0.08)   # 80 ms between probes — fast enough to stay in the 15 s window


def test_syn_like_model_trigger(target_ip: str, count: int = 30):
    """
    Send a burst of 30 SYN packets to port 80 to exercise inference.py's Layer 1 ML.

    This scenario does NOT target Layer 2 DPI (no payload signature) or Layer 3
    behavior (only one destination port — below the 10-port scan threshold and
    not matching the brute-force rate rule at this rate).  Instead it generates
    a traffic pattern — high pkt_rate, is_syn=1, small payload_len=0, dport=80 —
    that the Random Forest may classify as an attack class if it has learned
    SYN-flood patterns from the training set.

    "If model generalizes" caveat:
      Whether the ML model fires depends on the training data and the confidence
      threshold (ATTACK_CONFIDENCE_STRONG = 0.90).  The scenario is not guaranteed
      to produce an alert — it is an exploratory test to see how the model scores
      this traffic pattern.  A gray-zone alert is also a valid and informative
      outcome.

    With Scapy:
      Sends 30 SYN packets using a loop; each packet uses a unique source port
      (40000 + index) to appear as 30 distinct half-open connections.
      10 ms sleep between packets (100 pkt/s) mimics a slow SYN flood.

    Without Scapy:
      Falls back to 5 large-payload TCP sends.  The ML model may still trigger
      on high byte_rate / payload_len features, but the result will be less
      predictable.
    """
    print("[Test] Scenario: crafted SYN-heavy burst | Expected layer: Layer 1 ML if model generalizes to this pattern")
    if not SCAPY_AVAILABLE:
        print("[Test] Scapy unavailable; falling back to repeated TCP payloads")
        for _ in range(5):
            send_tcp_payload(target_ip, TEST_SERVER_PORT, "X" * 180)   # Large filler payload
            time.sleep(0.05)
        return

    for index in range(count):
        packet = IP(src=TEST_ATTACKER_IP, dst=target_ip) / TCP(
            dport=80,                  # HTTP port — common SYN flood target
            sport=40000 + index,       # Incrementing source port — distinct half-open connections
            flags="S",                 # Pure SYN — no payload, no ACK
            seq=1000 + index,          # Incrementing sequence numbers for realism
        )
        try:
            send(packet, verbose=False)
        except Exception as exc:
            print(f"[Test] Error sending scapy SYN packet: {exc}")
            break   # Abort burst on first send error (e.g. interface went down)
        time.sleep(0.01)   # 10 ms between SYNs = ~100 pkt/s burst rate

    print(f"[Test] Sent {count} crafted SYN packets to {target_ip}:80")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

def scenario_map() -> dict[str, Callable[[str], None]]:
    """
    Return the scenario name → function dispatch table.

    Centralising the mapping here (rather than inline in main()) means:
      • parse_args() can derive the valid --scenario choices dynamically from
        scenario_map().keys() without hard-coding them twice.
      • Adding a new scenario requires only one new function + one new dict entry.

    All values are Callable[[str], None] — they accept target_ip as their
    single argument and return nothing.
    """
    return {
        "normal": send_normal_baseline,    # Baseline: should NOT trigger alerts
        "sqli":   test_sql_injection,      # Layer 2 DPI → SQL_Injection (critical)
        "cmdi":   test_command_injection,  # Layer 2 DPI → Command_Injection (critical)
        "xss":    test_xss_injection,      # Layer 2 DPI → XSS_Injection (critical)
        "path":   test_directory_traversal,# Layer 2 DPI → Directory_Traversal (critical)
        "scan":   test_port_scan,          # Layer 3 Behavior → Stealth_Horizontal_Port_Scan
        "syn":    test_syn_like_model_trigger,  # Layer 1 ML → model-dependent
    }


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    """
    Define and parse command-line arguments.

    --target-ip  (optional)
        IPv4 address of the machine running inference.py.  Defaults to the
        local machine's primary IP (get_local_ip()), which is correct when
        the test runner and inference.py are on the same VM.
        Set explicitly when running the test runner on a separate host (e.g.
        Kali VM attacking an Ubuntu VM running inference.py).

    --scenario  (repeatable, optional)
        Name of a scenario to run.  Can be specified multiple times:
          --scenario sqli --scenario scan
        Passing "all" expands to DEFAULT_SCENARIOS.
        When omitted, DEFAULT_SCENARIOS is used (same as "all").
        Choices are generated dynamically from scenario_map().keys() so the
        argparse help text stays in sync with the dispatch table.

    --delay  (optional, default 1.0)
        Seconds to wait between successive scenarios.  A 1-second gap ensures
        the rolling-window state in inference.py has time to partially flush
        between scenarios so they do not interfere with each other's counters.
        Increase to 5+ when ELAI_ALERT_COOLDOWN_SEC is set higher than the default.
    """
    parser = argparse.ArgumentParser(description="Safe ELAI traffic scenario runner")
    parser.add_argument(
        "--target-ip",
        type=str,
        default=None,
        help="Target IP for the local inference engine. Defaults to detected local IP.",
    )
    parser.add_argument(
        "--scenario",
        action="append",   # Each --scenario flag appends to a list; allows repeating
        choices=sorted(scenario_map().keys()) + ["all"],
        help="Scenario to run. Repeat flag for multiple scenarios. Default runs a balanced demo set.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between scenarios.",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    Orchestrate the end-to-end traffic generation run.

    Execution order:
      1. Parse arguments.
      2. Resolve target IP (arg or auto-detect); warn if loopback.
      3. Expand "all" shorthand and validate scenario names.
      4. Start the echo server (blocks until server.close() in the finally block).
      5. Wait 0.5 s for the server thread to enter its accept() loop.
      6. Iterate over selected scenarios in order; sleep --delay seconds between each.
      7. In the finally block: print a completion message and close the server.

    The try/finally pattern ensures server.close() is always called, even when
    a scenario raises an unexpected exception, so the port is not left in use.
    """
    args = parse_args()
    target_ip = args.target_ip or get_local_ip()
    if target_ip == "127.0.0.1":
        # Loopback traffic will be dropped by inference.py's self-traffic guard
        # because LOCAL_VM_IP is also 127.0.0.1 when no routed interface exists.
        print("[Test] Warning: local IP resolved to 127.0.0.1. Inference may be listening on another interface IP.")

    # Expand "all" to the ordered default scenario list; deduplicate while preserving order
    requested = args.scenario or DEFAULT_SCENARIOS
    if "all" in requested:
        requested = DEFAULT_SCENARIOS   # Use canonical order rather than whatever the user typed

    scenarios = scenario_map()

    print(f"[Test] Using target IP {target_ip}")
    print(f"[Test] Selected scenarios: {', '.join(requested)}")

    # Start the echo server BEFORE sending any traffic so the first send_tcp_payload()
    # call does not fail with ConnectionRefusedError before the server is ready.
    server = start_echo_server(target_ip, TEST_SERVER_PORT)
    time.sleep(0.5)   # Give the daemon thread time to reach server.accept()

    try:
        for name in requested:
            scenarios[name](target_ip)   # Call the scenario function with target IP
            time.sleep(args.delay)       # Pause between scenarios to let cooldowns reset
    finally:
        # Always print the completion banner and close the server, even on exception.
        # Analysts should check two places after this script finishes:
        #   • inference.py terminal output — for real-time layer hit messages
        #   • explainable_ai/alerts/alerts_log.json — for the full structured alert records
        print("[Test] Finished sending traffic. Check inference output and explainable_ai/alerts/alerts_log.json")
        time.sleep(1)    # Brief pause so the final scenario's alert has time to be posted
        server.close()   # Unblock server.accept() → loop's except branch → thread exits


if __name__ == "__main__":
    main()
