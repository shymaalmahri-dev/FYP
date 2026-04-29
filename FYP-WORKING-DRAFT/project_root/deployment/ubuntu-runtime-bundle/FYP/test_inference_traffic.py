import argparse
import socket
import threading
import time
from typing import Callable

try:
    from scapy.all import IP, TCP, Raw, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


TEST_SERVER_PORT = 9000
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995]
DEFAULT_SCENARIOS = ["normal", "sqli", "cmdi", "xss", "path", "scan", "syn"]
TEST_ATTACKER_IP = "198.51.100.77"


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        sock.close()


def start_echo_server(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)
    print(f"[Test] Echo server listening on {host}:{port}")

    def loop():
        while True:
            try:
                conn, addr = server.accept()
                data = conn.recv(4096)
                if data:
                    print(f"[Test] Server received {len(data)} bytes from {addr}")
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                conn.close()
            except Exception:
                break

    threading.Thread(target=loop, daemon=True).start()
    return server


def send_tcp_payload(target_ip: str, target_port: int, payload: str):
    try:
        with socket.create_connection((target_ip, target_port), timeout=3) as sock:
            sock.sendall(payload.encode("utf-8"))
            try:
                sock.recv(1024)
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
    if not SCAPY_AVAILABLE:
        print("[Test] Scapy unavailable, falling back to a local socket send. This may be ignored by inference as self-traffic.")
        send_tcp_payload(target_ip, target_port, payload or "X" * 40)
        return

    packet = IP(src=source_ip, dst=target_ip) / TCP(
        sport=source_port,
        dport=target_port,
        flags=flags,
        seq=1000,
    )
    if payload:
        packet = packet / Raw(payload.encode("utf-8"))

    try:
        send(packet, verbose=False)
        print(f"[Test] Sent spoofed packet from {source_ip}:{source_port} to {target_ip}:{target_port} with flags={flags}")
    except Exception as exc:
        print(f"[Test] Error sending spoofed packet: {exc}")


def send_normal_baseline(target_ip: str):
    print("[Test] Scenario: normal baseline traffic | Expected result: ideally no alert")
    payloads = [
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "PING /health HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "temperature=23.5&status=ok",
    ]

    for payload in payloads:
        send_tcp_payload(target_ip, TEST_SERVER_PORT, payload)
        time.sleep(0.2)


def test_sql_injection(target_ip: str):
    print("[Test] Scenario: SQL injection payload | Expected layer: Layer 2 DPI")
    payload = (
        "GET /search?q=1=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: elai-test\r\n"
        "Content-Length: 48\r\n\r\n"
        "username=admin&password=123' OR '1'='1' --"
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41001)


def test_command_injection(target_ip: str):
    print("[Test] Scenario: command injection payload | Expected layer: Layer 2 DPI")
    payload = (
        "POST /run HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 26\r\n\r\n"
        "cmd=ping 1.1.1.1 && wget x"
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41002)


def test_xss_injection(target_ip: str):
    print("[Test] Scenario: XSS payload | Expected layer: Layer 2 DPI")
    payload = (
        "POST /comment HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 40\r\n\r\n"
        "<script>alert('owned')</script>"
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41003)


def test_directory_traversal(target_ip: str):
    print("[Test] Scenario: directory traversal payload | Expected layer: Layer 2 DPI")
    payload = (
        "GET /download?file=cat /etc/passwd HTTP/1.1\r\n"
        "Host: example.com\r\n\r\n"
    )
    send_spoofed_tcp_packet(target_ip, TEST_SERVER_PORT, payload, flags="PA", source_port=41004)


def test_port_scan(target_ip: str):
    print("[Test] Scenario: horizontal port scan | Expected layer: Layer 3 behavior")
    for index, port in enumerate(SCAN_PORTS):
        if SCAPY_AVAILABLE:
            send_spoofed_tcp_packet(
                target_ip,
                port,
                payload="",
                flags="S",
                source_port=42000 + index,
            )
        else:
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
        time.sleep(0.08)


def test_syn_like_model_trigger(target_ip: str, count: int = 30):
    print("[Test] Scenario: crafted SYN-heavy burst | Expected layer: Layer 1 ML if model generalizes to this pattern")
    if not SCAPY_AVAILABLE:
        print("[Test] Scapy unavailable; falling back to repeated TCP payloads")
        for _ in range(5):
            send_tcp_payload(target_ip, TEST_SERVER_PORT, "X" * 180)
            time.sleep(0.05)
        return

    for index in range(count):
        packet = IP(src=TEST_ATTACKER_IP, dst=target_ip) / TCP(
            dport=80,
            sport=40000 + index,
            flags="S",
            seq=1000 + index,
        )
        try:
            send(packet, verbose=False)
        except Exception as exc:
            print(f"[Test] Error sending scapy SYN packet: {exc}")
            break
        time.sleep(0.01)

    print(f"[Test] Sent {count} crafted SYN packets to {target_ip}:80")


def scenario_map() -> dict[str, Callable[[str], None]]:
    return {
        "normal": send_normal_baseline,
        "sqli": test_sql_injection,
        "cmdi": test_command_injection,
        "xss": test_xss_injection,
        "path": test_directory_traversal,
        "scan": test_port_scan,
        "syn": test_syn_like_model_trigger,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Safe ELAI traffic scenario runner")
    parser.add_argument(
        "--target-ip",
        type=str,
        default=None,
        help="Target IP for the local inference engine. Defaults to detected local IP.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
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


def main():
    args = parse_args()
    target_ip = args.target_ip or get_local_ip()
    if target_ip == "127.0.0.1":
        print("[Test] Warning: local IP resolved to 127.0.0.1. Inference may be listening on another interface IP.")

    requested = args.scenario or DEFAULT_SCENARIOS
    if "all" in requested:
        requested = DEFAULT_SCENARIOS

    scenarios = scenario_map()

    print(f"[Test] Using target IP {target_ip}")
    print(f"[Test] Selected scenarios: {', '.join(requested)}")

    server = start_echo_server(target_ip, TEST_SERVER_PORT)
    time.sleep(0.5)

    try:
        for name in requested:
            scenarios[name](target_ip)
            time.sleep(args.delay)
    finally:
        print("[Test] Finished sending traffic. Check inference output and explainable_ai/alerts/alerts_log.json")
        time.sleep(1)
        server.close()


if __name__ == "__main__":
    main()
