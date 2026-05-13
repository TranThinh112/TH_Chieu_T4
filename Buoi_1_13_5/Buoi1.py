import subprocess
import time
import select
from collections import defaultdict, deque

# =========================
# CONFIG
# =========================
INTERFACE = "ens33"
WINDOW = 10

PORTSCAN_BLOCK_TIME = 10
HIGH_RATE_BLOCK_TIME = 20


PORTSCAN_THRESHOLD = 8
PING_THRESHOLD = 10

WHITELIST = {
    "127.0.0.1",
    "192.168.88.168"
}

# =========================
# STATE
# =========================
port_traffic = defaultdict(deque)
icmp_traffic = defaultdict(deque)
blocked_ips = {}

# =========================
# FIREWALL
# =========================
def block_ip(ip, reason, block_time):
    if ip in blocked_ips:
        return

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        blocked_ips[ip] = {
            "time": time.time(),
            "duration": block_time
        }

        print(f"\n[TRIGGER] {reason}")
        print(f"[BLOCKED] {ip} for {block_time}s\n")

    except subprocess.CalledProcessError:
        print(f"[ERROR] Failed to block {ip}")



def unblock_expired():
    now = time.time()
    expired = []

    for ip, data in list(blocked_ips.items()):
        if now - data["time"] >= data["duration"]:
            expired.append(ip)

    for ip in expired:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            del blocked_ips[ip]
            print(f"[UNBLOCKED] {ip}")

        except subprocess.CalledProcessError:
            pass


# =========================
# CLEANUP
# =========================
def cleanup_ports(ip):
    now = time.time()

    while port_traffic[ip] and now - port_traffic[ip][0][0] > WINDOW:
        port_traffic[ip].popleft()


def cleanup_icmp(ip):
    now = time.time()

    while icmp_traffic[ip] and now - icmp_traffic[ip][0] > WINDOW:
        icmp_traffic[ip].popleft()


# =========================
# DETECTION
# =========================
def detect_port_scan(ip):
    ports = {port for _, port in port_traffic[ip]}
    return len(ports) >= PORTSCAN_THRESHOLD


def detect_high_rate_ping(ip):
    return len(icmp_traffic[ip]) >= PING_THRESHOLD


# =========================
# TSHARK
# =========================
def start_tshark():
    cmd = [
        "tshark",
        "-l",
        "-i", INTERFACE,
        "-Y", "ip",
        "-T", "fields",
        "-E", "separator=|",
        "-e", "ip.src",
        "-e", "icmp.type",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.dstport"
    ]

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
# =========================
# MAIN
# =========================
def detect():
    process = start_tshark()

    print("[INFO] Hybrid IPS started...")
    print("[INFO] PORT_SCAN + ICMP HIGH_RATE enabled")

    while True:
        unblock_expired()

        if process.poll() is not None:
            print("[WARNING] tshark stopped, restarting...")
            process = start_tshark()

        ready, _, _ = select.select([process.stdout], [], [], 1)

        if not ready:
            continue

        line = process.stdout.readline().strip()

        if not line:
            continue

        parts = line.split("|")

        ip = parts[0] if len(parts) > 0 else ""
        icmp_type = parts[1] if len(parts) > 1 else ""
        syn = parts[2] if len(parts) > 2 else ""
        ack = parts[3] if len(parts) > 3 else ""
        dstport = parts[4] if len(parts) > 4 else ""

        if not ip:
            continue

        if ip in WHITELIST or ip in blocked_ips:
            continue

        # =====================
        # PORT SCAN
        # =====================
        if dstport:
            port_traffic[ip].append((time.time(), dstport))
            cleanup_ports(ip)

            ports = {p for _, p in port_traffic[ip]}
            print(f"IP: {ip} | Ports tried: {len(ports)}")

            if detect_port_scan(ip):
                block_ip(ip, "PORT_SCAN DETECTED", PORTSCAN_BLOCK_TIME)

                if ip in port_traffic:
                    del port_traffic[ip]

                if ip in icmp_traffic:
                    del icmp_traffic[ip]

                continue

        # =====================
        # HIGH RATE ICMP
        # =====================
        if icmp_type == "8":
            icmp_traffic[ip].append(time.time())
            cleanup_icmp(ip)

            print(f"IP: {ip} | Ping count: {len(icmp_traffic[ip])}")

            if detect_high_rate_ping(ip):
                block_ip(ip, "HIGH_RATE ICMP", HIGH_RATE_BLOCK_TIME)

                if ip in icmp_traffic:
                    del icmp_traffic[ip]

                if ip in port_traffic:
                    del port_traffic[ip]

if __name__ == "__main__":
    detect()