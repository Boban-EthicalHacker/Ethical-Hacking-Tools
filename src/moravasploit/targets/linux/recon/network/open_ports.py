# Модул за приказ отворених портова на систему.
# Чита /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6.
# Ово су kernel-level фајлови који приказују све мрежне
# конекције без потребе за спољним алатима.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import socket
import struct
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до kernel фајлова са мрежним конекцијама.
PROC_NET_TCP = Path("/proc/net/tcp")
PROC_NET_TCP6 = Path("/proc/net/tcp6")
PROC_NET_UDP = Path("/proc/net/udp")
PROC_NET_UDP6 = Path("/proc/net/udp6")

# TCP стања (из Linux kernel-а).
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

# Познати портови (само најчешћи).
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3000: "Node.js / Rails",
    3306: "MySQL",
    5000: "Flask / dev server",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP alt",
    8080: "HTTP proxy",
    8443: "HTTPS alt",
    9000: "PHP-FPM",
    9090: "Prometheus",
    27017: "MongoDB",
}


def run() -> dict:
    """Приказује отворене портове на систему.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Open ports[/bold cyan]\n")

    # Читамо све конекције.
    tcp = _read_proc_net(PROC_NET_TCP, "tcp")
    tcp6 = _read_proc_net(PROC_NET_TCP6, "tcp6")
    udp = _read_proc_net(PROC_NET_UDP, "udp")
    udp6 = _read_proc_net(PROC_NET_UDP6, "udp6")

    # Издвајамо само listening портове.
    listening = _filter_listening(tcp + tcp6 + udp + udp6)

    # Укупне статистике.
    all_connections = tcp + tcp6 + udp + udp6

    data = {
        "listening": listening,
        "all_connections_count": len(all_connections),
        "summary": {
            "total_listening": len(listening),
            "tcp_listening": len([x for x in listening if "tcp" in x["protocol"]]),
            "udp_listening": len([x for x in listening if "udp" in x["protocol"]]),
            "total_connections": len(all_connections),
        },
    }

    _print_data(data)

    return data


def _read_proc_net(path: Path, protocol: str) -> list[dict]:
    """Чита /proc/net/<protocol> фајл."""
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return []

    lines = content.splitlines()

    # Прва линија је заглавље.
    if len(lines) < 2:
        return []

    entries = []

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        parsed = _parse_proc_net_line(line, protocol)
        if parsed:
            entries.append(parsed)

    return entries


def _parse_proc_net_line(line: str, protocol: str) -> dict | None:
    """Парсира једну линију из /proc/net/."""
    parts = line.split()
    if len(parts) < 4:
        return None

    # Формат линије (по колонама):
    # sl  local_address  rem_address  st  tx_queue:rx_queue  ...
    # 0:  0100007F:1F90  00000000:0000  0A  00000000:00000000  ...
    try:
        local_addr = parts[1]
        state = parts[3]
    except IndexError:
        return None

    # Парсирамо адресу и порт.
    try:
        ip, port = _parse_address(local_addr, protocol)
    except ValueError:
        return None

    # Стање.
    if "tcp" in protocol:
        state_name = TCP_STATES.get(state.upper(), "UNKNOWN")
    else:
        # UDP нема стања — користимо "LISTEN" за отворене портове.
        # У /proc/net/udp, state 07 значи да није повезан (listening).
        state_name = "LISTEN" if state == "07" else "CONNECTED"

    return {
        "protocol": protocol,
        "ip": ip,
        "port": port,
        "state": state_name,
        "state_code": state,
        "service": COMMON_PORTS.get(port, ""),
    }


def _parse_address(addr: str, protocol: str) -> tuple[str, int]:
    """Парсира адресу из /proc/net формата.

    Формат: HEHEX_IP:HEX_PORT
    Пример: 0100007F:1F90  (127.0.0.1:8080)
    """
    if ":" not in addr:
        raise ValueError("invalid address format")

    ip_hex, port_hex = addr.rsplit(":", 1)

    # Порт је увек hex.
    port = int(port_hex, 16)

    # IP адреса — разликује се за IPv4 и IPv6.
    if "6" in protocol:
        # IPv6 — 32 hex карактера (16 бајтова).
        ip = _parse_ipv6(ip_hex)
    else:
        # IPv4 — 8 hex карактера (4 бајта).
        ip = _parse_ipv4(ip_hex)

    return ip, port


def _parse_ipv4(hex_str: str) -> str:
    """Парсира IPv4 адресу из hex формата.

    Linux чува IP у little-endian формату.
    Пример: "0100007F" -> "127.0.0.1"
    """
    if len(hex_str) != 8:
        raise ValueError("invalid IPv4 hex")

    # Конвертујемо у бајтове.
    bytes_le = bytes.fromhex(hex_str)

    # Обрћемо редослед (little-endian).
    bytes_be = bytes_le[::-1]

    # Узимамо 4 бајта.
    return ".".join(str(b) for b in bytes_be)


def _parse_ipv6(hex_str: str) -> str:
    """Парсира IPv6 адресу из hex формата.

    IPv6 је 32 hex карактера (16 бајтова). Linux чува сваку
    4-бајтну групу у little-endian формату.
    """
    if len(hex_str) != 32:
        raise ValueError("invalid IPv6 hex")

    # Раздвајамо на 4 групе по 8 карактера.
    groups = [hex_str[i:i+8] for i in range(0, 32, 8)]

    # Сваку групу обрћемо (little-endian).
    bytes_list = []
    for group in groups:
        group_bytes = bytes.fromhex(group)
        bytes_list.append(group_bytes[::-1])

    # Спајамо у 16 бајтова.
    addr_bytes = b"".join(bytes_list)

    # Конвертујемо у читљив IPv6 формат.
    try:
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    except Exception:
        return hex_str


def _filter_listening(entries: list[dict]) -> list[dict]:
    """Издваја само listening портове."""
    result = []

    for entry in entries:
        if entry["state"] == "LISTEN":
            result.append(entry)

    # Уклањамо дупликате (исти порт може да буде на IPv4 и IPv6).
    seen = set()
    unique = []

    for entry in result:
        key = (entry["port"], entry["protocol"].rstrip("6"))
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    # Сортирамо по порту.
    unique.sort(key=lambda x: x["port"])

    return unique


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    listening = data.get("listening", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Listening ports:[/bold]    "
        f"{summary.get('total_listening', 0)}"
    )
    console.print(
        f"  TCP:              "
        f"{summary.get('tcp_listening', 0)}"
    )
    console.print(
        f"  UDP:              "
        f"{summary.get('udp_listening', 0)}"
    )
    console.print(
        f"[bold]Total connections:[/bold]  "
        f"{summary.get('total_connections', 0)}"
    )
    console.print()

    if not listening:
        console.print(
            "  [dim]No listening ports found.[/dim]\n"
        )
        return

    # Приказујемо листу портова.
    console.print("[bold]Ports:[/bold]\n")
    console.print(
        f"  {'PORT':>6s}  {'PROTO':8s}  {'ADDRESS':45s}  SERVICE"
    )

    for entry in listening:
        port = entry["port"]
        protocol = entry["protocol"]
        ip = entry["ip"]
        service = entry["service"]

        # Скраћујемо дугачке IPv6 адресе.
        if len(ip) > 43:
            ip = ip[:40] + "..."

        # Боја — црвено за портове који слушају на 0.0.0.0 или ::.
        if ip in ("0.0.0.0", "::", "::0"):
            color = "bold red"
            ip_display = f"{ip} (all)"
        elif ip in ("127.0.0.1", "::1"):
            color = "dim"
            ip_display = f"{ip} (local)"
        else:
            color = "white"
            ip_display = ip

        line = (
            f"  [{color}]{port:>6d}[/{color}]  "
            f"{protocol:8s}  {ip_display:45s}  "
            f"{service}"
        )

        console.print(line)

    console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"