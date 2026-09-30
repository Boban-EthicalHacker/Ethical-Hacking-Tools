# Модул за приказ процеса који слушају на мрежним портовима.
# Користи команду `ss -tulpn` (или netstat као резерву).
# За разлику од open_ports модула који чита /proc/net/,
# овај модул показује КОЈИ ПРОЦЕС држи порт отвореним.
#
# Напомена: за приказ туђих процеса потребан је root.
# Без root-а видимо само своје процесе.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess

from rich.console import Console

console = Console()

# Познати портови.
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

# Процеси који су познато безбедни (не приказујемо црвено).
KNOWN_SAFE_PROCESSES = {
    "sshd",
    "systemd",
    "systemd-resolve",
    "systemd-network",
    "cupsd",
    "avahi-daemon",
    "dbus-daemon",
    "chronyd",
    "ntpd",
    "postfix",
    "dovecot",
    "mariadbd",
    "mysqld",
    "postgres",
    "redis-server",
    "nginx",
    "apache2",
    "httpd",
}


def run() -> dict:
    """Приказује процесе који слушају на портовима.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Listening services[/bold cyan]\n")

    # Проверавамо који алат је доступан.
    tool = _detect_tool()

    if tool is None:
        console.print(
            "  [red]Neither 'ss' nor 'netstat' is available.[/red]\n"
        )
        return _empty_result()

    console.print(f"[dim]Using: {tool}[/dim]\n")

    # Читамо податке.
    if tool == "ss":
        services = _read_with_ss()
    else:
        services = _read_with_netstat()

    data = {
        "tool": tool,
        "services": services,
        "summary": {
            "total": len(services),
            "tcp": len([s for s in services if s["protocol"] == "tcp"]),
            "udp": len([s for s in services if s["protocol"] == "udp"]),
            "public": len([
                s for s in services
                if s["address"] in ("0.0.0.0", "::", "*")
            ]),
            "local_only": len([
                s for s in services
                if s["address"] in ("127.0.0.1", "::1", "localhost")
            ]),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "tool": None,
        "services": [],
        "summary": {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "public": 0,
            "local_only": 0,
        },
    }


def _detect_tool() -> str | None:
    """Препознаје који алат је доступан."""
    if shutil.which("ss"):
        return "ss"
    if shutil.which("netstat"):
        return "netstat"
    return None


def _read_with_ss() -> list[dict]:
    """Чита listening портове помоћу `ss -tulpn`."""
    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    output = result.stdout
    if not output:
        return []

    return _parse_ss_output(output)


def _parse_ss_output(output: str) -> list[dict]:
    """Парсира излаз команде `ss -tulpn`.

    Пример:
        Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
        tcp   LISTEN 0      128    127.0.0.1:3306     0.0.0.0:*
            users:(("mariadbd",pid=1234,fd=22))
        udp   UNCONN 0      0      0.0.0.0:5353       0.0.0.0:*
            users:(("avahi-daemon",pid=850,fd=12))
    """
    services = []

    # Прва линија је заглавље.
    lines = output.splitlines()

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        parsed = _parse_ss_line(line)
        if parsed:
            services.append(parsed)

    return services


def _parse_ss_line(line: str) -> dict | None:
    """Парсира једну линију из `ss` излаза."""
    # Прво покушавамо да извучемо процес из users:(("name",pid=N,fd=M)).
    process_name = None
    pid = None

    process_match = re.search(
        r'users:\(\("([^"]+)",pid=(\d+)',
        line,
    )
    if process_match:
        process_name = process_match.group(1)
        try:
            pid = int(process_match.group(2))
        except ValueError:
            pid = None

    # Уклањамо део са процесом да лакше парсирамо остало.
    clean_line = re.sub(r"users:\(.*\)", "", line).strip()

    parts = clean_line.split()
    if len(parts) < 5:
        return None

    # Формат: Netid State Recv-Q Send-Q Local_Address Peer_Address
    protocol = parts[0].lower()   # tcp, udp, tcp6, udp6
    state = parts[1]              # LISTEN, UNCONN
    local_address = parts[4]      # 127.0.0.1:3306

    # Парсирамо адресу и порт.
    address, port = _split_address_port(local_address)
    if port is None:
        return None

    # Скраћујемо IPv6 адресе у читљив облик.
    address = _normalize_address(address)

    return {
        "protocol": protocol,
        "state": state,
        "address": address,
        "port": port,
        "process": process_name,
        "pid": pid,
        "service": COMMON_PORTS.get(port, ""),
    }


def _split_address_port(local: str) -> tuple[str, int | None]:
    """Раздваја адресу и порт из "address:port" формата.

    Ради и за IPv4 (127.0.0.1:3306) и за IPv6 ([::1]:3306 или :::3306).
    """
    # IPv6 формат: [::1]:3306
    if local.startswith("["):
        end = local.find("]")
        if end == -1:
            return local, None
        address = local[1:end]
        port_str = local[end+2:] if len(local) > end + 2 else ""
    else:
        # IPv4 или без заграда.
        if ":" not in local:
            return local, None
        address, port_str = local.rsplit(":", 1)

    try:
        port = int(port_str)
    except ValueError:
        return address, None

    return address, port


def _normalize_address(address: str) -> str:
    """Нормализује адресу у читљив облик."""
    # "*" значи све адресе.
    if address == "*":
        return "0.0.0.0"

    # "::" значи све IPv6 адресе.
    if address == "::":
        return "::"

    # Уклањамо зоне (%eth0, %wlan0).
    if "%" in address:
        address = address.split("%")[0]

    return address


def _read_with_netstat() -> list[dict]:
    """Чита listening портове помоћу `netstat -tulpn`."""
    try:
        result = subprocess.run(
            ["netstat", "-tulpn"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    output = result.stdout
    if not output:
        return []

    return _parse_netstat_output(output)


def _parse_netstat_output(output: str) -> list[dict]:
    """Парсира излаз команде `netstat -tulpn`.

    Пример:
        Proto Recv-Q Send-Q Local Address   Foreign Address  State   PID/Program name
        tcp   0      0      127.0.0.1:3306  0.0.0.0:*        LISTEN  1234/mariadbd
    """
    services = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Прескачемо заглавље.
        if line.startswith(("Proto", "Active")):
            continue

        parsed = _parse_netstat_line(line)
        if parsed:
            services.append(parsed)

    return services


def _parse_netstat_line(line: str) -> dict | None:
    """Парсира једну линију из netstat излаза."""
    parts = line.split()
    if len(parts) < 7:
        return None

    protocol = parts[0].lower()
    local_address = parts[3]
    state = parts[5]
    pid_program = parts[6]

    # Парсирамо PID и име програма.
    process_name = None
    pid = None

    if "/" in pid_program:
        pid_str, process_name = pid_program.split("/", 1)
        try:
            pid = int(pid_str)
        except ValueError:
            pid = None

    # Парсирамо адресу и порт.
    address, port = _split_address_port(local_address)
    if port is None:
        return None

    address = _normalize_address(address)

    return {
        "protocol": protocol,
        "state": state,
        "address": address,
        "port": port,
        "process": process_name,
        "pid": pid,
        "service": COMMON_PORTS.get(port, ""),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    services = data.get("services", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total listening:[/bold]    {summary.get('total', 0)}"
    )
    console.print(
        f"  TCP:              {summary.get('tcp', 0)}"
    )
    console.print(
        f"  UDP:              {summary.get('udp', 0)}"
    )
    console.print(
        f"  Public (0.0.0.0): {summary.get('public', 0)}"
    )
    console.print(
        f"  Local only:       {summary.get('local_only', 0)}"
    )
    console.print()

    if not services:
        console.print(
            "  [dim]No listening services found.[/dim]\n"
        )
        return

    # Сортирамо по порту.
    sorted_services = sorted(services, key=lambda x: x["port"])

    console.print("[bold]Services:[/bold]\n")
    console.print(
        f"  {'PORT':>6s}  {'PROTO':5s}  {'ADDRESS':20s}  "
        f"{'PROCESS':25s}  SERVICE"
    )

    for svc in sorted_services:
        _print_service(svc)

    console.print()

    # Напомена ако нема PID-ова.
    if not any(s.get("pid") for s in services):
        console.print(
            "[dim]Note: no process info available. "
            "Run with sudo to see all processes.[/dim]\n"
        )


def _print_service(svc: dict) -> None:
    """Приказује једну услугу."""
    port = svc["port"]
    protocol = svc["protocol"]
    address = svc["address"]
    process = svc.get("process") or "?"
    pid = svc.get("pid")
    service = svc.get("service", "")

    # Боја — црвено ако слуша на свим адресама.
    is_public = address in ("0.0.0.0", "::", "*")

    if is_public:
        color = "bold red"
    else:
        color = "white"

    # Скраћујемо дугачке адресе.
    if len(address) > 18:
        address = address[:15] + "..."

    # Додајемо PID ако постоји.
    process_display = process
    if pid:
        process_display = f"{process} ({pid})"

    if len(process_display) > 23:
        process_display = process_display[:20] + "..."

    line = (
        f"  [{color}]{port:>6d}[/{color}]  "
        f"{protocol:5s}  "
        f"{address:20s}  "
        f"{process_display:25s}  "
        f"{service}"
    )

    console.print(line)