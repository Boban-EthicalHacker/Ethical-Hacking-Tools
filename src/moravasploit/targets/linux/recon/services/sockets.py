# Модул за приказ systemd socket јединица.
# Socket activation је systemd механизам где systemd слуша
# на порту, а тек кад стигне конекција покрене сервис.
# Ово значи да сервис може бити "неактиван" али се покреће
# на захтев. Нападачи могу користити ово за скривени persistence.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми са systemd socket фајловима.
SYSTEMD_DIRS = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
]

# Познати портови.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    631: "CUPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP alt",
    8443: "HTTPS alt",
}

# Патерни који указују на сумњиве socket јединице.
SUSPICIOUS_PATTERNS = [
    (r"/tmp/", "socket in /tmp"),
    (r"/var/tmp/", "socket in /var/tmp"),
    (r"/dev/shm/", "socket in /dev/shm"),
    (r"backdoor", "name contains backdoor"),
    (r"rootkit", "name contains rootkit"),
    (r"reverse", "name contains reverse"),
]


def run() -> dict:
    """Приказује systemd socket јединице.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Systemd sockets[/bold cyan]\n")

    # Проверавамо да ли systemctl постоји.
    if not shutil.which("systemctl"):
        console.print(
            "  [yellow]systemctl not found. "
            "This system may not use systemd.[/yellow]\n"
        )
        return _empty_result()

    # Читамо socket-е.
    sockets = _read_sockets()

    if not sockets:
        console.print(
            "  [dim]No sockets found or unable to query.[/dim]\n"
        )
        return _empty_result()

    # Проналазимо сумњиве.
    suspicious = _find_suspicious(sockets)

    # Правимо резиме.
    summary = _make_summary(sockets, suspicious)

    data = {
        "sockets": sockets,
        "suspicious": suspicious,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "sockets": [],
        "suspicious": [],
        "summary": {
            "total": 0,
            "listening": 0,
            "suspicious_count": 0,
        },
    }


def _read_sockets() -> list[dict]:
    """Чита све socket јединице."""
    # Прва опција — systemctl list-sockets.
    sockets = _read_with_systemctl()

    # Fallback — читамо .socket фајлове.
    if not sockets:
        sockets = _read_socket_files()

    return sockets


def _read_with_systemctl() -> list[dict]:
    """Чита socket-е помоћу `systemctl list-sockets --all`."""
    try:
        proc = subprocess.run(
            [
                "systemctl", "list-sockets",
                "--all",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    output = proc.stdout
    if not output:
        return []

    return _parse_systemctl_output(output)


def _parse_systemctl_output(output: str) -> list[dict]:
    """Парсира излаз `systemctl list-sockets`.

    Пример:
        LISTEN                         UNIT                         ACTIVATES
        /run/dbus/system_bus_socket    dbus.socket                  dbus.service
        [::]:22                        sshd.socket                  sshd.service
    """
    sockets = []
    lines = output.splitlines()

    # Прескачемо заглавље.
    for line in lines[1:]:
        line = line.rstrip()
        if not line.strip():
            continue

        # Прескачемо footer ("X sockets listed.").
        if "sockets listed" in line.lower():
            continue

        parsed = _parse_socket_line(line)
        if parsed:
            sockets.append(parsed)

    return sockets


def _parse_socket_line(line: str) -> dict | None:
    """Парсира једну линију из `systemctl list-sockets`.

    Постоје два формата:
        1. Unix/IP socket: LISTEN UNIT ACTIVATES
        2. Netlink socket: LISTEN PORT_ID UNIT ACTIVATES
           (Port ID је број без тачке, нпр. "1", "1361")
    """
    parts = line.split()
    if len(parts) < 3:
        return None

    listen = parts[0]

    # Препознајемо netlink формат: други део је чист број,
    # а трећи део садржи ".socket".
    if (
        len(parts) >= 4
        and parts[1].isdigit()
        and ".socket" in parts[2]
    ):
        # Netlink формат — прескачемо port ID.
        unit = parts[2]
        activates = parts[3] if len(parts) > 3 else None
    else:
        # Нормалан формат.
        unit = parts[1]
        activates = parts[2] if len(parts) > 2 else None

    # Парсирамо порт ако је адреса:порт.
    port = None
    address = listen

    if ":" in listen and not listen.startswith("/"):
        # Формат: [::]:22 или 0.0.0.0:22
        addr_part, port_part = listen.rsplit(":", 1)

        # Скраћујемо IPv6 заграде.
        if addr_part.startswith("[") and addr_part.endswith("]"):
            addr_part = addr_part[1:-1]

        address = addr_part

        try:
            port = int(port_part)
        except ValueError:
            port = None

    # Име је unit без .socket суфикса.
    name = unit
    if name.endswith(".socket"):
        name = name[:-7]

    return {
        "listen": listen,
        "address": address,
        "port": port,
        "unit": unit,
        "activates": activates,
        "name": name,
        "is_active": True,
        "service": COMMON_PORTS.get(port) if port else None,
    }

def _read_socket_files() -> list[dict]:
    """Чита .socket фајлове директно (fallback)."""
    sockets = []
    seen = set()

    for base_dir in SYSTEMD_DIRS:
        if not base_dir.exists() or not base_dir.is_dir():
            continue

        try:
            entries = sorted(base_dir.iterdir())
        except (PermissionError, Exception):
            continue

        for file_path in entries:
            if not file_path.is_file():
                continue
            if not file_path.name.endswith(".socket"):
                continue

            if file_path.name in seen:
                continue
            seen.add(file_path.name)

            sockets.append({
                "listen": None,
                "address": None,
                "port": None,
                "unit": file_path.name,
                "activates": None,
                "name": file_path.name.replace(".socket", ""),
                "is_active": False,
                "service": None,
                "source_file": str(file_path),
            })

    return sockets


def _find_suspicious(sockets: list[dict]) -> list[dict]:
    """Проналази сумњиве socket јединице."""
    suspicious = []

    for sock in sockets:
        unit = sock.get("unit", "")
        listen = sock.get("listen", "") or ""
        path = sock.get("source_file", "") or ""

        combined = f"{unit} {listen} {path}"

        for pattern, description in SUSPICIOUS_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                suspicious.append({
                    "unit": unit,
                    "listen": listen,
                    "reason": description,
                    "severity": "red",
                })
                break

    return suspicious


def _make_summary(
    sockets: list[dict], suspicious: list[dict]
) -> dict:
    """Прави резиме."""
    listening = [s for s in sockets if s.get("is_active")]

    return {
        "total": len(sockets),
        "listening": len(listening),
        "suspicious_count": len(suspicious),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    sockets = data.get("sockets", [])
    suspicious = data.get("suspicious", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total sockets:[/bold]     {summary.get('total', 0)}"
    )
    console.print(
        f"  [green]Active:[/green]          {summary.get('listening', 0)}"
    )

    if suspicious:
        console.print(
            f"  [bold red]Suspicious:[/bold red]      "
            f"{summary.get('suspicious_count', 0)}"
        )

    console.print()

    # Сумњиви прво.
    if suspicious:
        console.print(
            f"[bold red]Suspicious findings ({len(suspicious)}):[/bold red]\n"
        )
        for item in suspicious:
            console.print(
                f"  [bold red]●[/bold red] "
                f"[yellow]{item['unit']}[/yellow]  "
                f"[dim]({item['reason']})[/dim]"
            )
            if item.get("listen"):
                console.print(
                    f"    Listen: {item['listen']}"
                )
        console.print()

    if not sockets:
        console.print(
            "  [dim]No socket units found.[/dim]\n"
        )
        return

    # Сортирамо — са портом прво, па по порту.
    def sort_key(s):
        port = s.get("port")
        if port is None:
            return (1, 0, s.get("unit", ""))
        return (0, port, "")

    sorted_sockets = sorted(sockets, key=sort_key)

    console.print("[bold]Sockets:[/bold]\n")
    console.print(
        f"  {'LISTEN':40s}  {'UNIT':30s}  ACTIVATES"
    )

    for sock in sorted_sockets:
        _print_socket(sock)

    console.print()


def _print_socket(sock: dict) -> None:
    """Приказује један socket."""
    listen = sock.get("listen") or "(no listen)"
    unit = sock.get("unit", "?")
    activates = sock.get("activates") or "?"
    port = sock.get("port")
    service = sock.get("service")
    is_active = sock.get("is_active", False)

    # Боја — црвено ако слуша на свим адресама.
    address = sock.get("address") or ""

    if address in ("0.0.0.0", "::", "*"):
        color = "bold red"
    elif is_active:
        color = "white"
    else:
        color = "dim"

    # Скраћујемо.
    if len(listen) > 38:
        listen = listen[:35] + "..."

    if len(unit) > 28:
        unit = unit[:25] + "..."

    if len(activates) > 28:
        activates = activates[:25] + "..."

    # Додајемо сервис ако знамо.
    service_display = ""
    if service:
        service_display = f"  [dim]({service})[/dim]"

    console.print(
        f"  [{color}]{listen:40s}[/{color}]  "
        f"[bold]{unit:30s}[/bold]  "
        f"[dim]{activates}[/dim]{service_display}"
    )