# Модул за приказ ARP кеша (Address Resolution Protocol).
# ARP кеш садржи мапинге IP адреса на MAC адресе у локалној мрежи.
# Ако видимо непознату MAC адресу за gateway, то може бити
# ARP spoofing (MITM напад). Такође видимо све уређаје који
# су недавно комуницирали са нашим системом.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Путања до ARP табеле у /proc.
PROC_NET_ARP = Path("/proc/net/arp")

# Путања до рута (за препознавање gateway-а).
PROC_NET_ROUTE = Path("/proc/net/route")


def run() -> dict:
    """Приказује ARP табелу.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]ARP table[/bold cyan]\n")

    # Препознајемо gateway.
    gateway = _get_gateway()

    # Читамо ARP табелу.
    entries = _read_arp_table()

    # Означавамо gateway и тражимо сумњиве.
    suspicious = _analyze_entries(entries, gateway)

    data = {
        "gateway": gateway,
        "entries": entries,
        "suspicious": suspicious,
        "summary": {
            "total": len(entries),
            "suspicious_count": len(suspicious),
            "gateway_ip": gateway.get("ip") if gateway else None,
            "gateway_mac": gateway.get("mac") if gateway else None,
        },
    }

    _print_data(data)

    return data


def _get_gateway() -> dict | None:
    """Проналази default gateway из /proc/net/route.

    Враћа речник са IP и MAC адресом gateway-а, или None.
    """
    if not PROC_NET_ROUTE.exists():
        return None

    try:
        content = PROC_NET_ROUTE.read_text(encoding="utf-8")
    except Exception:
        return None

    lines = content.splitlines()

    # Прва линија је заглавље.
    if len(lines) < 2:
        return None

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue

        # Destination "00000000" значи default route.
        if parts[1] != "00000000":
            continue

        # Gateway је у hex формату (little-endian).
        gateway_hex = parts[2]
        try:
            gateway_ip = _hex_to_ip(gateway_hex)
            return {"ip": gateway_ip, "mac": None}
        except ValueError:
            continue

    return None


def _hex_to_ip(hex_str: str) -> str:
    """Конвертује little-endian hex у IP адресу."""
    if len(hex_str) != 8:
        raise ValueError("invalid hex")

    bytes_le = bytes.fromhex(hex_str)
    bytes_be = bytes_le[::-1]

    return ".".join(str(b) for b in bytes_be)


def _read_arp_table() -> list[dict]:
    """Чита ARP табелу.

    Прво покушава са `ip neigh`, затим са /proc/net/arp.
    """
    # Прва опција — ip neigh (новији, поузданији).
    if shutil.which("ip"):
        entries = _read_with_ip_neigh()
        if entries:
            return entries

    # Друга опција — /proc/net/arp.
    return _read_proc_arp()


def _read_with_ip_neigh() -> list[dict]:
    """Чита ARP табелу помоћу `ip neigh`."""
    try:
        proc = subprocess.run(
            ["ip", "neigh"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    output = proc.stdout
    if not output:
        return []

    entries = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        parsed = _parse_ip_neigh_line(line)
        if parsed:
            entries.append(parsed)

    return entries


def _parse_ip_neigh_line(line: str) -> dict | None:
    """Парсира једну линију из `ip neigh`.

    Пример:
        10.206.49.81 dev wlan0 lladdr c4:03:a8:29:bc:38 REACHABLE
    """
    parts = line.split()
    if len(parts) < 1:
        return None

    ip = parts[0]
    device = None
    mac = None
    state = None

    i = 1
    while i < len(parts):
        if parts[i] == "dev" and i + 1 < len(parts):
            device = parts[i + 1]
            i += 2
        elif parts[i] == "lladdr" and i + 1 < len(parts):
            mac = parts[i + 1]
            i += 2
        elif parts[i].isupper():
            state = parts[i]
            i += 1
        else:
            i += 1

    if not ip:
        return None

    return {
        "ip": ip,
        "mac": mac,
        "device": device,
        "state": state,
    }


def _read_proc_arp() -> list[dict]:
    """Чита ARP табелу из /proc/net/arp (fallback)."""
    if not PROC_NET_ARP.exists():
        return []

    try:
        content = PROC_NET_ARP.read_text(encoding="utf-8")
    except Exception:
        return []

    lines = content.splitlines()

    # Прва линија је заглавље.
    if len(lines) < 2:
        return []

    entries = []

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue

        # Формат: IP HW_type Flags HW_address Mask Device
        ip = parts[0]
        mac = parts[3]
        device = parts[5]

        # Прескачемо невалидне MAC адресе.
        if mac == "00:00:00:00:00:00":
            continue

        entries.append({
            "ip": ip,
            "mac": mac,
            "device": device,
            "state": None,
        })

    return entries


def _analyze_entries(
    entries: list[dict], gateway: dict | None
) -> list[dict]:
    """Анализира ARP уносе и проналази сумњиве."""
    suspicious = []

    # Прво означавамо gateway.
    if gateway:
        for entry in entries:
            if entry["ip"] == gateway["ip"]:
                entry["is_gateway"] = True
                gateway["mac"] = entry["mac"]
            else:
                entry["is_gateway"] = False
    else:
        for entry in entries:
            entry["is_gateway"] = False

    # Тражимо дупликате IP са различитим MAC.
    ip_to_macs: dict[str, set[str]] = {}

    for entry in entries:
        ip = entry.get("ip", "")
        mac = entry.get("mac", "")

        if not ip or not mac:
            continue

        if ip not in ip_to_macs:
            ip_to_macs[ip] = set()
        ip_to_macs[ip].add(mac)

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            suspicious.append({
                "type": "duplicate_ip",
                "ip": ip,
                "macs": list(macs),
                "description": f"IP {ip} has multiple MAC addresses",
            })

    # Тражимо incomplete entries (без MAC).
    for entry in entries:
        if not entry.get("mac"):
            suspicious.append({
                "type": "incomplete",
                "ip": entry.get("ip", "?"),
                "description": "Incomplete ARP entry (no MAC)",
            })

    return suspicious


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    entries = data.get("entries", [])
    suspicious = data.get("suspicious", [])
    summary = data.get("summary", {})
    gateway = data.get("gateway")

    console.print(
        f"[bold]Total entries:[/bold]     {summary.get('total', 0)}"
    )

    if gateway:
        console.print(
            f"[bold]Gateway:[/bold]          "
            f"{gateway.get('ip')}  "
            f"[dim]({gateway.get('mac') or 'unknown'})[/dim]"
        )

    if suspicious:
        console.print(
            f"[bold]Suspicious:[/bold]       "
            f"[bold red]{len(suspicious)}[/bold red]"
        )

    console.print()

    if not entries:
        console.print("  [dim]No ARP entries found.[/dim]\n")
        return

    # Сумњиви прво.
    if suspicious:
        console.print(
            f"[bold red]Suspicious findings ({len(suspicious)}):[/bold red]\n"
        )
        for item in suspicious:
            console.print(
                f"  [bold red]●[/bold red] "
                f"[yellow]{item['type']}[/yellow]  "
                f"{item['description']}"
            )
        console.print()

    # Приказујемо све уносе.
    console.print(f"[bold]Entries ({len(entries)}):[/bold]\n")
    console.print(
        f"  {'IP':20s}  {'MAC':20s}  {'DEVICE':10s}  STATE"
    )

    for entry in sorted(entries, key=lambda x: _ip_sort_key(x["ip"])):
        _print_entry(entry)

    console.print()


def _print_entry(entry: dict) -> None:
    """Приказује један ARP унос."""
    ip = entry.get("ip", "?")
    mac = entry.get("mac") or "?"
    device = entry.get("device") or "-"
    state = entry.get("state") or "-"
    is_gateway = entry.get("is_gateway", False)

    # Боја — зелено за gateway, бело за остале.
    if is_gateway:
        color = "bold green"
        marker = " [dim](gateway)[/dim]"
    elif entry.get("state") == "FAILED":
        color = "red"
        marker = ""
    elif not entry.get("mac"):
        color = "yellow"
        marker = ""
    else:
        color = "white"
        marker = ""

    # Скраћујемо IPv6 адресе.
    if len(ip) > 18:
        ip = ip[:15] + "..."

    # Скраћујемо state.
    if len(state) > 12:
        state = state[:12]

    console.print(
        f"  [{color}]{ip:20s}[/{color}]  "
        f"{mac:20s}  "
        f"{device:10s}  "
        f"{state}{marker}"
    )


def _ip_sort_key(ip: str) -> tuple:
    """Сортира IP адресе нумерички, не лексикографски."""
    parts = ip.split(".")

    if len(parts) == 4:
        try:
            return tuple(int(p) for p in parts)
        except ValueError:
            pass

    # IPv6 или невалидан — сортирамо као стринг.
    return (999, 999, 999, ip)