# Модул за приказ мрежних информација на систему.
# Приказује интерфејсе, IP адресе, MAC адресе, руте и DNS.
# Користи стандардне Linux команде (ip, cat) уместо
# Python библиотека, јер су тако подаци тачнији.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
RESOLV_CONF = Path("/etc/resolv.conf")


def run() -> dict:
    """Приказује мрежне информације.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Network information[/bold cyan]\n")

    data = {
        "interfaces": _get_interfaces(),
        "routes": _get_routes(),
        "dns": _get_dns(),
    }

    _print_data(data)

    return data


def _run_command(cmd: list[str]) -> str | None:
    """Покреће команду и враћа излаз."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None


def _get_interfaces() -> list[dict]:
    """Чита мрежне интерфејсе помоћу `ip -j addr`."""
    # -j значи JSON излаз, лакше је парсирати.
    output = _run_command(["ip", "-j", "addr"])
    if not output:
        return []

    try:
        import json
        interfaces = json.loads(output)
    except Exception:
        return []

    result = []

    for iface in interfaces:
        iface_name = iface.get("ifname", "?")
        iface_state = iface.get("operstate", "unknown")
        mac = iface.get("address", "")

        # Прескачемо loopback? Не — вреди га видети.
        # Али прескачемо "down" интерфејсе који немају адресу.
        addrs = iface.get("addr_info", [])

        ipv4 = []
        ipv6 = []

        for addr in addrs:
            family = addr.get("family")
            ip = addr.get("local", "")
            prefix = addr.get("prefixlen", "")

            if family == "inet":
                ipv4.append(f"{ip}/{prefix}")
            elif family == "inet6":
                ipv6.append(f"{ip}/{prefix}")

        result.append({
            "name": iface_name,
            "state": iface_state,
            "mac": mac,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mtu": iface.get("mtu"),
        })

    return result


def _get_routes() -> list[dict]:
    """Чита руте помоћу `ip -j route`."""
    output = _run_command(["ip", "-j", "route"])
    if not output:
        return []

    try:
        import json
        routes = json.loads(output)
    except Exception:
        return []

    result = []

    for route in routes:
        entry = {
            "dst": route.get("dst", "default"),
            "gateway": route.get("gateway"),
            "device": route.get("dev"),
            "protocol": route.get("protocol"),
        }
        result.append(entry)

    return result


def _get_dns() -> dict:
    """Чита DNS конфигурацију из /etc/resolv.conf."""
    result = {
        "nameservers": [],
        "search": [],
        "options": [],
    }

    if not RESOLV_CONF.exists():
        return result

    try:
        content = RESOLV_CONF.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if not parts:
            continue

        key = parts[0]

        if key == "nameserver" and len(parts) > 1:
            result["nameservers"].append(parts[1])
        elif key == "search":
            result["search"].extend(parts[1:])
        elif key == "options":
            result["options"].extend(parts[1:])

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    interfaces = data.get("interfaces", [])
    routes = data.get("routes", [])
    dns = data.get("dns", {})

    # Интерфејси.
    if interfaces:
        console.print(f"[bold]Interfaces ({len(interfaces)}):[/bold]\n")
        for iface in interfaces:
            _print_interface(iface)
    else:
        console.print("[bold]Interfaces:[/bold]  [dim]none found[/dim]\n")

    # Руте.
    if routes:
        console.print(f"[bold]Routes ({len(routes)}):[/bold]\n")

        # Приказујемо default route прво.
        default_routes = [r for r in routes if r["dst"] == "default"]
        other_routes = [r for r in routes if r["dst"] != "default"]

        for route in default_routes:
            _print_route(route, highlight=True)

        for route in other_routes[:10]:
            _print_route(route)

        if len(other_routes) > 10:
            console.print(
                f"  [dim]... and {len(other_routes) - 10} more[/dim]"
            )

        console.print()

    # DNS.
    if dns.get("nameservers") or dns.get("search"):
        console.print("[bold]DNS:[/bold]\n")

        for ns in dns.get("nameservers", []):
            console.print(f"  Nameserver:  [cyan]{ns}[/cyan]")

        if dns.get("search"):
            console.print(
                f"  Search:      [dim]{', '.join(dns['search'])}[/dim]"
            )

        if dns.get("options"):
            console.print(
                f"  Options:     [dim]{', '.join(dns['options'])}[/dim]"
            )

        console.print()


def _print_interface(iface: dict) -> None:
    """Приказује један интерфејс."""
    name = iface.get("name", "?")
    state = iface.get("state", "unknown")
    mac = iface.get("mac", "")
    mtu = iface.get("mtu")

    # Боја стања.
    if state == "UP":
        state_color = "green"
    elif state == "DOWN":
        state_color = "dim"
    else:
        state_color = "yellow"

    console.print(
        f"  [bold]{name}[/bold]  "
        f"[{state_color}]{state}[/{state_color}]"
    )

    if mac:
        console.print(f"    MAC:   [dim]{mac}[/dim]")

    if mtu:
        console.print(f"    MTU:   [dim]{mtu}[/dim]")

    for ip in iface.get("ipv4", []):
        console.print(f"    IPv4:  [cyan]{ip}[/cyan]")

    for ip in iface.get("ipv6", []):
        # Скраћујемо IPv6 адресе.
        if len(ip) > 40:
            ip = ip[:37] + "..."
        console.print(f"    IPv6:  [dim]{ip}[/dim]")

    console.print()


def _print_route(route: dict, highlight: bool = False) -> None:
    """Приказује једну руту."""
    dst = route.get("dst", "?")
    gateway = route.get("gateway")
    device = route.get("device")

    if highlight:
        color = "bold green"
    else:
        color = "white"

    line = f"  [{color}]{dst:20s}[/{color}]"

    if gateway:
        line += f"  via {gateway}"

    if device:
        line += f"  dev {device}"

    console.print(line)