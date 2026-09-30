# Модул за приказ systemd сервиса.
# Приказује све сервисе (активне и неактивне) са стањем.
# Systemd је главни init систем на већини модерних Linux
# дистрибуција. Сервиси могу бити покренути, заустављени,
# или у стању грешке.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми са systemd unit фајловима.
SYSTEMD_DIRS = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
]

# Сервиси који су познато безбедни (не означавамо их).
KNOWN_SAFE_SERVICES = {
    "systemd-journald",
    "systemd-udevd",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-logind",
    "dbus",
    "cron",
    "crond",
    "ssh",
    "sshd",
    "NetworkManager",
    "networking",
    "rsyslog",
    "systemd-networkd",
}


def run() -> dict:
    """Приказује systemd сервисе.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Systemd services[/bold cyan]\n")

    # Проверавамо да ли systemd постоји.
    if not shutil.which("systemctl"):
        console.print(
            "  [yellow]systemctl not found. "
            "This system may not use systemd.[/yellow]\n"
        )
        return _empty_result()

    # Читамо све сервисе.
    services = _read_services()

    if not services:
        console.print(
            "  [dim]No services found or unable to query.[/dim]\n"
        )
        return _empty_result()

    # Раздвајамо по стању.
    running = [s for s in services if s["active_state"] == "active"]
    failed = [s for s in services if s["active_state"] == "failed"]
    inactive = [s for s in services if s["active_state"] == "inactive"]

    # Тражимо сумњиве.
    suspicious = _find_suspicious(services)

    data = {
        "services": services,
        "suspicious": suspicious,
        "summary": {
            "total": len(services),
            "running": len(running),
            "failed": len(failed),
            "inactive": len(inactive),
            "suspicious_count": len(suspicious),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "services": [],
        "suspicious": [],
        "summary": {
            "total": 0,
            "running": 0,
            "failed": 0,
            "inactive": 0,
            "suspicious_count": 0,
        },
    }


def _read_services() -> list[dict]:
    """Чита све systemd сервисе.

    Користимо `systemctl list-units --type=service --all` за
    листу и `systemctl show` за детаље (по потреби).
    """
    try:
        proc = subprocess.run(
            [
                "systemctl", "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--no-legend",
                "--plain",
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

    services = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        # Формат:
        # UNIT LOAD ACTIVE SUB DESCRIPTION
        unit = parts[0]
        load = parts[1]
        active = parts[2]
        sub = parts[3]
        description = " ".join(parts[4:]) if len(parts) > 4 else ""

        # Име без .service суфикса.
        name = unit
        if name.endswith(".service"):
            name = name[:-8]

        services.append({
            "name": name,
            "unit": unit,
            "load": load,
            "active_state": active,
            "sub_state": sub,
            "description": description,
            "is_known_safe": name in KNOWN_SAFE_SERVICES,
        })

    return services


def _find_suspicious(services: list[dict]) -> list[dict]:
    """Проналази сумњиве сервисе.

    Сумњиви су они који су:
        - failed (пукли)
        - running, а нису у листи познатих
        - имају необична имена
    """
    suspicious = []

    # Имена која су често легитимна али могу бити и маскирани малвер.
    suspicious_name_patterns = (
        "backdoor",
        "rootkit",
        "miner",
        "xmrig",
        "kdevtmpfsi",
        "kinsing",
        "sysupdate",
        "networkservice",
        "cryptonight",
        "cpuminer",
    )

    for svc in services:
        name = svc["name"]
        name_lower = name.lower()
        active = svc["active_state"]
        sub = svc["sub_state"]

        # Пукли сервиси.
        if active == "failed":
            suspicious.append({
                "name": name,
                "reason": "service failed",
                "severity": "yellow",
            })
            continue

        # Имена која личе на малвер.
        for pattern in suspicious_name_patterns:
            if pattern in name_lower:
                suspicious.append({
                    "name": name,
                    "reason": f"name matches suspicious pattern: {pattern}",
                    "severity": "red",
                })
                break

    return suspicious


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    services = data.get("services", [])
    suspicious = data.get("suspicious", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total services:[/bold]   {summary.get('total', 0)}"
    )
    console.print(
        f"  [green]Running:[/green]           {summary.get('running', 0)}"
    )
    console.print(
        f"  [red]Failed:[/red]            {summary.get('failed', 0)}"
    )
    console.print(
        f"  [dim]Inactive:[/dim]          {summary.get('inactive', 0)}"
    )

    if suspicious:
        console.print(
            f"  [bold red]Suspicious:[/bold red]        "
            f"{summary.get('suspicious_count', 0)}"
        )

    console.print()

    # Сумњиви прво.
    if suspicious:
        console.print(
            f"[bold red]Suspicious findings ({len(suspicious)}):[/bold red]\n"
        )
        for item in suspicious:
            severity = item.get("severity", "yellow")
            console.print(
                f"  [{severity}]● {item['name']}[/{severity}]  "
                f"[dim]({item['reason']})[/dim]"
            )
        console.print()

    # Приказујемо failed сервисе.
    failed = [s for s in services if s["active_state"] == "failed"]
    if failed:
        console.print(
            f"[bold red]Failed services ({len(failed)}):[/bold red]\n"
        )
        for svc in failed:
            console.print(f"  [red]{svc['name']}[/red]  "
                          f"[dim]{svc['description']}[/dim]")
        console.print()

    # Приказујемо активне сервисе (првих 25).
    running = [s for s in services if s["active_state"] == "active"]
    if running:
        console.print(
            f"[bold]Running services ({len(running)}):[/bold]\n"
        )

        limit = 25
        for svc in running[:limit]:
            _print_service(svc)

        if len(running) > limit:
            console.print(
                f"  [dim]... and {len(running) - limit} more[/dim]"
            )
        console.print()


def _print_service(svc: dict) -> None:
    """Приказује један сервис."""
    name = svc["name"]
    sub = svc["sub_state"]
    description = svc["description"]

    # Скраћујемо опис.
    if len(description) > 60:
        description = description[:57] + "..."

    # Боја за sub_state.
    if sub == "running":
        color = "green"
    elif sub == "exited":
        color = "dim"
    else:
        color = "yellow"

    console.print(
        f"  [{color}]{sub:10s}[/{color}]  "
        f"[bold]{name:35s}[/bold]  "
        f"[dim]{description}[/dim]"
    )