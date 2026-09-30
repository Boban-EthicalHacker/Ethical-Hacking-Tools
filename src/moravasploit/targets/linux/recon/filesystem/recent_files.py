# Модул за проналажење недавно измењених фајлова.
# Приказује фајлове који су измењени у последњих N дана.
# Корисно за откривање недавних промена на систему —
# након напада, фајлови су често свеже измењени.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import stat
import time
from pathlib import Path

from rich.console import Console

console = Console()

# Колико дана уназад гледамо (подразумевано).
DEFAULT_DAYS = 7

# Директоријуми које прескачемо при претрази.
SKIP_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/lib/containers",
    "/mnt",
    "/media",
    "/var/lib/libvirt",
}

# Локације које су безбедносно високо ризичне.
HIGH_RISK_PATHS = (
    "/etc/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/boot/",
    "/lib/",
    "/usr/lib/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/var/www/",
)

# Директоријуми где су недавне измене нормалне (cache, log, tmp).
NORMAL_PATHS = (
    "/var/cache/",
    "/var/log/",
    "/var/lib/",
    "/home/",
    "/root/",
    "/tmp/",
    "/var/tmp/",
    "/run/",
    "/var/spool/",
)

# Максимална дубина претраге.
MAX_DEPTH = 8

# Максималан број резултата да не буде превише.
MAX_RESULTS = 500


def run() -> dict:
    """Проналази недавно измењене фајлове.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Recently modified files[/bold cyan]\n")

    # Питамо корисника колико дана уназад.
    days = _ask_days()

    cutoff = time.time() - (days * 86400)

    console.print(
        f"[dim]Searching for files modified in the last {days} days. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо недавно измењене фајлове.
    items = _find_recent_files(cutoff)

    # Класификујемо их.
    high_risk, normal = _classify_items(items)

    data = {
        "days": days,
        "cutoff_timestamp": cutoff,
        "high_risk": high_risk,
        "normal": normal,
        "summary": {
            "total": len(items),
            "high_risk": len(high_risk),
            "normal": len(normal),
            "truncated": len(items) >= MAX_RESULTS,
        },
    }

    _print_data(data)

    return data


def _ask_days() -> int:
    """Пита корисника колико дана уназад да гледа."""
    # Покушавамо са input-ом, ако не успемо, користимо подразумевано.
    try:
        from rich.prompt import Prompt

        result = Prompt.ask(
            "Days to look back",
            default=str(DEFAULT_DAYS),
        )

        days = int(result)
        if days < 1:
            days = 1
        if days > 365:
            days = 365

        return days

    except (ValueError, KeyboardInterrupt, EOFError):
        return DEFAULT_DAYS
    except Exception:
        return DEFAULT_DAYS


def _find_recent_files(cutoff: float) -> list[dict]:
    """Претражује систем за фајловима измењеним после cutoff."""
    items = []

    for root, dirs, files in os.walk("/", topdown=True):
        # Прескачемо SKIP_DIRS.
        dirs[:] = [
            d for d in dirs
            if os.path.join(root, d) not in SKIP_DIRS
            and not os.path.join(root, d).startswith(
                tuple(f"{s}/" for s in SKIP_DIRS)
            )
        ]

        # Проверавамо дубину.
        depth = root.count(os.sep)
        if depth > MAX_DEPTH:
            dirs[:] = []
            continue

        # Прескачемо ако немамо дозволу.
        if not os.access(root, os.R_OK | os.X_OK):
            continue

        for file_name in files:
            path = os.path.join(root, file_name)

            try:
                st = os.lstat(path)
            except (OSError, PermissionError):
                continue

            # Прескачемо симлинкове.
            if stat.S_ISLNK(st.st_mode):
                continue

            # Прескачемо ако је старији од cutoff.
            if st.st_mtime < cutoff:
                continue

            items.append({
                "path": path,
                "size_bytes": st.st_size,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mode": stat.filemode(st.st_mode),
                "mtime": st.st_mtime,
                "mtime_iso": time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(st.st_mtime),
                ),
            })

            # Ограничавамо број резултата.
            if len(items) >= MAX_RESULTS:
                return items

    return items


def _classify_items(
    items: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Класификује ставке на високо ризичне и нормалне.

    Приоритет имају HIGH_RISK локације. Ако је пут у обе листе
    (нпр. /tmp/ је и у HIGH_RISK и у NORMAL), третирамо га
    као нормалан јер су недавне измене у /tmp уобичајене.
    """
    high_risk = []
    normal = []

    for item in items:
        path = item["path"]

        # Ако је у нормалној локацији — нормално.
        if any(path.startswith(p) for p in NORMAL_PATHS):
            normal.append(item)
            continue

        # Ако је у високо ризичној локацији — високо ризично.
        if any(path.startswith(p) for p in HIGH_RISK_PATHS):
            high_risk.append(item)
            continue

        # Остало — нормално (није у ризичној локацији).
        normal.append(item)

    return high_risk, normal


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    high_risk = data.get("high_risk", [])
    normal = data.get("normal", [])
    days = data.get("days", DEFAULT_DAYS)

    console.print(
        f"[bold]Days back:[/bold]           {days}"
    )
    console.print(
        f"[bold]Total recent files:[/bold]  {summary.get('total', 0)}"
    )
    console.print(
        f"  [yellow]High risk:[/yellow]           "
        f"{summary.get('high_risk', 0)}"
    )
    console.print(
        f"  [green]Normal locations:[/green]     "
        f"{summary.get('normal', 0)}"
    )

    if summary.get("truncated"):
        console.print(
            f"  [dim](results truncated to {MAX_RESULTS})[/dim]"
        )

    console.print()

    # Високо ризичне.
    if high_risk:
        console.print(
            f"[bold red]High risk ({len(high_risk)}):[/bold red]\n"
        )
        # Сортирамо по времену — најновији први.
        for item in sorted(high_risk, key=lambda x: x["mtime"], reverse=True)[:50]:
            _print_item(item, "red")

        if len(high_risk) > 50:
            console.print(
                f"  [dim]... and {len(high_risk) - 50} more[/dim]"
            )
        console.print()

    # Нормалне — само кратак преглед.
    if normal:
        console.print(
            f"[bold]Normal locations ({len(normal)}):[/bold]\n"
        )
        console.print(
            "  [dim]Recent files in /home, /var/cache, /var/log and "
            "other standard locations are not shown.[/dim]"
        )
        console.print()


def _print_item(item: dict, color: str) -> None:
    """Приказује једну ставку."""
    path = item["path"]
    mtime_iso = item.get("mtime_iso", "")
    size = item.get("size_bytes", 0)

    size_str = _format_size(size)

    console.print(
        f"  [{color}]{path}[/{color}]"
    )
    console.print(
        f"    [dim]{mtime_iso}  {size_str}[/dim]"
    )


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"