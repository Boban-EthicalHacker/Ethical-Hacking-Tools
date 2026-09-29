# Модул за проналажење фајлова и директоријума које сви могу мењати.
# World-writable значи да свако (не само власник) може да пише у њих.
# Ако је world-writable фајл на важној локацији (нпр. /etc/),
# неко може да га измени и покрене као root. Ово је чест пут
# за privilege escalation.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import stat
from pathlib import Path

from rich.console import Console

console = Console()

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

# Путање где је world-writable нормално (не сумњиво).
# Ово су стандардни привремени директоријуми.
NORMAL_WORLD_WRITABLE = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/lock/",
    "/var/lock/",
    "/run/user/",
    "/var/spool/",
    "/var/mail/",
    "/var/crash/",
    # Кориснички home директоријуми — world-writable је
    # уобичајено у неким конфигурацијама и није безбедносни
    # проблем сам по себи (јер је то корисников простор).
    "/home/",
    "/root/",
)

# Путање где world-writable је високо ризично.
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
)

# Максимална дубина претраге.
MAX_DEPTH = 8


def run() -> dict:
    """Проналази world-writable фајлове и директоријуме.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]World-writable files[/bold cyan]\n")

    console.print(
        "[dim]Searching for files and directories writable by everyone. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо све world-writable ставке.
    items = _find_world_writable()

    # Класификујемо их.
    normal, high_risk, unknown = _classify_items(items)

    data = {
        "all_items": items,
        "normal": normal,
        "high_risk": high_risk,
        "unknown": unknown,
        "summary": {
            "total": len(items),
            "normal": len(normal),
            "high_risk": len(high_risk),
            "unknown": len(unknown),
        },
    }

    _print_data(data)

    return data


def _find_world_writable() -> list[dict]:
    """Претражује систем за world-writable фајловима и директоријумима."""
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

        # Проверавамо директоријум root.
        if root != "/":
            _check_world_writable(root, items, is_dir=True)

        # Проверавамо фајлове у директоријуму.
        for file_name in files:
            path = os.path.join(root, file_name)
            _check_world_writable(path, items, is_dir=False)

    return items


def _check_world_writable(path: str, items: list[dict], is_dir: bool) -> None:
    """Проверава да ли је фајл/директоријум world-writable."""
    try:
        st = os.lstat(path)
    except (OSError, PermissionError):
        return

    # Прескачемо симлинкове.
    if stat.S_ISLNK(st.st_mode):
        return

    # Проверавамо other-write бит.
    if not (st.st_mode & stat.S_IWOTH):
        return

    # Проверавамо sticky bit (за директоријуме).
    # Ако директоријум има sticky bit, само власник може да
    # брише своје фајлове (нпр. /tmp). То је безбедније.
    has_sticky = bool(st.st_mode & stat.S_ISVTX)

    items.append({
        "path": path,
        "is_dir": is_dir,
        "size_bytes": st.st_size,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.filemode(st.st_mode),
        "has_sticky_bit": has_sticky,
    })


def _classify_items(
    items: list[dict]
) -> tuple[list[dict], list[dict], list[dict]]:
    """Класификује ставке на нормалне, високо ризичне и непознате."""
    normal = []
    high_risk = []
    unknown = []

    for item in items:
        path = item["path"] + ("/" if item["is_dir"] else "")

        # Проверавамо да ли је на нормалној локацији.
        if any(path.startswith(p) for p in NORMAL_WORLD_WRITABLE):
            normal.append(item)
            continue

        # Проверавамо да ли је на високо ризичној локацији.
        if any(path.startswith(p) for p in HIGH_RISK_PATHS):
            high_risk.append(item)
            continue

        # Остало — непознато, вреди погледати.
        unknown.append(item)

    return normal, high_risk, unknown


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    high_risk = data.get("high_risk", [])
    unknown = data.get("unknown", [])
    normal = data.get("normal", [])

    console.print(f"[bold]Total world-writable:[/bold]  {summary.get('total', 0)}")
    console.print(
        f"  [green]Normal locations:[/green]     {summary.get('normal', 0)}"
    )
    console.print(
        f"  [yellow]Unknown locations:[/yellow]   {summary.get('unknown', 0)}"
    )
    console.print(
        f"  [bold red]High risk:[/bold red]           {summary.get('high_risk', 0)}"
    )
    console.print()

    # Високо ризичне.
    if high_risk:
        console.print(
            f"[bold red]High risk ({len(high_risk)}):[/bold red]\n"
        )
        for item in sorted(high_risk, key=lambda x: x["path"]):
            _print_item(item, "red")
        console.print()

    # Непознате.
    if unknown:
        console.print(
            f"[bold yellow]Unknown ({len(unknown)}):[/bold yellow]\n"
        )
        for item in sorted(unknown, key=lambda x: x["path"])[:30]:
            _print_item(item, "yellow")

        if len(unknown) > 30:
            console.print(
                f"  [dim]... and {len(unknown) - 30} more[/dim]"
            )
        console.print()

    # Нормалне — само кратак преглед.
    if normal:
        console.print(
            f"[bold]Normal locations ({len(normal)}):[/bold]\n"
        )
        for item in sorted(normal, key=lambda x: x["path"])[:10]:
            console.print(f"  [dim]{item['path']}[/dim]")

        if len(normal) > 10:
            console.print(
                f"  [dim]... and {len(normal) - 10} more[/dim]"
            )
        console.print()


def _print_item(item: dict, color: str) -> None:
    """Приказује једну ставку."""
    path = item["path"]
    is_dir = item["is_dir"]
    mode = item["mode"]
    has_sticky = item["has_sticky_bit"]

    # Ознака за директоријум.
    type_marker = "[dir]" if is_dir else "[file]"
    sticky_marker = ""
    if is_dir and has_sticky:
        sticky_marker = " [dim](sticky)[/dim]"

    console.print(
        f"  [{color}]{path}[/{color}]  "
        f"[dim]{type_marker} {mode}[/dim]{sticky_marker}"
    )