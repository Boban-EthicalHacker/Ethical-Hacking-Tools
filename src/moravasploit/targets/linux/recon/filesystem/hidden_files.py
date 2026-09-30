# Модул за проналажење скривених фајлова на необичним локацијама.
# Скривени фајлови почињу са тачком (.). У home директоријумима
# и /etc/ су нормални, али у /tmp, /var/www, /usr/bin су сумњиви.
# Нападачи често остављају backdoor фајлове као скривене.
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

# Путање где су скривени фајлови НОРМАЛНИ.
# Ту спадају home директоријуми, /etc, /var, конфигурације.
NORMAL_LOCATIONS = (
    "/home/",
    "/root/",
    "/etc/",
    "/var/lib/",
    "/var/cache/",
    "/var/log/",
    "/usr/share/",
    "/usr/lib/",
    "/usr/local/share/",
    "/opt/",
)

# Путање где су скривени фајлови ВИСОКО РИЗИЧНИ.
HIGH_RISK_LOCATIONS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/var/www/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/boot/",
)

# Имена скривених фајлова која су често легитимна.
KNOWN_HIDDEN_NAMES = {
    ".git",
    ".gitignore",
    ".gitkeep",
    ".github",
    ".gitlab-ci.yml",
    ".svn",
    ".hg",
    ".hgignore",
    ".bzr",
    ".dockerignore",
    ".editorconfig",
    ".env",
    ".env.example",
    ".eslintrc",
    ".eslintignore",
    ".prettierrc",
    ".stylelintrc",
    ".npmrc",
    ".nvmrc",
    ".yarnrc",
    ".bashrc",
    ".bash_profile",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".inputrc",
    ".vimrc",
    ".viminfo",
    ".ssh",
    ".gnupg",
    ".config",
    ".cache",
    ".local",
    ".mozilla",
    ".thunderbird",
    ".xinitrc",
    ".Xauthority",
    ".Xresources",
    ".ICEauthority",
    ".dbus",
    ".pki",
    ".cache",
    ".ICE-unix",
    ".X11-unix",
    ".font-unix",
    ".XIM-unix",
    ".Test-unix",
    ".tmp",
    ".keep",
    ".placeholder",
    ".DS_Store",
    ".localized",
    ".htaccess",
    ".htpasswd",
    ".user.ini",
    ".updated",
    ".X0-lock",
}

# Максимална дубина претраге.
MAX_DEPTH = 8


def run() -> dict:
    """Проналази скривене фајлове на необичним локацијама.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Hidden files[/bold cyan]\n")

    console.print(
        "[dim]Searching for hidden files in unusual locations. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо све скривене фајлове.
    items = _find_hidden_files()

    # Класификујемо их.
    high_risk, unknown, normal = _classify_items(items)

    data = {
        "all_items": items,
        "high_risk": high_risk,
        "unknown": unknown,
        "normal": normal,
        "summary": {
            "total": len(items),
            "high_risk": len(high_risk),
            "unknown": len(unknown),
            "normal": len(normal),
        },
    }

    _print_data(data)

    return data


def _find_hidden_files() -> list[dict]:
    """Претражује систем за скривеним фајловима."""
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

        # Проверавамо скривене директоријуме.
        for d in list(dirs):
            if d.startswith("."):
                path = os.path.join(root, d)
                _check_item(path, items, is_dir=True)

        # Проверавамо скривене фајлове.
        for file_name in files:
            if file_name.startswith("."):
                path = os.path.join(root, file_name)
                _check_item(path, items, is_dir=False)

    return items


def _check_item(path: str, items: list[dict], is_dir: bool) -> None:
    """Проверава скривени фајл/директоријум."""
    try:
        st = os.lstat(path)
    except (OSError, PermissionError):
        return

    # Прескачемо симлинкове.
    if stat.S_ISLNK(st.st_mode):
        return

    name = os.path.basename(path)

    items.append({
        "path": path,
        "name": name,
        "is_dir": is_dir,
        "size_bytes": st.st_size,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.filemode(st.st_mode),
        "mtime": st.st_mtime,
        "is_known": name in KNOWN_HIDDEN_NAMES,
    })


def _classify_items(
    items: list[dict]
) -> tuple[list[dict], list[dict], list[dict]]:
    """Класификује ставке на високо ризичне, непознате и нормалне."""
    high_risk = []
    unknown = []
    normal = []

    for item in items:
        path = item["path"] + ("/" if item["is_dir"] else "")

        # Ако је познато име — нормално.
        if item["is_known"]:
            normal.append(item)
            continue

        # Проверавамо локацију.
        if any(path.startswith(p) for p in HIGH_RISK_LOCATIONS):
            high_risk.append(item)
            continue

        if any(path.startswith(p) for p in NORMAL_LOCATIONS):
            normal.append(item)
            continue

        # Остало — непознато.
        unknown.append(item)

    return high_risk, unknown, normal


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    high_risk = data.get("high_risk", [])
    unknown = data.get("unknown", [])
    normal = data.get("normal", [])

    console.print(f"[bold]Total hidden items:[/bold]   {summary.get('total', 0)}")
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
        for item in sorted(unknown, key=lambda x: x["path"])[:40]:
            _print_item(item, "yellow")

        if len(unknown) > 40:
            console.print(
                f"  [dim]... and {len(unknown) - 40} more[/dim]"
            )
        console.print()

    # Нормалне — само кратак преглед.
    if normal:
        console.print(
            f"[bold]Normal locations ({len(normal)}):[/bold]\n"
        )
        console.print(
            "  [dim]Hidden files in home, /etc, /var and other "
            "standard locations are not shown.[/dim]"
        )
        console.print()


def _print_item(item: dict, color: str) -> None:
    """Приказује једну ставку."""
    path = item["path"]
    is_dir = item["is_dir"]
    mode = item["mode"]

    type_marker = "[dir]" if is_dir else "[file]"

    console.print(
        f"  [{color}]{path}[/{color}]  "
        f"[dim]{type_marker} {mode}[/dim]"
    )