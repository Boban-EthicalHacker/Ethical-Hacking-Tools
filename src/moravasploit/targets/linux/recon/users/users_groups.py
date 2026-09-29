# Модул за приказ корисника, група и sudo права на Linux систему.
# Чита /etc/passwd, /etc/group и покушава да прочита sudoers
# конфигурацију.
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
PASSWD_FILE = Path("/etc/passwd")
GROUP_FILE = Path("/etc/group")
SUDOERS_FILE = Path("/etc/sudoers")
SUDOERS_DIR = Path("/etc/sudoers.d")

# Листа системских shell-ова који значе да корисник може
# да се пријави интерактивно.
INTERACTIVE_SHELLS = (
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/bin/ksh",
    "/bin/csh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/bin/fish",
)


def run() -> dict:
    """Приказује кориснике, групе и sudo права.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Users and groups[/bold cyan]\n")

    # Прикупљамо податке.
    users = _read_passwd()
    groups = _read_group()
    sudo_entries = _read_sudoers()

    # Правимо речник за JSON.
    data = {
        "users": users,
        "groups": groups,
        "sudo_entries": sudo_entries,
        "summary": _make_summary(users, groups),
    }

    # Приказујемо на екран.
    _print_data(data)

    return data


def _read_passwd() -> list[dict]:
    """Чита /etc/passwd и враћа листу корисника."""
    users = []

    if not PASSWD_FILE.exists():
        return users

    try:
        content = PASSWD_FILE.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return users

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 7:
            continue

        try:
            users.append({
                "name": parts[0],
                "uid": int(parts[2]),
                "gid": int(parts[3]),
                "gecos": parts[4],
                "home": parts[5],
                "shell": parts[6],
            })
        except (ValueError, IndexError):
            continue

    return users


def _read_group() -> list[dict]:
    """Чита /etc/group и враћа листу група."""
    groups = []

    if not GROUP_FILE.exists():
        return groups

    try:
        content = GROUP_FILE.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return groups

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 4:
            continue

        try:
            members = [m for m in parts[3].split(",") if m]
            groups.append({
                "name": parts[0],
                "gid": int(parts[2]),
                "members": members,
            })
        except (ValueError, IndexError):
            continue

    return groups


def _read_sudoers() -> list[str]:
    """Чита sudoers конфигурацију.

    Покушава /etc/sudoers и /etc/sudoers.d/.
    Ако нема дозволе, враћа празну листу.
    """
    entries = []

    # Главни фајл.
    entries.extend(_parse_sudoers(SUDOERS_FILE))

    # Додатни фајлови у /etc/sudoers.d/.
    if SUDOERS_DIR.exists() and SUDOERS_DIR.is_dir():
        try:
            for entry in sorted(SUDOERS_DIR.iterdir()):
                if not entry.is_file():
                    continue
                entries.extend(_parse_sudoers(entry))
        except PermissionError:
            pass

    return entries


def _parse_sudoers(path: Path) -> list[str]:
    """Парсира sudoers фајл и враћа листу правила."""
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return []
    except Exception:
        return []

    entries = []

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue
        if line.startswith("Defaults"):
            continue
        if "_Alias" in line:
            continue
        if line.startswith("#include") or line.startswith("@"):
            continue
        if line.startswith("Cmnd_Alias"):
            continue

        entries.append(line)

    return entries


def _make_summary(users: list[dict], groups: list[dict]) -> dict:
    """Прави резиме са бројевима."""
    system_users = [u for u in users if u["uid"] < 1000]
    regular_users = [u for u in users if u["uid"] >= 1000]
    uid0_users = [u for u in users if u["uid"] == 0]
    interactive_users = [
        u for u in users
        if u["uid"] >= 1000 and u["shell"] in INTERACTIVE_SHELLS
    ]

    return {
        "total_users": len(users),
        "total_groups": len(groups),
        "system_users": len(system_users),
        "regular_users": len(regular_users),
        "uid0_users": len(uid0_users),
        "interactive_users": len(interactive_users),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    users = data.get("users", [])
    groups = data.get("groups", [])
    sudo_entries = data.get("sudo_entries", [])

    # Резиме.
    console.print(f"[bold]Total users:[/bold]      {summary.get('total_users', 0)}")
    console.print(
        f"  System (UID < 1000):    {summary.get('system_users', 0)}"
    )
    console.print(
        f"  Regular (UID >= 1000):  {summary.get('regular_users', 0)}"
    )
    console.print(f"[bold]Total groups:[/bold]     {summary.get('total_groups', 0)}")
    console.print()

    # UID 0 корисници.
    uid0 = [u for u in users if u["uid"] == 0]
    if uid0:
        console.print(f"[bold]UID 0 users ({len(uid0)}):[/bold]\n")
        for u in uid0:
            if u["name"] == "root":
                console.print(f"  [green]{u['name']}[/green]  ({u['shell']})")
            else:
                console.print(
                    f"  [bold red]{u['name']}[/bold red]  "
                    f"({u['shell']}) — [red]non-standard root user[/red]"
                )
        console.print()

    # Интерактивни корисници.
    interactive = [
        u for u in users
        if u["uid"] >= 1000 and u["shell"] in INTERACTIVE_SHELLS
    ]

    if interactive:
        console.print(
            f"[bold]Interactive users ({len(interactive)}):[/bold]\n"
        )
        console.print(
            f"  {'USER':20s} {'UID':>6s}  {'HOME':30s}  SHELL"
        )
        for u in sorted(interactive, key=lambda x: x["uid"]):
            console.print(
                f"  {u['name']:20s} {u['uid']:>6d}  "
                f"{u['home']:30s}  {u['shell']}"
            )
        console.print()

    # Sudo.
    if sudo_entries:
        console.print(f"[bold]Sudo rules ({len(sudo_entries)}):[/bold]\n")
        for entry in sudo_entries:
            console.print(f"  {entry}")
        console.print()
    else:
        console.print("[bold]Sudo rules:[/bold]  [dim]none readable[/dim]")
        console.print(
            "  [dim](/etc/sudoers is usually readable only by root.)[/dim]\n"
        )