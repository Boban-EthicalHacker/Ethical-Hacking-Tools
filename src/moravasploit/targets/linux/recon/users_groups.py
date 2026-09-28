# Модул за приказ корисника, група и sudo права на Linux систему.
# Чита /etc/passwd, /etc/group и покушава да прочита sudoers
# конфигурацију. Ово је важно за процену површине напада —
# ко има приступ, ко може да се пријави, ко има администраторска
# права.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
PASSWD_FILE = Path("/etc/passwd")
GROUP_FILE = Path("/etc/group")
SUDOERS_FILE = Path("/etc/sudoers")
SUDOERS_DIR = Path("/etc/sudoers.d")

# Листа системских shell-ова који значе да корисник може
# да се пријави интерактивно. Ако је shell /usr/sbin/nologin
# или /bin/false, корисник не може да се пријави.
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


def run() -> None:
    """Приказује кориснике, групе и sudo права."""
    console.print("\n[bold cyan]Users and groups[/bold cyan]\n")

    # Читамо кориснике.
    users = _read_passwd()

    # Читамо групе.
    groups = _read_group()

    # Приказујемо резиме.
    _print_summary(users, groups)

    # Приказујемо кориснике са UID 0 (root-еквиваленти).
    _print_uid0_users(users)

    # Приказујемо кориснике који могу да се пријаве.
    _print_interactive_users(users)

    # Приказујемо sudo кориснике.
    _print_sudo_users()


def _read_passwd() -> list[dict]:
    """Чита /etc/passwd и враћа листу корисника.

    Формат сваке линије:
        name:password:uid:gid:gecos:home:shell
    """
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
    """Чита /etc/group и враћа листу група.

    Формат сваке линије:
        name:password:gid:members
    """
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


def _print_summary(users: list[dict], groups: list[dict]) -> None:
    """Приказује резиме — број корисника и група."""
    # Раздвајамо системске од обичних корисника.
    # Системски имају UID < 1000 (обично), обични UID >= 1000.
    system_users = [u for u in users if u["uid"] < 1000]
    regular_users = [u for u in users if u["uid"] >= 1000]

    console.print(f"[bold]Total users:[/bold]      {len(users)}")
    console.print(f"  System (UID < 1000):    {len(system_users)}")
    console.print(f"  Regular (UID >= 1000):  {len(regular_users)}")
    console.print(f"[bold]Total groups:[/bold]     {len(groups)}")
    console.print()


def _print_uid0_users(users: list[dict]) -> None:
    """Приказује кориснике са UID 0 (root-еквиваленти)."""
    uid0 = [u for u in users if u["uid"] == 0]

    if not uid0:
        return

    console.print(f"[bold]UID 0 users ({len(uid0)}):[/bold]\n")

    for u in uid0:
        # Обично је само "root". Ако постоји више, то је сумњиво.
        if u["name"] == "root":
            console.print(f"  [green]{u['name']}[/green]  ({u['shell']})")
        else:
            console.print(
                f"  [bold red]{u['name']}[/bold red]  "
                f"({u['shell']}) — [red]non-standard root user[/red]"
            )

    console.print()


def _print_interactive_users(users: list[dict]) -> None:
    """Приказује кориснике који могу интерактивно да се пријаве."""
    interactive = [
        u for u in users
        if u["uid"] >= 1000 and u["shell"] in INTERACTIVE_SHELLS
    ]

    if not interactive:
        console.print(
            "[dim]No interactive user accounts found "
            "(besides system users).[/dim]\n"
        )
        return

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


def _print_sudo_users() -> None:
    """Приказује кориснике који имају sudo права.

    Чита /etc/sudoers и /etc/sudoers.d/. Ако нема дозволе
    за читање, приказује поруку.
    """
    console.print("[bold]Sudo users:[/bold]\n")

    sudo_entries = []

    # Читамо главни sudoers фајл.
    main_entries = _parse_sudoers(SUDOERS_FILE)
    if main_entries:
        sudo_entries.extend(main_entries)

    # Читамо све фајлове у /etc/sudoers.d/.
    if SUDOERS_DIR.exists() and SUDOERS_DIR.is_dir():
        try:
            for entry in sorted(SUDOERS_DIR.iterdir()):
                if not entry.is_file():
                    continue

                file_entries = _parse_sudoers(entry)
                if file_entries:
                    sudo_entries.extend(file_entries)
        except PermissionError:
            pass

    if not sudo_entries:
        console.print(
            "  [dim]No readable sudo configuration found.[/dim]"
        )
        console.print(
            "  [dim](This is normal if running as unprivileged user — "
            "/etc/sudoers is usually readable only by root.)[/dim]\n"
        )
        return

    for entry in sudo_entries:
        console.print(f"  {entry}")

    console.print()


def _parse_sudoers(path: Path) -> list[str]:
    """Парсира sudoers фајл и враћа листу правила.

    Фајл може бити нечитак за обичне кориснике.
    """
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

        # Прескачемо празне линије и коментаре.
        if not line or line.startswith("#"):
            continue

        # Прескачемо "Defaults" линије.
        if line.startswith("Defaults"):
            continue

        # Прескачемо "User_Alias", "Host_Alias", итд.
        if "_Alias" in line:
            continue

        # Прескачемо Include и #includedir.
        if line.startswith("#include") or line.startswith("@"):
            continue

        # Прескачемо Cmnd_Alias.
        if line.startswith("Cmnd_Alias"):
            continue

        # Остало су правила типа: user host=(runas) commands
        entries.append(line)

    return entries