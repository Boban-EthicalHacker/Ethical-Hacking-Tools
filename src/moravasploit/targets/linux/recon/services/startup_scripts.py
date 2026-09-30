# Модул за приказ скрипти које се покрећу при подизању система.
# Ово су локације где нападачи често стављају persistence.
# Чита /etc/rc.local, /etc/init.d/, /etc/profile.d/,
# X11 autostart и systemd user services.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до локација за покретање.
RC_LOCAL = Path("/etc/rc.local")
INIT_D_DIR = Path("/etc/init.d")
PROFILE_D_DIR = Path("/etc/profile.d")
PROFILE_FILE = Path("/etc/profile")
BASHRC_FILE = Path("/etc/bash.bashrc")
XDG_AUTOSTART = Path("/etc/xdg/autostart")

# Кориснички директоријуми (тражимо у /home/*/).
USER_AUTOSTART_DIRS = [
    ".config/autostart",
    ".config/systemd/user",
]

# Патерни који указују на сумњиве скрипте.
SUSPICIOUS_PATTERNS = [
    # /tmp/ али не /tmp/.X11-unix, /tmp/.ICE-unix, итд.
    (r"/tmp/(?!\.X11-unix|\.ICE-unix|\.XIM-unix|\.font-unix|\.Test-unix)",
     "executes from /tmp"),
    (r"/var/tmp/", "executes from /var/tmp"),
    (r"/dev/shm/", "executes from /dev/shm"),
    (r"curl\s+.*\|\s*(ba)?sh", "pipe from curl to shell"),
    (r"wget\s+.*\|\s*(ba)?sh", "pipe from wget to shell"),
    (r"base64\s+-d", "decodes base64 (obfuscation)"),
    (r"/bin/(ba)?sh\s+-i", "reverse shell"),
    (r"nc\s+-[el]", "netcat listener"),
    (r"python.*socket.*connect", "python reverse shell"),
]

# Компајлирамо патерне.
SUSPICIOUS_RE = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in SUSPICIOUS_PATTERNS
]

# Скрипте које су познато безбедне и прескачемо их при анализи.
# Ово су системске скрипте које користе /tmp/ за легитимне ствари.
KNOWN_SAFE_SCRIPTS = {
    "/etc/init.d/x11-common",
    "/etc/init.d/x11-common.dpkg-new",
    "/etc/init.d/x11-common.dpkg-old",
}


def run() -> dict:
    """Приказује скрипте за покретање.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Startup scripts[/bold cyan]\n")

    # Читамо све изворе.
    rc_local = _read_file_safe(RC_LOCAL)
    init_d = _read_dir_files(INIT_D_DIR, extensions=None)
    profile_d = _read_dir_files(PROFILE_D_DIR, extensions=None)
    global_profile = _read_global_profile()
    xdg_autostart = _read_xdg_autostart()
    user_autostart = _read_user_autostart()

    # Спајамо све скрипте за анализу.
    all_scripts = _collect_all_scripts(
        rc_local,
        init_d,
        profile_d,
        global_profile,
        xdg_autostart,
        user_autostart,
    )

    # Тражимо сумњиве.
    suspicious = _find_suspicious(all_scripts)

    data = {
        "rc_local": rc_local,
        "init_d": init_d,
        "profile_d": profile_d,
        "global_profile": global_profile,
        "xdg_autostart": xdg_autostart,
        "user_autostart": user_autostart,
        "suspicious": suspicious,
        "summary": {
            "total_scripts": len(all_scripts),
            "suspicious_count": len(suspicious),
            "sources": {
                "rc_local": 1 if rc_local.get("exists") else 0,
                "init_d": len(init_d),
                "profile_d": len(profile_d),
                "xdg_autostart": len(xdg_autostart),
                "user_autostart": len(user_autostart),
            },
        },
    }

    _print_data(data)

    return data


def _read_file_safe(path: Path) -> dict:
    """Чита фајл и враћа речник са садржајем."""
    result = {
        "path": str(path),
        "exists": path.exists(),
        "readable": False,
        "content": None,
        "is_executable": False,
    }

    if not path.exists():
        return result

    try:
        result["is_executable"] = bool(path.stat().st_mode & 0o111)
    except Exception:
        pass

    try:
        result["content"] = path.read_text(
            encoding="utf-8", errors="replace"
        )
        result["readable"] = True
    except (PermissionError, Exception):
        pass

    return result


def _read_dir_files(path: Path, extensions: list | None) -> list[dict]:
    """Чита све фајлове у директоријуму."""
    files = []

    if not path.exists() or not path.is_dir():
        return files

    try:
        entries = sorted(path.iterdir())
    except (PermissionError, Exception):
        return files

    for file_path in entries:
        if not file_path.is_file():
            continue

        name = file_path.name

        # Прескачемо скривене и backup.
        if name.startswith(".") or name.endswith("~"):
            continue

        # Ако су дати наставци, филтрирамо.
        if extensions:
            if not any(name.endswith(ext) for ext in extensions):
                continue

        entry = {
            "name": name,
            "path": str(file_path),
        }

        try:
            st = file_path.stat()
            entry["size_bytes"] = st.st_size
            entry["executable"] = bool(st.st_mode & 0o111)
            entry["uid"] = st.st_uid
        except Exception:
            pass

        # За мале фајлове читамо садржај.
        try:
            content = file_path.read_text(
                encoding="utf-8", errors="replace"
            )
            # Узимамо само првих 2000 знакова за анализу.
            entry["content_preview"] = content[:2000]
        except Exception:
            entry["content_preview"] = ""

        files.append(entry)

    return files


def _read_global_profile() -> dict:
    """Чита /etc/profile и /etc/bash.bashrc."""
    result = {
        "profile": _read_file_safe(PROFILE_FILE),
        "bashrc": _read_file_safe(BASHRC_FILE),
    }
    return result


def _read_xdg_autostart() -> list[dict]:
    """Чита XDG autostart (.desktop фајлови)."""
    files = []

    if not XDG_AUTOSTART.exists() or not XDG_AUTOSTART.is_dir():
        return files

    try:
        entries = sorted(XDG_AUTOSTART.iterdir())
    except (PermissionError, Exception):
        return files

    for file_path in entries:
        if not file_path.is_file():
            continue
        if not file_path.name.endswith(".desktop"):
            continue

        try:
            content = file_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception:
            content = ""

        # Парсирамо .desktop фајл.
        parsed = _parse_desktop_file(content)

        files.append({
            "name": file_path.name,
            "path": str(file_path),
            "name_display": parsed.get("Name"),
            "exec": parsed.get("Exec"),
            "hidden": parsed.get("Hidden") == "true",
            "content_preview": content[:500],
        })

    return files


def _parse_desktop_file(content: str) -> dict:
    """Парсира .desktop фајл и враћа кључне вредности."""
    result = {}

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()

    return result


def _read_user_autostart() -> list[dict]:
    """Чита корисничке autostart и systemd user services."""
    entries = []

    home_base = Path("/home")
    if not home_base.exists():
        return entries

    try:
        user_homes = [d for d in home_base.iterdir() if d.is_dir()]
    except (PermissionError, Exception):
        return entries

    for user_home in user_homes:
        username = user_home.name

        for rel_path in USER_AUTOSTART_DIRS:
            target_dir = user_home / rel_path

            if not target_dir.exists() or not target_dir.is_dir():
                continue

            try:
                files = sorted(target_dir.iterdir())
            except (PermissionError, Exception):
                continue

            for file_path in files:
                if not file_path.is_file():
                    continue

                name = file_path.name

                # XDG autostart — .desktop фајлови.
                if rel_path.endswith("autostart"):
                    if not name.endswith(".desktop"):
                        continue

                    try:
                        content = file_path.read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except Exception:
                        content = ""

                    parsed = _parse_desktop_file(content)

                    entries.append({
                        "user": username,
                        "type": "xdg_autostart",
                        "name": name,
                        "path": str(file_path),
                        "name_display": parsed.get("Name"),
                        "exec": parsed.get("Exec"),
                        "hidden": parsed.get("Hidden") == "true",
                    })

                # Systemd user services — .service фајлови.
                elif rel_path.endswith("systemd/user"):
                    if not name.endswith((".service", ".timer")):
                        continue

                    try:
                        content = file_path.read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except Exception:
                        content = ""

                    entries.append({
                        "user": username,
                        "type": "systemd_user",
                        "name": name,
                        "path": str(file_path),
                        "content_preview": content[:500],
                    })

    return entries


def _collect_all_scripts(
    rc_local: dict,
    init_d: list,
    profile_d: list,
    global_profile: dict,
    xdg_autostart: list,
    user_autostart: list,
) -> list[dict]:
    """Скупља све скрипте у једну листу за анализу."""
    scripts = []

    # rc.local
    if rc_local.get("exists") and rc_local.get("readable"):
        scripts.append({
            "source": "rc.local",
            "path": rc_local["path"],
            "content": rc_local.get("content", ""),
        })

    # init.d
    for entry in init_d:
        scripts.append({
            "source": "init.d",
            "path": entry["path"],
            "content": entry.get("content_preview", ""),
        })

    # profile.d
    for entry in profile_d:
        scripts.append({
            "source": "profile.d",
            "path": entry["path"],
            "content": entry.get("content_preview", ""),
        })

    # Global profile
    for key in ("profile", "bashrc"):
        entry = global_profile.get(key, {})
        if entry.get("exists") and entry.get("readable"):
            scripts.append({
                "source": f"/etc/{key}",
                "path": entry["path"],
                "content": entry.get("content", "")[:2000],
            })

    # XDG autostart
    for entry in xdg_autostart:
        scripts.append({
            "source": "xdg_autostart",
            "path": entry["path"],
            "content": (
                (entry.get("exec") or "") + " " +
                (entry.get("name_display") or "")
            ),
        })

    # User autostart
    for entry in user_autostart:
        content = entry.get("exec", "") or entry.get("content_preview", "")
        scripts.append({
            "source": f"user:{entry.get('user', '?')}:{entry.get('type', '?')}",
            "path": entry["path"],
            "content": content,
        })

    return scripts


def _find_suspicious(scripts: list[dict]) -> list[dict]:
    """Проналази сумњиве скрипте."""
    suspicious = []

    for script in scripts:
        content = script.get("content", "")
        path = script.get("path", "")

        # Прескачемо познато безбедне скрипте.
        if path in KNOWN_SAFE_SCRIPTS:
            continue

        combined = f"{path} {content}"

        for pattern, description in SUSPICIOUS_RE:
            if pattern.search(combined):
                suspicious.append({
                    "source": script.get("source", "?"),
                    "path": path,
                    "reason": description,
                    "severity": "red",
                })
                break

    return suspicious


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    suspicious = data.get("suspicious", [])
    rc_local = data.get("rc_local", {})
    init_d = data.get("init_d", [])
    profile_d = data.get("profile_d", [])
    xdg_autostart = data.get("xdg_autostart", [])
    user_autostart = data.get("user_autostart", [])

    console.print(
        f"[bold]Total scripts:[/bold]    "
        f"{summary.get('total_scripts', 0)}"
    )

    sources = summary.get("sources", {})
    console.print(f"  rc.local:          {sources.get('rc_local', 0)}")
    console.print(f"  init.d:            {sources.get('init_d', 0)}")
    console.print(f"  profile.d:         {sources.get('profile_d', 0)}")
    console.print(f"  xdg autostart:     {sources.get('xdg_autostart', 0)}")
    console.print(f"  user autostart:    {sources.get('user_autostart', 0)}")

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
            console.print(
                f"  [bold red]●[/bold red] "
                f"[yellow]{item['reason']}[/yellow]"
            )
            console.print(f"    [dim]{item['path']}[/dim]")
        console.print()

    # rc.local
    if rc_local.get("exists"):
        console.print("[bold cyan]/etc/rc.local[/bold cyan]\n")

        if not rc_local.get("readable"):
            console.print("  [dim]Not readable.[/dim]\n")
        else:
            content = rc_local.get("content", "")
            # Приказујемо не-коментар линије.
            lines = [
                ln for ln in content.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            if lines:
                for ln in lines[:10]:
                    console.print(f"  {ln}")
            else:
                console.print("  [dim]Empty (only comments).[/dim]")
            console.print()

    # init.d
    if init_d:
        console.print(
            f"[bold cyan]/etc/init.d/ ({len(init_d)} scripts)[/bold cyan]\n"
        )
        for entry in init_d[:15]:
            exec_marker = (
                "[green]exec[/green]"
                if entry.get("executable")
                else "[dim]noexec[/dim]"
            )
            console.print(
                f"  {entry['name']:35s}  {exec_marker}"
            )
        if len(init_d) > 15:
            console.print(
                f"  [dim]... and {len(init_d) - 15} more[/dim]"
            )
        console.print()

    # profile.d
    if profile_d:
        console.print(
            f"[bold cyan]/etc/profile.d/ "
            f"({len(profile_d)} scripts)[/bold cyan]\n"
        )
        for entry in profile_d[:15]:
            exec_marker = (
                "[green]exec[/green]"
                if entry.get("executable")
                else "[dim]noexec[/dim]"
            )
            console.print(
                f"  {entry['name']:35s}  {exec_marker}"
            )
        if len(profile_d) > 15:
            console.print(
                f"  [dim]... and {len(profile_d) - 15} more[/dim]"
            )
        console.print()

    # XDG autostart
    if xdg_autostart:
        console.print(
            f"[bold cyan]XDG autostart ({len(xdg_autostart)})[/bold cyan]\n"
        )

        # Приказујемо само видљиве (не Hidden=true).
        visible = [e for e in xdg_autostart if not e.get("hidden")]

        for entry in visible[:15]:
            name_display = entry.get("name_display") or entry["name"]
            exec_cmd = entry.get("exec", "")

            # Скраћујемо.
            if len(exec_cmd) > 50:
                exec_cmd = exec_cmd[:47] + "..."

            console.print(
                f"  [bold]{name_display:30s}[/bold]  "
                f"[dim]{exec_cmd}[/dim]"
            )

        if len(visible) > 15:
            console.print(
                f"  [dim]... and {len(visible) - 15} more[/dim]"
            )
        console.print()

    # User autostart
    if user_autostart:
        console.print(
            f"[bold cyan]User autostart ({len(user_autostart)})[/bold cyan]\n"
        )
        for entry in user_autostart[:15]:
            user = entry.get("user", "?")
            name = entry.get("name_display") or entry["name"]
            entry_type = entry.get("type", "?")

            console.print(
                f"  [bold]{user}[/bold]  "
                f"[dim]{entry_type}[/dim]  "
                f"{name}"
            )
        if len(user_autostart) > 15:
            console.print(
                f"  [dim]... and {len(user_autostart) - 15} more[/dim]"
            )
        console.print()