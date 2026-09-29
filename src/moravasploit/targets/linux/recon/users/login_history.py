# Модул за приказ историје пријављивања на систем.
# Користи системске команде за читање wtmp/btmp фајлова.
#
# На новијим системима (нпр. Kali 2026.3+) користи се wtmpdb
# уместо класичних wtmp/btmp бинарних фајлова и last/lastb
# команди. Овај модул подржава оба система.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess

from rich.console import Console

console = Console()

# Максималан број редова које приказујемо/чувамо.
MAX_ENTRIES = 50


def run() -> dict:
    """Приказује историју пријављивања.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Login history[/bold cyan]\n")

    # Препознајемо који систем је доступан.
    backend = _detect_backend()

    # Тренутно пријављени корисници.
    current = _parse_who()

    # Последње пријаве.
    recent = _parse_recent(backend)

    # Неуспешни покушаји.
    failed = _parse_failed(backend)

    data = {
        "backend": backend,
        "current_logins": current,
        "recent_logins": recent,
        "failed_logins": failed,
        "summary": _make_summary(current, recent, failed),
    }

    _print_data(data)

    return data


def _detect_backend() -> str:
    """Препознаје који систем за логове је доступан.

    Враћа: "wtmpdb", "last", или "none".
    """
    # Прво проверавамо wtmpdb (новији систем).
    if shutil.which("wtmpdb"):
        return "wtmpdb"

    # Затим класични last.
    if shutil.which("last"):
        return "last"

    return "none"


def _run_command(cmd: list[str]) -> str | None:
    """Покреће команду и враћа њен излаз.

    Враћа None ако команда не постоји или пукне.
    """
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


def _parse_who() -> list[dict]:
    """Парсира излаз команде who.

    Формат:
        boban    pts/0        2026-09-29 22:00 (192.168.1.5)
    """
    output = _run_command(["who"])
    if not output:
        return []

    entries = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        user = parts[0]
        tty = parts[1]

        login_time = None
        from_host = None

        # Тражимо део у заградама (from host).
        if "(" in line and ")" in line:
            start = line.rfind("(")
            end = line.rfind(")")
            from_host = line[start + 1 : end]

        # Спајамо датум и време.
        try:
            after_tty = line.split(tty, 1)[1].strip()
            if "(" in after_tty:
                login_time = after_tty.split("(")[0].strip()
            else:
                login_time = after_tty
        except (IndexError, ValueError):
            pass

        entries.append({
            "user": user,
            "tty": tty,
            "login_time": login_time,
            "from_host": from_host,
        })

    return entries


def _parse_recent(backend: str) -> list[dict]:
    """Парсира последње пријаве у зависности од backend-а."""
    if backend == "wtmpdb":
        return _parse_wtmpdb_last()
    if backend == "last":
        return _parse_classic_last()
    return []


def _parse_wtmpdb_last() -> list[dict]:
    """Парсира излаз команде `wtmpdb last`.

    Формат:
        boban    tty7         :0               Tue Sep 29 21:24 - still logged in
        boban    tty7         :0               Mon Sep 28 22:15 - 23:55  (01:39)
    """
    output = _run_command(["wtmpdb", "last", "-n", str(MAX_ENTRIES)])
    if not output:
        return []

    entries = []

    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue

        # Прескачемо "wtmpdb begins ..." на крају.
        if line.startswith("wtmpdb begins"):
            continue

        parsed = _parse_wtmpdb_line(line)
        if parsed:
            entries.append(parsed)

    return entries


def _parse_wtmpdb_line(line: str) -> dict | None:
    """Парсира једну линију из `wtmpdb last`."""
    parts = line.split()
    if len(parts) < 3:
        return None

    user = parts[0]
    tty = parts[1] if len(parts) > 1 else None

    # Откривамо где је host (обично трећи део ако није датум).
    # Датум почиње са даном у недељи (Mon, Tue, ...).
    days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

    host = None
    date_index = None

    for i, part in enumerate(parts):
        if part in days:
            date_index = i
            break

    # Ако смо нашли датум, host је пре њега (између tty и датума).
    if date_index is not None and date_index > 2:
        host = parts[2]

    # Извлачимо датум и време.
    login_time = None
    if date_index is not None and date_index + 3 < len(parts):
        login_time = f"{parts[date_index]} {parts[date_index + 1]} " \
                     f"{parts[date_index + 2]} {parts[date_index + 3]}"

    # Статус (still logged in или трајање).
    status = None
    if "still logged in" in line:
        status = "still logged in"
    elif "still running" in line:
        status = "still running"
    elif "gone - no logout" in line:
        status = "gone - no logout"
    elif "(" in line and line.endswith(")"):
        # Трајање је у заградама на крају.
        start = line.rfind("(")
        status = line[start:].strip()

    return {
        "user": user,
        "tty": tty,
        "from_host": host,
        "login_time": login_time,
        "status": status,
    }


def _parse_classic_last() -> list[dict]:
    """Парсира излаз класичне команде `last`."""
    output = _run_command(["last", "-n", str(MAX_ENTRIES)])
    if not output:
        return []

    entries = []

    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue

        if line.startswith("wtmp begins"):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        user = parts[0]

        # Reboot има другачији формат.
        if user == "reboot":
            entries.append({
                "user": "reboot",
                "tty": None,
                "from_host": None,
                "login_time": _extract_date_from_last(parts),
                "status": _extract_status_from_last(line),
            })
            continue

        tty = parts[1] if len(parts) > 1 else None
        from_host = parts[2] if len(parts) > 2 else None

        entries.append({
            "user": user,
            "tty": tty,
            "from_host": from_host,
            "login_time": _extract_date_from_last(parts),
            "status": _extract_status_from_last(line),
        })

    return entries


def _extract_date_from_last(parts: list[str]) -> str | None:
    """Извлачи датум из класичног last излаза."""
    days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = (
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    )

    for i, part in enumerate(parts):
        if part in days and i + 3 < len(parts):
            return f"{parts[i]} {parts[i + 1]} {parts[i + 2]} {parts[i + 3]}"
        if part in months and i + 2 < len(parts):
            return f"{part} {parts[i + 1]} {parts[i + 2]}"

    return None


def _extract_status_from_last(line: str) -> str | None:
    """Извлачи статус из класичног last излаза."""
    statuses = [
        "still logged in",
        "still running",
        "gone - no logout",
        "down",
        "crash",
    ]

    for status in statuses:
        if status in line:
            return status

    if "(" in line and line.endswith(")"):
        start = line.rfind("(")
        return line[start:].strip()

    return None


def _parse_failed(backend: str) -> list[dict]:
    """Парсира неуспешне покушаје пријаве.

    На wtmpdb систему, неуспешни покушаји обично нису доступни
    кроз исту команду. На класичном систему, користимо lastb.
    """
    if backend == "last":
        return _parse_classic_lastb()

    # wtmpdb тренутно не нуди директан еквивалент за lastb.
    # Могуће је да постоји у будућности.
    return []


def _parse_classic_lastb() -> list[dict]:
    """Парсира излаз класичне команде `lastb`."""
    output = _run_command(["lastb", "-n", str(MAX_ENTRIES)])
    if not output:
        return []

    entries = []

    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue

        if line.startswith("btmp begins"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        user = parts[0]
        tty = parts[1] if len(parts) > 1 else None
        from_host = parts[2] if len(parts) > 2 else None

        entries.append({
            "user": user,
            "tty": tty,
            "from_host": from_host,
            "login_time": _extract_date_from_last(parts),
        })

    return entries


def _make_summary(
    current: list[dict],
    recent: list[dict],
    failed: list[dict],
) -> dict:
    """Прави резиме."""
    user_logins = [e for e in recent if e["user"] != "reboot"]

    return {
        "current_logins": len(current),
        "recent_logins": len(user_logins),
        "recent_reboots": len(recent) - len(user_logins),
        "failed_logins": len(failed),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    backend = data.get("backend", "unknown")
    current = data.get("current_logins", [])
    recent = data.get("recent_logins", [])
    failed = data.get("failed_logins", [])

    # Backend.
    backend_labels = {
        "wtmpdb": "wtmpdb (new)",
        "last": "last (classic)",
        "none": "not available",
    }
    console.print(
        f"[bold]Backend:[/bold]              "
        f"[cyan]{backend_labels.get(backend, backend)}[/cyan]"
    )

    console.print(
        f"[bold]Currently logged in:[/bold]  {summary.get('current_logins', 0)}"
    )
    console.print(
        f"[bold]Recent logins:[/bold]        {summary.get('recent_logins', 0)}"
    )
    console.print(
        f"[bold]Recent reboots:[/bold]       {summary.get('recent_reboots', 0)}"
    )

    if failed:
        console.print(
            f"[bold]Failed logins:[/bold]       "
            f"[red]{summary.get('failed_logins', 0)}[/red]"
        )
    else:
        console.print(
            f"[bold]Failed logins:[/bold]       "
            f"[dim]0 (not available on this system)[/dim]"
        )

    console.print()

    # Тренутно пријављени.
    if current:
        console.print("[bold]Currently logged in:[/bold]\n")
        for entry in current:
            line = f"  {entry['user']:15s} {entry.get('tty') or '':10s}"
            if entry.get("from_host"):
                line += f"  from {entry['from_host']}"
            if entry.get("login_time"):
                line += f"  [dim]({entry['login_time']})[/dim]"
            console.print(line)
        console.print()

    # Последње пријаве.
    if recent:
        console.print(f"[bold]Recent logins (last {len(recent)}):[/bold]\n")
        for entry in recent[:20]:
            _print_login_entry(entry)

        if len(recent) > 20:
            console.print(
                f"  [dim]... and {len(recent) - 20} more[/dim]"
            )
        console.print()

    # Неуспешни покушаји.
    if failed:
        console.print(
            f"[bold]Failed logins (last {len(failed)}):[/bold]\n"
        )
        for entry in failed[:20]:
            _print_login_entry(entry, failed=True)

        if len(failed) > 20:
            console.print(
                f"  [dim]... and {len(failed) - 20} more[/dim]"
            )
        console.print()


def _print_login_entry(entry: dict, failed: bool = False) -> None:
    """Приказује један унос пријаве."""
    user = entry.get("user", "?")
    tty = entry.get("tty") or ""
    from_host = entry.get("from_host") or ""
    login_time = entry.get("login_time") or ""
    status = entry.get("status") or ""

    color = "red" if failed else "white"

    line = f"  [{color}]{user:15s}[/{color}] {tty:10s}"

    if from_host:
        line += f"  from {from_host}"

    if login_time:
        line += f"  [dim]{login_time}[/dim]"

    if status:
        line += f"  [dim]{status}[/dim]"

    console.print(line)