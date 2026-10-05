# Модул за анализу audit логова (Linux Audit система).
# Audit је најдетаљнији безбедносни лог — бележи syscall-ове,
# извршавање команди, аутентикацију, AVC деније.
#
# Ако auditd није активан, покушавамо journal fallback.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до audit логова.
AUDIT_LOG_PATHS = [
    Path("/var/log/audit/audit.log"),
    Path("/var/log/audit/audit.log.1"),
]

# Патерни за различите типове audit записа.
AUDIT_PATTERNS = {
    "syscall": re.compile(
        r"type=SYSCALL\s+msg=audit\([^)]+\):"
    ),
    "execve": re.compile(
        r"type=EXECVE\s+msg=audit\([^)]+\):"
    ),
    "user_auth": re.compile(
        r"type=USER_AUTH\s+msg=audit\([^)]+\):"
    ),
    "user_login": re.compile(
        r"type=USER_LOGIN\s+msg=audit\([^)]+\):"
    ),
    "user_acct": re.compile(
        r"type=USER_ACCT\s+msg=audit\([^)]+\):"
    ),
    "avc_denied": re.compile(
        r"type=AVC\s+msg=audit\([^)]+\):.*denied"
    ),
    "config_change": re.compile(
        r"type=CONFIG_CHANGE\s+msg=audit\([^)]+\):"
    ),
    "service_start": re.compile(
        r"type=SERVICE_START\s+msg=audit\([^)]+\):"
    ),
    "service_stop": re.compile(
        r"type=SERVICE_STOP\s+msg=audit\([^)]+\):"
    ),
    "semanage": re.compile(
        r"type=MAC_POLICY_LOAD\s+msg=audit\([^)]+\):"
    ),
    "anomaly": re.compile(
        r"type=ANOM_.*msg=audit\([^)]+\):"
    ),
}

# Максималан број линија које читамо.
MAX_LINES = 50000

# Максималан број догађаја за приказ по типу.
MAX_DISPLAY = 10


def run() -> dict:
    """Анализира audit логове.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Audit logs[/bold cyan]\n")

    # Проналазимо audit лог фајлове.
    log_files = _find_log_files()

    all_lines = []
    source_type = None

    if log_files:
        source_type = "files"
        for log_path in log_files:
            lines = _read_log_file(log_path)
            for line in lines:
                line["source"] = str(log_path)
            all_lines.extend(lines)

    # Ако нема, покушавамо journal.
    if not all_lines and shutil.which("journalctl"):
        source_type = "journal"
        journal_lines = _read_journal_audit()
        all_lines.extend(journal_lines)

    if not all_lines:
        console.print(
            "  [yellow]No audit logs found.[/yellow]\n"
        )
        console.print(
            "  [dim]Checked: /var/log/audit/audit.log, "
            "journalctl[/dim]\n"
        )
        console.print(
            "  [dim]auditd may not be installed or active.[/dim]\n"
        )
        return _empty_result()

    # Анализирамо записе.
    events = _parse_events(all_lines)

    # Правимо статистике.
    stats = _make_statistics(events)

    data = {
        "source_type": source_type,
        "log_files": (
            [str(p) for p in log_files]
            if log_files
            else ["journalctl"]
        ),
        "total_lines": len(all_lines),
        "events": events,
        "statistics": stats,
        "summary": {
            "total_lines": len(all_lines),
            "total_events": sum(len(v) for v in events.values()),
            "syscalls": len(events.get("syscall", [])),
            "execve": len(events.get("execve", [])),
            "user_auth": len(events.get("user_auth", [])),
            "avc_denied": len(events.get("avc_denied", [])),
            "config_changes": len(events.get("config_change", [])),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "source_type": None,
        "log_files": [],
        "total_lines": 0,
        "events": {},
        "statistics": {},
        "summary": {
            "total_lines": 0,
            "total_events": 0,
            "syscalls": 0,
            "execve": 0,
            "user_auth": 0,
            "avc_denied": 0,
            "config_changes": 0,
        },
    }


def _find_log_files() -> list[Path]:
    """Проналази audit лог фајлове."""
    found = []

    for path in AUDIT_LOG_PATHS:
        if path.exists() and path.is_file():
            found.append(path)

    return found


def _read_log_file(path: Path) -> list[dict]:
    """Чита audit лог фајл."""
    lines = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        recent = all_lines[-MAX_LINES:]

        for line in recent:
            line = line.strip()
            if line:
                lines.append({"text": line})

    except PermissionError:
        return []
    except Exception:
        return []

    return lines


def _read_journal_audit() -> list[dict]:
    """Чита audit догађаје из journal-а."""
    lines = []

    try:
        proc = subprocess.run(
            [
                "journalctl",
                "-t", "audit",
                "-o", "short",
                "--no-pager",
                "-n", "10000",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return lines
    except Exception:
        return lines

    if proc.returncode != 0:
        return lines

    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            lines.append({
                "text": line,
                "source": "journalctl",
            })

    return lines


def _parse_events(lines: list[dict]) -> dict:
    """Парсира audit записе."""
    events = {}

    for line_info in lines:
        text = line_info.get("text", "")
        source = line_info.get("source", "")

        # Проверавамо сваки патерн.
        for event_type, pattern in AUDIT_PATTERNS.items():
            if pattern.search(text):
                if event_type not in events:
                    events[event_type] = []

                # Ограничавамо број догађаја по типу.
                if len(events[event_type]) < 500:
                    events[event_type].append({
                        "text": text[:400],
                        "source": source,
                    })
                break  # само један тип по линији

    return events


def _make_statistics(events: dict) -> dict:
    """Прави статистике из audit догађаја."""
    result = {}

    # Извлачимо EXECVE команде.
    execve_commands = _extract_execve_commands(events.get("execve", []))
    result["execve_commands"] = execve_commands

    # Извлачимо UID-ове који су извршили syscall-ове.
    syscall_uids = _extract_syscall_uids(events.get("syscall", []))
    result["syscall_uids"] = syscall_uids

    # AVC деније по типу.
    avc_types = _extract_avc_types(events.get("avc_denied", []))
    result["avc_types"] = avc_types

    # Корисници из USER_AUTH.
    auth_users = _extract_auth_users(events.get("user_auth", []))
    result["auth_users"] = auth_users

    return result


def _extract_execve_commands(events: list[dict]) -> list[dict]:
    """Извлачи команде из EXECVE записа."""
    commands = []
    seen = set()

    # Regex за argv: "a0=\"cmd\" a1=\"arg1\"" итд.
    arg_re = re.compile(r'a[0-9]+="([^"]*)"')

    for event in events:
        text = event.get("text", "")

        # Тражимо prog= или exe= у SYSCALL делу.
        # EXECVE садржи само argv.
        args = arg_re.findall(text)

        if args:
            cmd = " ".join(args)
            # Ограничавамо дужину.
            cmd = cmd[:200]

            if cmd and cmd not in seen:
                seen.add(cmd)
                commands.append({
                    "command": cmd,
                    "source": event.get("source", ""),
                })

    return commands[:100]


def _extract_syscall_uids(events: list[dict]) -> dict:
    """Извлачи UID-ове из SYSCALL записа."""
    uids = Counter()

    uid_re = re.compile(r"\buid=(\d+)")

    for event in events:
        text = event.get("text", "")
        match = uid_re.search(text)

        if match:
            uids[match.group(1)] += 1

    return dict(uids.most_common(20))


def _extract_avc_types(events: list[dict]) -> dict:
    """Извлачи типове AVC денија."""
    types = Counter()

    # Regex за "denied { read write } for pid=..."
    denied_re = re.compile(r"denied\s+\{([^}]+)\}")

    for event in events:
        text = event.get("text", "")
        match = denied_re.search(text)

        if match:
            permissions = match.group(1).strip()
            types[permissions] += 1

    return dict(types.most_common(10))


def _extract_auth_users(events: list[dict]) -> dict:
    """Извлачи кориснике из USER_AUTH записа."""
    users = Counter()

    # Regex за acct="username"
    acct_re = re.compile(r'acct="([^"]+)"')

    for event in events:
        text = event.get("text", "")
        match = acct_re.search(text)

        if match:
            users[match.group(1)] += 1

    return dict(users.most_common(20))


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    source_type = data.get("source_type", "?")
    log_files = data.get("log_files", [])
    total_lines = data.get("total_lines", 0)
    events = data.get("events", {})
    stats = data.get("statistics", {})
    summary = data.get("summary", {})

    # Извори.
    if source_type == "journal":
        console.print("[bold]Source:[/bold]  systemd journal")
    else:
        console.print("[bold]Log files:[/bold]\n")
        for log_file in log_files:
            console.print(f"  [dim]{log_file}[/dim]")

    console.print()
    console.print(
        f"[bold]Total lines:[/bold]  {total_lines}"
    )
    console.print()

    # Резиме.
    console.print("[bold]Event summary:[/bold]\n")

    syscalls = summary.get("syscalls", 0)
    execve = summary.get("execve", 0)
    user_auth = summary.get("user_auth", 0)
    avc = summary.get("avc_denied", 0)
    config = summary.get("config_changes", 0)

    console.print(f"  SYSCALL events:    {syscalls}")
    console.print(f"  EXECVE events:     {execve}")
    console.print(f"  USER_AUTH events:  {user_auth}")

    if avc > 0:
        console.print(
            f"  [bold red]AVC denials:[/bold red]       {avc}"
        )
    else:
        console.print("  [green]AVC denials:[/green]       0")

    if config > 0:
        console.print(
            f"  [yellow]Config changes:[/yellow]    {config}"
        )
    else:
        console.print("  Config changes:    0")

    console.print()

    # Ако нема догађаја.
    total_events = sum(len(v) for v in events.values())

    if total_events == 0:
        console.print(
            "  [dim]No audit events found.[/dim]\n"
        )
        return

    # AVC деније прво.
    _print_avc_denials(events.get("avc_denied", []), stats)

    # EXECVE команде.
    _print_execve_commands(stats.get("execve_commands", []))

    # Корисници из auth.
    _print_auth_users(stats.get("auth_users", {}))

    # Config changes.
    _print_config_changes(events.get("config_change", []))


def _print_avc_denials(avc_events: list[dict], stats: dict) -> None:
    """Приказује AVC деније."""
    if not avc_events:
        return

    console.print(
        f"[bold red]AVC denials ({len(avc_events)}):[/bold red]\n"
    )

    # По типу.
    avc_types = stats.get("avc_types", {})

    if avc_types:
        console.print("[bold]Denied permissions:[/bold]\n")
        for permissions, count in avc_types.items():
            console.print(
                f"  [red]{permissions:40s}[/red]  {count}"
            )
        console.print()

    # Приказујемо првих 5.
    console.print("[bold]Recent denials:[/bold]\n")

    for event in avc_events[-5:]:
        text = event.get("text", "")
        if len(text) > 120:
            text = text[:117] + "..."
        console.print(f"  [dim]{text}[/dim]")

    console.print()


def _print_execve_commands(commands: list[dict]) -> None:
    """Приказује извршене команде."""
    if not commands:
        return

    console.print(
        f"[bold]Executed commands ({len(commands)}):[/bold]\n"
    )

    # Приказујемо првих MAX_DISPLAY.
    for cmd in commands[:MAX_DISPLAY]:
        command = cmd.get("command", "")
        console.print(f"  {command}")

    if len(commands) > MAX_DISPLAY:
        console.print(
            f"  [dim]... and {len(commands) - MAX_DISPLAY} more[/dim]"
        )

    console.print()


def _print_auth_users(users: dict) -> None:
    """Приказује кориснике из auth записа."""
    if not users:
        return

    console.print(
        f"[bold]Users in auth events ({len(users)}):[/bold]\n"
    )

    for user, count in list(users.items())[:10]:
        console.print(f"  {user:25s}  {count} event(s)")

    console.print()


def _print_config_changes(events: list[dict]) -> None:
    """Приказује промене audit конфигурације."""
    if not events:
        return

    console.print(
        f"[bold yellow]Audit config changes "
        f"({len(events)}):[/bold yellow]\n"
    )

    for event in events[-5:]:
        text = event.get("text", "")
        if len(text) > 120:
            text = text[:117] + "..."
        console.print(f"  [dim]{text}[/dim]")

    console.print()