# Модул за анализу auth логова.
# Auth логови садрже пријаве, неуспешне покушаје, sudo команде.
#
# На различитим системима се налазе на различитим местима:
#   - Debian/Ubuntu/Kali (старији): /var/log/auth.log
#   - RHEL/Fedora/CentOS: /var/log/secure
#   - Модерни systemd системи: journalctl
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from rich.console import Console

console = Console()

# Могуће путање до auth логова.
AUTH_LOG_PATHS = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
    Path("/var/log/auth.log.1"),
    Path("/var/log/secure.1"),
]

# Патерни за различите типове догађаја.
PATTERNS = {
    "successful_login": re.compile(
        r"Accepted\s+(password|publickey|keyboard-interactive)"
        r"\s+for\s+(\S+)\s+from\s+(\S+)"
    ),
    "failed_login": re.compile(
        r"Failed\s+(password|publickey)"
        r"\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
    ),
    "invalid_user": re.compile(
        r"Invalid user\s+(\S+)\s+from\s+(\S+)"
    ),
    "sudo_command": re.compile(
        r"sudo\[\d+\]:\s+(\S+)\s*:.*COMMAND=(.+)"
    ),
    "sudo_failed": re.compile(
        r"sudo\[\d+\]:\s+(\S+)\s*:.*incorrect password"
    ),
    "session_opened": re.compile(
        r"session opened for user\s+(\S+)"
    ),
    "session_closed": re.compile(
        r"session closed for user\s+(\S+)"
    ),
    "connection_closed": re.compile(
        r"Connection closed by\s+(\S+)"
    ),
}

# Максималан број линија које читамо (задњих).
MAX_LINES = 50000

# Максимална дубина ротираних фајлова.
MAX_ROTATED = 3

# Максималан број линија из journal-а.
MAX_JOURNAL_LINES = 10000


def run() -> dict:
    """Анализира auth логове.

    Прво покушава класичне фајлове, онда systemd journal.
    """
    console.print("\n[bold cyan]Authentication logs[/bold cyan]\n")

    # Проналазимо класичне лог фајлове.
    log_files = _find_log_files()

    all_lines = []
    source_type = None

    if log_files:
        # Класични логови.
        source_type = "files"
        for log_path in log_files:
            lines = _read_log_file(log_path)
            for line in lines:
                line["source"] = str(log_path)
            all_lines.extend(lines)

    # Ако нема класичних, користимо journalctl.
    if not all_lines and shutil.which("journalctl"):
        source_type = "journal"
        journal_lines = _read_journal()
        all_lines.extend(journal_lines)

    if not all_lines:
        console.print(
            "  [yellow]No auth logs found.[/yellow]\n"
        )
        console.print(
            "  [dim]Checked: /var/log/auth.log, /var/log/secure, "
            "journalctl[/dim]\n"
        )
        console.print(
            "  [dim]Try running with sudo for full access.[/dim]\n"
        )
        return _empty_result()

    # Анализирамо догађаје.
    events = _parse_events(all_lines)

    # Правимо статистике.
    stats = _make_statistics(events, all_lines)

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
            "successful_logins": len(events["successful_login"]),
            "failed_logins": len(events["failed_login"]),
            "invalid_users": len(events["invalid_user"]),
            "sudo_commands": len(events["sudo_command"]),
            "sudo_failures": len(events["sudo_failed"]),
            "unique_source_ips": len(stats.get("source_ips", [])),
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
        "events": {
            "successful_login": [],
            "failed_login": [],
            "invalid_user": [],
            "sudo_command": [],
            "sudo_failed": [],
        },
        "statistics": {},
        "summary": {
            "successful_logins": 0,
            "failed_logins": 0,
            "invalid_users": 0,
            "sudo_commands": 0,
            "sudo_failures": 0,
            "unique_source_ips": 0,
        },
    }


def _find_log_files() -> list[Path]:
    """Проналази доступне auth лог фајлове.

    Укључује ротиране (.1, .2.gz).
    """
    found = []

    # Прво главни фајлови.
    for path in AUTH_LOG_PATHS:
        if path.exists() and path.is_file():
            found.append(path)

    # Онда ротирани (само ако главни не постоји).
    if not found:
        for base_path in [
            Path("/var/log/auth.log"),
            Path("/var/log/secure"),
        ]:
            for i in range(1, MAX_ROTATED + 1):
                rotated = Path(f"{base_path}.{i}")
                if rotated.exists() and rotated.is_file():
                    found.append(rotated)
                compressed = Path(f"{base_path}.{i}.gz")
                if compressed.exists() and compressed.is_file():
                    found.append(compressed)

    return found


def _read_log_file(path: Path) -> list[dict]:
    """Чита лог фајл.

    За .gz фајлове користимо gzip модул.
    За обичне читамо задњих MAX_LINES линија.
    """
    lines = []

    if not path.exists():
        return lines

    try:
        if path.suffix == ".gz":
            # Читамо компресован фајл.
            import gzip

            with gzip.open(
                path, "rt", encoding="utf-8", errors="replace"
            ) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append({"text": line})

        else:
            # Читамо обичан фајл (задњих MAX_LINES).
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()

            # Узимамо задњих MAX_LINES.
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


def _read_journal() -> list[dict]:
    """Чита auth догађаје из systemd journal.

    Користи journalctl са филтерима за auth догађаје.
    """
    lines = []

    # Команда: journalctl -o short --no-pager -n 10000
    try:
        proc = subprocess.run(
            [
                "journalctl",
                "-o", "short",
                "--no-pager",
                "-n", str(MAX_JOURNAL_LINES),
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

    # Филтрирамо само линије које имају auth/sudo/sshd.
    auth_keywords = (
        "sshd", "sudo", "su:", "login", "systemd-logind",
        "Accepted", "Failed", "Invalid user", "session opened",
        "session closed", "COMMAND=",
    )

    for line in proc.stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        # Проверавамо да ли линија садржи auth кључну реч.
        if not any(kw in line for kw in auth_keywords):
            continue

        lines.append({
            "text": line,
            "source": "journalctl",
        })

    return lines


def _parse_events(lines: list[dict]) -> dict:
    """Парсира лог линије и издваја догађаје."""
    events = {
        "successful_login": [],
        "failed_login": [],
        "invalid_user": [],
        "sudo_command": [],
        "sudo_failed": [],
        "session_opened": [],
        "session_closed": [],
    }

    for line_info in lines:
        text = line_info.get("text", "")
        source = line_info.get("source", "")

        # Успешна пријава.
        match = PATTERNS["successful_login"].search(text)
        if match:
            method = match.group(1)
            user = match.group(2)
            source_ip = match.group(3)

            events["successful_login"].append({
                "user": user,
                "method": method,
                "source_ip": source_ip,
                "raw": text[:200],
                "source": source,
            })
            continue

        # Неуспешна пријава.
        match = PATTERNS["failed_login"].search(text)
        if match:
            method = match.group(1)
            user = match.group(2)
            source_ip = match.group(3)

            events["failed_login"].append({
                "user": user,
                "method": method,
                "source_ip": source_ip,
                "raw": text[:200],
                "source": source,
            })
            continue

        # Невалидан корисник.
        match = PATTERNS["invalid_user"].search(text)
        if match:
            user = match.group(1)
            source_ip = match.group(2)

            events["invalid_user"].append({
                "user": user,
                "source_ip": source_ip,
                "raw": text[:200],
                "source": source,
            })
            continue

        # Sudo команде.
        match = PATTERNS["sudo_command"].search(text)
        if match:
            user = match.group(1)
            command = match.group(2).strip()

            events["sudo_command"].append({
                "user": user,
                "command": command[:200],
                "raw": text[:200],
                "source": source,
            })
            continue

        # Sudo неуспех.
        match = PATTERNS["sudo_failed"].search(text)
        if match:
            user = match.group(1)

            events["sudo_failed"].append({
                "user": user,
                "raw": text[:200],
                "source": source,
            })
            continue

        # Сесија отворена.
        match = PATTERNS["session_opened"].search(text)
        if match:
            user = match.group(1)
            events["session_opened"].append({
                "user": user,
                "raw": text[:200],
                "source": source,
            })

    return events


def _make_statistics(events: dict, lines: list[dict]) -> dict:
    """Прави статистике из догађаја."""
    result = {}

    # Број неуспешних пријава по IP-у.
    failed_ips = Counter()
    for event in events["failed_login"]:
        ip = event.get("source_ip", "")
        if ip:
            failed_ips[ip] += 1

    result["failed_by_ip"] = dict(failed_ips.most_common(20))

    # Број неуспешних пријава по кориснику.
    failed_users = Counter()
    for event in events["failed_login"]:
        user = event.get("user", "")
        if user:
            failed_users[user] += 1

    result["failed_by_user"] = dict(failed_users.most_common(20))

    # Невалидни корисници (често brute force).
    invalid_users = Counter()
    for event in events["invalid_user"]:
        user = event.get("user", "")
        if user:
            invalid_users[user] += 1

    result["invalid_users"] = dict(invalid_users.most_common(20))

    # Успешне пријаве по IP-у.
    success_ips = Counter()
    for event in events["successful_login"]:
        ip = event.get("source_ip", "")
        if ip:
            success_ips[ip] += 1

    result["success_by_ip"] = dict(success_ips.most_common(20))

    # Sudo команде по кориснику.
    sudo_users = Counter()
    for event in events["sudo_command"]:
        user = event.get("user", "")
        if user:
            sudo_users[user] += 1

    result["sudo_by_user"] = dict(sudo_users.most_common(20))

    # Укупан број извора.
    all_ips = set()
    for event_type in events.values():
        for event in event_type:
            ip = event.get("source_ip", "")
            if ip and ip != "":
                all_ips.add(ip)

    result["source_ips"] = list(all_ips)

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    source_type = data.get("source_type", "?")
    log_files = data.get("log_files", [])
    total_lines = data.get("total_lines", 0)
    events = data.get("events", {})
    stats = data.get("statistics", {})
    summary = data.get("summary", {})

    # Основни подаци.
    if source_type == "journal":
        console.print("[bold]Source:[/bold]  systemd journal")
    else:
        console.print("[bold]Log files:[/bold]\n")
        for log_file in log_files:
            console.print(f"  [dim]{log_file}[/dim]")

    console.print()
    console.print(
        f"[bold]Total lines read:[/bold]  {total_lines}"
    )
    console.print()

    # Резиме.
    console.print("[bold]Event summary:[/bold]\n")

    console.print(
        f"  [green]Successful logins:[/green]  "
        f"{summary.get('successful_logins', 0)}"
    )
    console.print(
        f"  [red]Failed logins:[/red]      "
        f"{summary.get('failed_logins', 0)}"
    )
    console.print(
        f"  [yellow]Invalid users:[/yellow]     "
        f"{summary.get('invalid_users', 0)}"
    )
    console.print(
        f"  Sudo commands:        "
        f"{summary.get('sudo_commands', 0)}"
    )

    if summary.get("sudo_failures", 0) > 0:
        console.print(
            f"  [red]Sudo failures:[/red]      "
            f"{summary.get('sudo_failures', 0)}"
        )

    console.print()

    # Ако нема догађаја, објашњавамо.
    total_events = sum(
        len(events.get(k, []))
        for k in (
            "successful_login", "failed_login", "invalid_user",
            "sudo_command", "sudo_failed",
        )
    )

    if total_events == 0:
        console.print(
            "  [dim]No authentication events found in the log source.[/dim]\n"
        )
        return

    # Статистике — неуспешни по IP-у.
    failed_by_ip = stats.get("failed_by_ip", {})

    if failed_by_ip:
        console.print(
            f"[bold red]Failed logins by IP "
            f"({len(failed_by_ip)} unique):[/bold red]\n"
        )

        for ip, count in list(failed_by_ip.items())[:10]:
            # Боја — црвено ако је више од 10 покушаја.
            if count >= 10:
                color = "bold red"
            elif count >= 3:
                color = "yellow"
            else:
                color = "dim"

            console.print(
                f"  [{color}]{ip:20s}[/{color}]  "
                f"{count} attempt(s)"
            )

        console.print()

    # Невалидни корисници (brute force индикатор).
    invalid_users = stats.get("invalid_users", {})

    if invalid_users:
        console.print(
            f"[bold yellow]Invalid users tried "
            f"({len(invalid_users)}):[/bold yellow]\n"
        )

        for user, count in list(invalid_users.items())[:15]:
            console.print(
                f"  {user:25s}  {count} attempt(s)"
            )

        if len(invalid_users) > 15:
            console.print(
                f"  [dim]... and {len(invalid_users) - 15} more[/dim]"
            )

        console.print()

    # Успешне пријаве по IP-у.
    success_by_ip = stats.get("success_by_ip", {})

    if success_by_ip:
        console.print(
            f"[bold green]Successful logins by IP:[/bold green]\n"
        )

        for ip, count in list(success_by_ip.items())[:10]:
            console.print(
                f"  {ip:20s}  {count} login(s)"
            )

        console.print()

    # Sudo команде.
    sudo_commands = events.get("sudo_command", [])

    if sudo_commands:
        console.print(
            f"[bold]Recent sudo commands "
            f"({len(sudo_commands)} total):[/bold]\n"
        )

        for event in sudo_commands[-10:]:
            user = event.get("user", "?")
            command = event.get("command", "")

            if len(command) > 80:
                command = command[:77] + "..."

            console.print(
                f"  [dim]{user:15s}[/dim]  {command}"
            )

        if len(sudo_commands) > 10:
            console.print(
                f"  [dim]... and {len(sudo_commands) - 10} more[/dim]"
            )

        console.print()