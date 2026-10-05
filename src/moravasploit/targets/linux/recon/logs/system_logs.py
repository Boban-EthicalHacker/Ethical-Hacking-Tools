# Модул за анализу системских логова.
# Системски логови садрже kernel поруке, сервисне поруке,
# грешке и упозорења. Откривају проблеме и потенцијалне
# индикаторе компромитовања.
#
# На различитим системима:
#   - Debian/Ubuntu/Kali: /var/log/syslog, /var/log/messages
#   - RHEL/Fedora: /var/log/messages
#   - Модерни systemd: journalctl
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from rich.console import Console

console = Console()

# Могуће путање до системских логова.
SYSTEM_LOG_PATHS = [
    Path("/var/log/syslog"),
    Path("/var/log/messages"),
    Path("/var/log/syslog.1"),
    Path("/var/log/messages.1"),
]

# Патерни за препознавање нивоа озбиљности.
SEVERITY_PATTERNS = {
    "critical": re.compile(
        r"\b(critical|crit|emerg|alert|panic|fatal)\b",
        re.IGNORECASE,
    ),
    "error": re.compile(
        r"\b(error|err|failed|failure|denied|refused)\b",
        re.IGNORECASE,
    ),
    "warning": re.compile(
        r"\b(warning|warn|deprecated)\b",
        re.IGNORECASE,
    ),
}

# Кључне речи које су безбедносно занимљиве.
SECURITY_KEYWORDS = [
    (r"\bsegfault\b", "segfault"),
    (r"\bout of memory\b", "oom"),
    (r"\boom-killer\b", "oom-killer"),
    # "Kernel panic" мора бити експлицитан, не "drm panic".
    (r"\bKernel panic\b", "kernel-panic"),
    (r"\bKernel Panic\b", "kernel-panic"),
    (r"\bapparmor.*denied\b", "apparmor-denied"),
    (r"\bselinux.*denied\b", "selinux-denied"),
    (r"\bsegmentation fault\b", "segfault"),
    (r"\bgeneral protection fault\b", "gp-fault"),
    (r"\bhardware error\b", "hardware-error"),
    (r"\bI/O error\b", "io-error"),
    (r"\bfilesystem.*error\b", "fs-error"),
    (r"\btainted kernel\b", "tainted-kernel"),
    (r"\bBUG:\s", "kernel-bug"),
    (r"\bWARNING:\s", "kernel-warning"),
    # "Call Trace:" је често део warning-а, али и део правих проблема.
    # Захтевамо да буде на крају линије (типичан формат).
    (r"Call Trace:\s*$", "call-trace"),
    (r"\bblocked for more than\b", "blocked-process"),
    (r"\bhung_task\b", "hung-task"),
]
# Компајлирамо патерне за безбедност.
SECURITY_RE = [
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in SECURITY_KEYWORDS
]

# Познати сервиси (за препознавање извора).
KNOWN_SERVICES = [
    "systemd",
    "kernel",
    "NetworkManager",
    "cron",
    "sshd",
    "sudo",
    "dbus",
    "systemd-logind",
    "systemd-resolved",
    "systemd-timesyncd",
    "cupsd",
    "avahi-daemon",
    "wpa_supplicant",
    "dhclient",
    "dhcpcd",
    "firewalld",
    "apparmor",
    "auditd",
    "polkitd",
]

# Максималан број линија које читамо.
MAX_LINES = 50000

# Максималан број линија из journal-а.
MAX_JOURNAL_LINES = 10000

# Максимална дубина ротираних фајлова.
MAX_ROTATED = 3


def run() -> dict:
    """Анализира системске логове.

    Прво покушава класичне фајлове, онда systemd journal.
    """
    console.print("\n[bold cyan]System logs[/bold cyan]\n")

    # Проналазимо класичне лог фајлове.
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

    # Ако нема класичних, користимо journalctl.
    if not all_lines and shutil.which("journalctl"):
        source_type = "journal"
        journal_lines = _read_journal()
        all_lines.extend(journal_lines)

    if not all_lines:
        console.print(
            "  [yellow]No system log files found.[/yellow]\n"
        )
        console.print(
            "  [dim]Checked: /var/log/syslog, /var/log/messages, "
            "journalctl[/dim]\n"
        )
        console.print(
            "  [dim]Try running with sudo for full access.[/dim]\n"
        )
        return _empty_result()

    # Анализирамо догађаје.
    analysis = _analyze_lines(all_lines)

    data = {
        "source_type": source_type,
        "log_files": (
            [str(p) for p in log_files]
            if log_files
            else ["journalctl"]
        ),
        "total_lines": len(all_lines),
        "severity_counts": analysis["severity_counts"],
        "services": analysis["services"],
        "security_findings": analysis["security_findings"],
        "errors": analysis["errors"],
        "warnings": analysis["warnings"],
        "summary": {
            "total_lines": len(all_lines),
            "critical": analysis["severity_counts"].get("critical", 0),
            "errors": analysis["severity_counts"].get("error", 0),
            "warnings": analysis["severity_counts"].get("warning", 0),
            "security_findings": len(analysis["security_findings"]),
            "unique_services": len(analysis["services"]),
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
        "severity_counts": {},
        "services": {},
        "security_findings": [],
        "errors": [],
        "warnings": [],
        "summary": {
            "total_lines": 0,
            "critical": 0,
            "errors": 0,
            "warnings": 0,
            "security_findings": 0,
            "unique_services": 0,
        },
    }


def _find_log_files() -> list[Path]:
    """Проналази доступне системске лог фајлове."""
    found = []

    for path in SYSTEM_LOG_PATHS:
        if path.exists() and path.is_file():
            found.append(path)

    # Ако нема главних, тражимо ротиране.
    if not found:
        for base_path in [
            Path("/var/log/syslog"),
            Path("/var/log/messages"),
        ]:
            for i in range(1, MAX_ROTATED + 1):
                rotated = Path(f"{base_path}.{i}")
                if rotated.exists() and rotated.is_file():
                    found.append(rotated)

    return found


def _read_log_file(path: Path) -> list[dict]:
    """Чита лог фајл."""
    lines = []

    if not path.exists():
        return lines

    try:
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
    """Чита системске догађаје из systemd journal."""
    lines = []

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

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        lines.append({
            "text": line,
            "source": "journalctl",
        })

    return lines


def _analyze_lines(lines: list[dict]) -> dict:
    """Анализира све лог линије."""
    severity_counts = Counter()
    services = Counter()
    security_findings = []
    errors = []
    warnings = []

    for line_info in lines:
        text = line_info.get("text", "")
        source = line_info.get("source", "")

        # Препознајемо сервис.
        service = _detect_service(text)
        if service:
            services[service] += 1

        # Проверавамо озбиљност.
        line_severity = None

        # Проверавамо critical прво, затим error, затим warning.
        if SEVERITY_PATTERNS["critical"].search(text):
            line_severity = "critical"
        elif SEVERITY_PATTERNS["error"].search(text):
            line_severity = "error"
        elif SEVERITY_PATTERNS["warning"].search(text):
            line_severity = "warning"

        if line_severity:
            severity_counts[line_severity] += 1

            entry = {
                "severity": line_severity,
                "text": text[:300],
                "service": service,
                "source": source,
            }

            if line_severity == "critical":
                errors.append(entry)  # критичне идемо у errors
            elif line_severity == "error":
                errors.append(entry)
            else:
                warnings.append(entry)

        # Проверавамо безбедносне кључне речи.
        for pattern, name in SECURITY_RE:
            if pattern.search(text):
                security_findings.append({
                    "type": name,
                    "text": text[:300],
                    "service": service,
                    "source": source,
                })
                break  # само један налаз по линији

    return {
        "severity_counts": dict(severity_counts),
        "services": dict(services.most_common(30)),
        "security_findings": security_findings,
        "errors": errors[-100:],  # задњих 100
        "warnings": warnings[-100:],  # задњих 100
    }


def _detect_service(text: str) -> str | None:
    """Препознаје сервис из лог линије."""
    # Формат journal: "Oct 05 14:48:57 hostname service[PID]: message"
    # Формат syslog: "Oct 05 14:48:57 hostname service[PID]: message"

    for service in KNOWN_SERVICES:
        # Проверавамо да ли се сервис појављује као реч.
        if re.search(rf"\b{re.escape(service)}[\[\s:]", text):
            return service

    # Покушавамо да извучемо име сервиса из формата "name[PID]:".
    match = re.search(r"\s([a-zA-Z][a-zA-Z0-9_\-]+)\[\d+\]:", text)
    if match:
        return match.group(1)

    # Или из формата "name: message".
    match = re.search(r"\s([a-zA-Z][a-zA-Z0-9_\-]{2,}):\s", text)
    if match:
        candidate = match.group(1)
        # Прескачемо hostname-ове и путање.
        if candidate not in ("kernel",) and "/" not in candidate:
            return candidate

    return None


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    source_type = data.get("source_type", "?")
    log_files = data.get("log_files", [])
    total_lines = data.get("total_lines", 0)
    severity = data.get("severity_counts", {})
    services = data.get("services", {})
    security = data.get("security_findings", [])
    errors = data.get("errors", [])
    warnings = data.get("warnings", [])
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

    # Резиме озбиљности.
    console.print("[bold]Severity summary:[/bold]\n")

    if summary.get("critical", 0) > 0:
        console.print(
            f"  [bold red]Critical:[/bold red]  "
            f"{summary['critical']}"
        )
    else:
        console.print("  [green]Critical:[/green]  0")

    if summary.get("errors", 0) > 0:
        console.print(
            f"  [red]Errors:[/red]    {summary['errors']}"
        )
    else:
        console.print("  [green]Errors:[/green]    0")

    if summary.get("warnings", 0) > 0:
        console.print(
            f"  [yellow]Warnings:[/yellow]  {summary['warnings']}"
        )
    else:
        console.print("  [green]Warnings:[/green]  0")

    console.print(
        f"  Services:  {summary.get('unique_services', 0)} unique"
    )
    console.print()

    # Безбедносни налази.
    if security:
        console.print(
            f"[bold red]Security findings "
            f"({len(security)}):[/bold red]\n"
        )

        # Групишемо по типу.
        by_type = Counter()
        for finding in security:
            by_type[finding.get("type", "?")] += 1

        for finding_type, count in by_type.most_common():
            console.print(f"  {finding_type:25s}  {count}")

        console.print()

        # Приказујемо задњих 5 налаза.
        console.print("[bold]Recent security events:[/bold]\n")

        for finding in security[-5:]:
            text = finding.get("text", "")
            if len(text) > 100:
                text = text[:97] + "..."

            console.print(f"  [red]{finding.get('type')}[/red]")
            console.print(f"    [dim]{text}[/dim]")

        console.print()

    # Сервиси (топ 10).
    if services:
        console.print("[bold]Top services:[/bold]\n")

        for service, count in list(services.items())[:10]:
            console.print(
                f"  {service:25s}  {count} message(s)"
            )

        console.print()

    # Грешке.
    if errors:
        console.print(
            f"[bold red]Recent errors "
            f"({len(errors)} total):[/bold red]\n"
        )

        # Приказујемо задњих 10.
        for error in errors[-10:]:
            text = error.get("text", "")
            severity = error.get("severity", "error")

            if len(text) > 100:
                text = text[:97] + "..."

            color = "bold red" if severity == "critical" else "red"

            console.print(
                f"  [{color}]●[/{color}] {text}"
            )

        if len(errors) > 10:
            console.print(
                f"  [dim]... and {len(errors) - 10} more[/dim]"
            )

        console.print()