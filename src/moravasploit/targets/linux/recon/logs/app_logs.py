# Модул за анализу логова апликација.
# Покрива web сервере, базе података, mail и FTP сервере.
# Web access логови су посебно важни — откривају покушаје
# напада (SQL injection, XSS, path traversal).
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
from collections import Counter
from pathlib import Path

from rich.console import Console

console = Console()

# Дефиниције апликационих логова по категоријама.
# Формат: категорија -> [(путања, опис)]
APP_LOGS = {
    "Web servers": [
        (Path("/var/log/apache2/access.log"), "Apache access log"),
        (Path("/var/log/apache2/error.log"), "Apache error log"),
        (Path("/var/log/apache2/other_vhosts_access.log"), "Apache vhosts"),
        (Path("/var/log/nginx/access.log"), "Nginx access log"),
        (Path("/var/log/nginx/error.log"), "Nginx error log"),
        (Path("/var/log/httpd/access_log"), "httpd access log"),
        (Path("/var/log/httpd/error_log"), "httpd error log"),
    ],
    "Databases": [
        (Path("/var/log/mysql/error.log"), "MySQL error log"),
        (Path("/var/log/mysql/mysql-slow.log"), "MySQL slow queries"),
        (Path("/var/log/mariadb/mariadb.log"), "MariaDB log"),
        (Path("/var/log/postgresql"), "PostgreSQL logs dir"),
    ],
    "Mail": [
        (Path("/var/log/mail.log"), "Mail log"),
        (Path("/var/log/maillog"), "Mail log (RHEL)"),
        (Path("/var/log/mail.err"), "Mail errors"),
    ],
    "FTP": [
        (Path("/var/log/vsftpd.log"), "vsftpd log"),
        (Path("/var/log/pure-ftpd/transfer.log"), "Pure-FTPd log"),
    ],
    "Other services": [
        (Path("/var/log/samba/log.smbd"), "Samba log"),
        (Path("/var/log/cups/access_log"), "CUPS access log"),
        (Path("/var/log/cups/error_log"), "CUPS error log"),
        (Path("/var/log/dpkg.log"), "DPKG package log"),
        (Path("/var/log/apt/history.log"), "APT history"),
    ],
}

# Патерни за сумњиве web захтеве.
SUSPICIOUS_WEB_PATTERNS = [
    # SQL injection
    (r"(?:union\s+(?:all\s+)?select|select\s+.*\s+from|insert\s+into|drop\s+table)",
     "SQL injection"),
    (r"(?:'|\")\s*(?:or|and)\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+",
     "SQL injection (classic)"),
    (r"\b(?:sleep|benchmark|waitfor\s+delay)\s*\(",
     "SQL injection (time-based)"),

    # XSS
    (r"<script[^>]*>", "XSS (script tag)"),
    (r"javascript:\s*", "XSS (javascript URI)"),
    (r"on(?:load|error|click|mouseover)\s*=", "XSS (event handler)"),

    # Path traversal
    (r"\.\./\.\./", "Path traversal"),
    (r"%2e%2e%2f", "Path traversal (encoded)"),
    (r"/etc/passwd", "Attempt to read /etc/passwd"),
    (r"/etc/shadow", "Attempt to read /etc/shadow"),
    (r"/proc/self/environ", "Attempt to read /proc/self/environ"),

    # Command injection
    (r"(?:;|\||`)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc)\b",
     "Command injection"),

    # Local/Remote File Inclusion
    (r"(?:file|page|include|inc|path|doc)=(?:https?|ftp|php|data):",
     "File inclusion"),
    (r"(?:file|page)=(?:/etc/|/var/|/proc/|/root/)", "Local file inclusion"),

    # Web shells
    (r"(?:eval|system|exec|passthru|shell_exec|popen)\s*\(",
     "PHP code execution"),
    (r"\.php\?.*=.*(?:base64|eval)", "PHP web shell attempt"),

    # Admin panel probing
    (r"/(?:wp-admin|wp-login|phpmyadmin|pma|adminer|mysqladmin)",
     "Admin panel probe"),
    (r"/(?:\.env|\.git|\.htaccess|\.svn|\.ssh)",
     "Config file probe"),

    # Shell upload
    (r"\.(?:php|asp|aspx|jsp|cgi)$", "Script file access"),
]

# Компајлирамо патерне.
SUSPICIOUS_WEB_RE = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in SUSPICIOUS_WEB_PATTERNS
]

# Максималан број линија које читамо по фајлу.
MAX_LINES = 10000

# Максимална величина фајла који читамо (у бајтовима).
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def run() -> dict:
    """Анализира логове апликација.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Application logs[/bold cyan]\n")

    # Проналазимо све доступне логове.
    found_logs = _find_logs()

    if not found_logs:
        console.print(
            "  [yellow]No application logs found.[/yellow]\n"
        )
        return _empty_result()

    # Анализирамо web логове за сумњиве захтеве.
    web_findings = _analyze_web_logs(found_logs)

    # Правимо резиме.
    summary = _make_summary(found_logs, web_findings)

    data = {
        "categories": found_logs,
        "web_findings": web_findings,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "categories": {},
        "web_findings": [],
        "summary": {
            "total_files": 0,
            "readable": 0,
            "total_size_bytes": 0,
            "web_findings": 0,
        },
    }


def _find_logs() -> dict:
    """Проналази све постојеће логове.

    Враћа речник: категорија -> листа логова.
    """
    found = {}

    for category, logs in APP_LOGS.items():
        category_logs = []

        for path, description in logs:
            if not path.exists():
                continue

            if path.is_dir():
                # Директоријум (нпр. PostgreSQL).
                dir_logs = _scan_log_dir(path, description)
                category_logs.extend(dir_logs)
            else:
                # Појединачначан фајл.
                log_info = _analyze_log_file(path, description)
                if log_info:
                    category_logs.append(log_info)

        if category_logs:
            found[category] = category_logs

    return found


def _scan_log_dir(dir_path: Path, description: str) -> list[dict]:
    """Претражује директоријум са логовима."""
    result = []

    try:
        entries = sorted(dir_path.iterdir())
    except (PermissionError, Exception):
        return result

    for entry in entries:
        if not entry.is_file():
            continue

        # Приказујемо само .log фајлове и обичне фајлове без екстензије.
        name = entry.name
        if not (name.endswith(".log") or "." not in name):
            continue

        log_info = _analyze_log_file(
            entry, f"{description}: {name}"
        )
        if log_info:
            result.append(log_info)

    return result


def _analyze_log_file(path: Path, description: str) -> dict | None:
    """Анализира један лог фајл."""
    try:
        st = path.stat()
    except (OSError, PermissionError):
        return None

    info = {
        "path": str(path),
        "description": description,
        "size_bytes": st.st_size,
        "readable": False,
        "total_lines": 0,
        "error_count": 0,
        "warning_count": 0,
        "sample_errors": [],
    }

    # Проверавамо величину.
    if st.st_size > MAX_FILE_SIZE:
        info["note"] = "File too large to analyze"
        return info

    # Читамо фајл.
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (PermissionError, Exception):
        return info

    info["readable"] = True
    info["total_lines"] = len(lines)

    # Узимамо задњих MAX_LINES за анализу.
    recent = lines[-MAX_LINES:] if len(lines) > MAX_LINES else lines

    # Бројимо грешке и упозорења.
    error_re = re.compile(
        r"\b(error|failed|failure|denied|refused|fatal|critical)\b",
        re.IGNORECASE,
    )
    warning_re = re.compile(
        r"\b(warning|warn)\b",
        re.IGNORECASE,
    )

    error_samples = []

    for line in recent:
        line_stripped = line.strip()

        if error_re.search(line_stripped):
            info["error_count"] += 1
            if len(error_samples) < 3:
                error_samples.append(line_stripped[:200])
        elif warning_re.search(line_stripped):
            info["warning_count"] += 1

    info["sample_errors"] = error_samples

    return info


def _analyze_web_logs(categories: dict) -> list[dict]:
    """Анализира web логове за сумњиве захтеве."""
    findings = []

    web_logs = categories.get("Web servers", [])

    for log_info in web_logs:
        # Анализирамо само access логове.
        description = log_info.get("description", "").lower()
        if "access" not in description and "vhost" not in description:
            continue

        path = log_info.get("path", "")

        if not log_info.get("readable"):
            continue

        # Читамо лог.
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (PermissionError, Exception):
            continue

        # Узимамо задњих MAX_LINES.
        recent = lines[-MAX_LINES:] if len(lines) > MAX_LINES else lines

        # Тражимо сумњиве захтеве.
        log_findings = _scan_web_log_for_attacks(recent, path)

        findings.extend(log_findings)

    return findings


def _scan_web_log_for_attacks(lines: list, source: str) -> list[dict]:
    """Тражи сумњиве захтеве у web access логу."""
    findings = []
    seen = set()

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()

        if not line:
            continue

        # Проверавамо сваки патерн.
        for pattern, description in SUSPICIOUS_WEB_RE:
            if pattern.search(line):
                # Избегавамо дупликате (исти pattern + IP).
                ip = _extract_ip(line)
                key = (description, ip)

                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "type": description,
                    "ip": ip,
                    "line": line[:300],
                    "source": source,
                })
                break  # један налаз по линији

    return findings


def _extract_ip(line: str) -> str:
    """Извлачи IP адресу из web лог линије.

    Формат: "IP - - [date] ..."
    """
    match = re.match(r"^(\d+\.\d+\.\d+\.\d+|[\da-f:]+)", line)
    if match:
        return match.group(1)
    return "unknown"


def _make_summary(categories: dict, findings: list[dict]) -> dict:
    """Прави резиме."""
    total_files = 0
    readable = 0
    total_size = 0

    for cat_logs in categories.values():
        for log_info in cat_logs:
            total_files += 1
            if log_info.get("readable"):
                readable += 1
            total_size += log_info.get("size_bytes", 0)

    return {
        "total_files": total_files,
        "readable": readable,
        "total_size_bytes": total_size,
        "web_findings": len(findings),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    categories = data.get("categories", {})
    web_findings = data.get("web_findings", [])
    summary = data.get("summary", {})

    if not categories:
        console.print(
            "  [dim]No application logs found.[/dim]\n"
        )
        return

    # Резиме.
    console.print(
        f"[bold]Log files found:[/bold]     "
        f"{summary.get('total_files', 0)}"
    )
    console.print(
        f"[bold]Readable:[/bold]            "
        f"{summary.get('readable', 0)}"
    )

    if web_findings:
        console.print(
            f"[bold red]Web attack attempts:[/bold red]  "
            f"{summary.get('web_findings', 0)}"
        )

    console.print()

    # Web findings прво.
    if web_findings:
        _print_web_findings(web_findings)

    # По категоријама.
    for category, cat_logs in categories.items():
        _print_category(category, cat_logs)


def _print_web_findings(findings: list[dict]) -> None:
    """Приказује сумњиве web захтеве."""
    console.print(
        f"[bold red]Web attack attempts "
        f"({len(findings)}):[/bold red]\n"
    )

    # Групишемо по типу.
    by_type = Counter()
    by_ip = Counter()

    for finding in findings:
        by_type[finding.get("type", "?")] += 1
        ip = finding.get("ip", "unknown")
        if ip != "unknown":
            by_ip[ip] += 1

    # По типу.
    console.print("[bold]By attack type:[/bold]\n")

    for attack_type, count in by_type.most_common():
        console.print(
            f"  [red]{attack_type:35s}[/red]  {count}"
        )

    console.print()

    # По IP-у (топ 10).
    if by_ip:
        console.print("[bold]By source IP:[/bold]\n")

        for ip, count in by_ip.most_common(10):
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

    # Приказујемо задњих 5 налаза.
    console.print("[bold]Recent examples:[/bold]\n")

    for finding in findings[-5:]:
        attack_type = finding.get("type", "?")
        ip = finding.get("ip", "?")
        line = finding.get("line", "")

        if len(line) > 100:
            line = line[:97] + "..."

        console.print(
            f"  [red]{attack_type}[/red]  "
            f"[dim]from {ip}[/dim]"
        )
        console.print(f"    [dim]{line}[/dim]")

    console.print()


def _print_category(category: str, logs: list[dict]) -> None:
    """Приказује логове једне категорије."""
    console.print(
        f"[bold cyan]{category} ({len(logs)})[/bold cyan]\n"
    )

    for log_info in logs:
        _print_log(log_info)


def _print_log(log_info: dict) -> None:
    """Приказује један лог фајл."""
    path = log_info.get("path", "?")
    description = log_info.get("description", "")
    size = log_info.get("size_bytes", 0)
    readable = log_info.get("readable", False)
    total_lines = log_info.get("total_lines", 0)
    errors = log_info.get("error_count", 0)
    warnings = log_info.get("warning_count", 0)

    # Форматирамо величину.
    size_str = _format_size(size)

    # Име фајла.
    name = Path(path).name

    if not readable:
        console.print(
            f"  [dim]{name}[/dim]  "
            f"[yellow](not readable, {size_str})[/yellow]"
        )
        return

    # Боја за грешке.
    if errors > 100:
        error_color = "bold red"
    elif errors > 10:
        error_color = "red"
    elif errors > 0:
        error_color = "yellow"
    else:
        error_color = "green"

    console.print(
        f"  [bold]{name}[/bold]  "
        f"[dim]({size_str}, {total_lines} lines)[/dim]"
    )

    # Ако има грешке, приказујемо их.
    if errors > 0:
        console.print(
            f"    [{error_color}]errors: {errors}[/{error_color}]  "
            f"[yellow]warnings: {warnings}[/yellow]"
        )
    elif warnings > 0:
        console.print(
            f"    [green]errors: 0[/green]  "
            f"[yellow]warnings: {warnings}[/yellow]"
        )

    console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"