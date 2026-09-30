# Модул за приказ заказаних задатака (cron jobs).
# Чита системске cron фајлове, drop-in фајлове, периодичне
# директоријуме и корисничке crontab-ове.
# Cron је чест пут за persistence — нападачи воле да ставе
# задатак који се покреће сваки минут/сат.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до cron конфигурације.
SYSTEM_CRONTAB = Path("/etc/crontab")
CRON_D_DIR = Path("/etc/cron.d")
CRON_PERIODIC_DIRS = {
    "hourly": Path("/etc/cron.hourly"),
    "daily": Path("/etc/cron.daily"),
    "weekly": Path("/etc/cron.weekly"),
    "monthly": Path("/etc/cron.monthly"),
}
USER_CRONTAB_DIRS = [
    Path("/var/spool/cron/crontabs"),  # Debian/Ubuntu/Kali
    Path("/var/spool/cron"),           # RHEL/Fedora
]

# Патерни који указују на сумњиве cron задатке.
SUSPICIOUS_PATTERNS = [
    (r"/tmp/", "executes from /tmp"),
    (r"/var/tmp/", "executes from /var/tmp"),
    (r"/dev/shm/", "executes from /dev/shm"),
    (r"curl\s+.*\|\s*(ba)?sh", "pipe from curl to shell"),
    (r"wget\s+.*\|\s*(ba)?sh", "pipe from wget to shell"),
    (r"base64\s+-d", "decodes base64 (obfuscation)"),
    (r"nc\s+-[el]", "netcat listener"),
    (r"ncat\s+", "ncat usage"),
    (r"/bin/(ba)?sh\s+-i", "reverse shell"),
    (r"python.*socket.*connect", "python reverse shell"),
    (r"perl.*socket", "perl reverse shell"),
    (r"bash\s+-c\s+.*>", "bash redirection to external"),
    (r"\bnc\b.*\d+\.\d+\.\d+\.\d+", "netcat to IP address"),
]

# Компајлирамо патерне.
SUSPICIOUS_RE = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in SUSPICIOUS_PATTERNS
]


def run() -> dict:
    """Приказује cron задатке.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Cron jobs[/bold cyan]\n")

    # Читамо све изворе.
    system_crontab = _read_system_crontab()
    cron_d = _read_cron_d()
    periodic = _read_periodic_dirs()
    user_crontabs = _read_user_crontabs()

    # Спајамо све задатке.
    all_jobs = (
        system_crontab.get("jobs", [])
        + _collect_jobs_from_list(cron_d)
        + _collect_jobs_from_periodic(periodic)
        + _collect_jobs_from_users(user_crontabs)
    )

    # Тражимо сумњиве.
    suspicious = _find_suspicious(all_jobs)

    data = {
        "system_crontab": system_crontab,
        "cron_d": cron_d,
        "periodic": periodic,
        "user_crontabs": user_crontabs,
        "suspicious": suspicious,
        "summary": {
            "total_jobs": len(all_jobs),
            "suspicious_count": len(suspicious),
            "sources": {
                "system_crontab": len(system_crontab.get("jobs", [])),
                "cron_d": len(_collect_jobs_from_list(cron_d)),
                "periodic": len(_collect_jobs_from_periodic(periodic)),
                "user_crontabs": len(_collect_jobs_from_users(user_crontabs)),
            },
        },
    }

    _print_data(data)

    return data


def _read_system_crontab() -> dict:
    """Чита /etc/crontab."""
    result = {
        "path": str(SYSTEM_CRONTAB),
        "readable": False,
        "jobs": [],
    }

    if not SYSTEM_CRONTAB.exists():
        return result

    try:
        content = SYSTEM_CRONTAB.read_text(encoding="utf-8", errors="replace")
        result["readable"] = True
    except (PermissionError, Exception):
        return result

    result["jobs"] = _parse_crontab_content(content, str(SYSTEM_CRONTAB))

    return result


def _read_cron_d() -> list[dict]:
    """Чита /etc/cron.d/."""
    files = []

    if not CRON_D_DIR.exists() or not CRON_D_DIR.is_dir():
        return files

    try:
        entries = sorted(CRON_D_DIR.iterdir())
    except (PermissionError, Exception):
        return files

    for file_path in entries:
        if not file_path.is_file():
            continue

        # Прескачемо backup фајлове и скривене.
        name = file_path.name
        if name.startswith(".") or name.endswith("~"):
            continue

        try:
            content = file_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except (PermissionError, Exception):
            continue

        jobs = _parse_crontab_content(content, str(file_path))

        files.append({
            "path": str(file_path),
            "name": name,
            "jobs": jobs,
        })

    return files


def _read_periodic_dirs() -> dict:
    """Чита периодичне cron директоријуме."""
    result = {}

    for period, path in CRON_PERIODIC_DIRS.items():
        scripts = []

        if not path.exists() or not path.is_dir():
            result[period] = {"path": str(path), "scripts": []}
            continue

        try:
            entries = sorted(path.iterdir())
        except (PermissionError, Exception):
            entries = []

        for file_path in entries:
            if not file_path.is_file():
                continue

            name = file_path.name
            if name.startswith("."):
                continue

            try:
                st = file_path.stat()
                scripts.append({
                    "name": name,
                    "path": str(file_path),
                    "size_bytes": st.st_size,
                    "executable": bool(st.st_mode & 0o111),
                })
            except Exception:
                continue

        result[period] = {
            "path": str(path),
            "scripts": scripts,
        }

    return result


def _read_user_crontabs() -> list[dict]:
    """Чита корисничке crontab-ове."""
    crontabs = []

    for base_dir in USER_CRONTAB_DIRS:
        if not base_dir.exists() or not base_dir.is_dir():
            continue

        try:
            entries = sorted(base_dir.iterdir())
        except (PermissionError, Exception):
            continue

        for file_path in entries:
            if not file_path.is_file():
                continue

            name = file_path.name
            # Прескачемо празне или скривене.
            if name.startswith("."):
                continue

            try:
                content = file_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except (PermissionError, Exception):
                continue

            jobs = _parse_crontab_content(content, str(file_path))

            crontabs.append({
                "user": name,
                "path": str(file_path),
                "jobs": jobs,
            })

    return crontabs


def _parse_crontab_content(content: str, source: str) -> list[dict]:
    """Парсира crontab садржај.

    Формат (/etc/crontab):
        m h dom mon dow user command
    Формат (user crontab):
        m h dom mon dow command
    """
    jobs = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_stripped = line.strip()

        if not line_stripped or line_stripped.startswith("#"):
            continue

        # Прескачемо поставке околине (VAR=value).
        if re.match(r"^[A-Z_]+=", line_stripped):
            continue

        # Прескачемо @reboot, @daily, итд. — обрадићемо их посебно.
        if line_stripped.startswith("@"):
            jobs.append({
                "schedule": line_stripped.split()[0],
                "user": None,
                "command": " ".join(line_stripped.split()[1:]),
                "source": source,
                "line_number": line_number,
                "raw": line_stripped,
            })
            continue

        parts = line_stripped.split()

        # Треба нам бар 6 делова за системски crontab.
        if len(parts) < 6:
            continue

        # Првих 5 су распоред.
        schedule = " ".join(parts[:5])

        # Шести део је корисник (за системски crontab).
        # За корисничке crontab-ове, шести део је команда.
        # Разликујемо по томе да ли је /etc/crontab или /etc/cron.d.
        is_system = "/etc/crontab" in source or "/etc/cron.d/" in source

        if is_system:
            user = parts[5]
            command = " ".join(parts[6:])
        else:
            user = None
            command = " ".join(parts[5:])

        jobs.append({
            "schedule": schedule,
            "user": user,
            "command": command,
            "source": source,
            "line_number": line_number,
            "raw": line_stripped,
        })

    return jobs


def _collect_jobs_from_list(files: list[dict]) -> list[dict]:
    """Скупља све задатке из листе фајлова."""
    jobs = []
    for file_entry in files:
        for job in file_entry.get("jobs", []):
            jobs.append(job)
    return jobs


def _collect_jobs_from_periodic(periodic: dict) -> list[dict]:
    """Претвара периодичне скрипте у "задатке"."""
    jobs = []

    for period, data in periodic.items():
        for script in data.get("scripts", []):
            jobs.append({
                "schedule": f"@{period}",
                "user": "root (via run-parts)",
                "command": script["path"],
                "source": data["path"],
                "line_number": None,
                "raw": script["name"],
            })

    return jobs


def _collect_jobs_from_users(users: list[dict]) -> list[dict]:
    """Скупља задатке из корисничких crontab-ова."""
    jobs = []
    for user_entry in users:
        for job in user_entry.get("jobs", []):
            # Додајемо корисника ако већ није.
            if not job.get("user"):
                job["user"] = user_entry.get("user")
            jobs.append(job)
    return jobs


def _find_suspicious(jobs: list[dict]) -> list[dict]:
    """Проналази сумњиве cron задатке."""
    suspicious = []

    for job in jobs:
        command = job.get("command", "")
        raw = job.get("raw", "")

        for pattern, description in SUSPICIOUS_RE:
            if pattern.search(command) or pattern.search(raw):
                suspicious.append({
                    "source": job.get("source", "?"),
                    "line_number": job.get("line_number"),
                    "user": job.get("user"),
                    "schedule": job.get("schedule"),
                    "command": command[:200],
                    "reason": description,
                })
                break

    return suspicious


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    suspicious = data.get("suspicious", [])
    system_crontab = data.get("system_crontab", {})
    cron_d = data.get("cron_d", [])
    periodic = data.get("periodic", {})
    user_crontabs = data.get("user_crontabs", [])

    console.print(
        f"[bold]Total cron jobs:[/bold]   "
        f"{summary.get('total_jobs', 0)}"
    )

    sources = summary.get("sources", {})
    console.print(
        f"  /etc/crontab:       {sources.get('system_crontab', 0)}"
    )
    console.print(
        f"  /etc/cron.d/:       {sources.get('cron_d', 0)}"
    )
    console.print(
        f"  Periodic dirs:      {sources.get('periodic', 0)}"
    )
    console.print(
        f"  User crontabs:      {sources.get('user_crontabs', 0)}"
    )

    if suspicious:
        console.print(
            f"  [bold red]Suspicious:[/bold red]         "
            f"{summary.get('suspicious_count', 0)}"
        )

    console.print()

    # Сумњиви прво.
    if suspicious:
        console.print(
            f"[bold red]Suspicious findings ({len(suspicious)}):[/bold red]\n"
        )
        for item in suspicious:
            _print_suspicious(item)
        console.print()

    # /etc/crontab
    system_jobs = system_crontab.get("jobs", [])
    if system_jobs:
        console.print(
            f"[bold cyan]/etc/crontab ({len(system_jobs)} jobs)[/bold cyan]\n"
        )
        for job in system_jobs:
            _print_job(job)
        console.print()

    # /etc/cron.d/
    if cron_d:
        total = sum(len(f.get("jobs", [])) for f in cron_d)
        console.print(
            f"[bold cyan]/etc/cron.d/ "
            f"({len(cron_d)} files, {total} jobs)[/bold cyan]\n"
        )
        for file_entry in cron_d:
            jobs = file_entry.get("jobs", [])
            if not jobs:
                continue
            console.print(f"  [dim]{file_entry['name']}:[/dim]")
            for job in jobs:
                _print_job(job, indent=4)
        console.print()

    # Периодични директоријуми.
    has_periodic = any(
        data.get("scripts") for data in periodic.values()
    )
    if has_periodic:
        console.print("[bold cyan]Periodic directories[/bold cyan]\n")
        for period, pdata in periodic.items():
            scripts = pdata.get("scripts", [])
            if not scripts:
                continue

            console.print(
                f"  [bold]@ {period}:[/bold]  "
                f"{len(scripts)} script(s)"
            )
            for script in scripts[:5]:
                executable = (
                    "[green]exec[/green]"
                    if script["executable"]
                    else "[dim]noexec[/dim]"
                )
                console.print(
                    f"    {script['name']}  {executable}"
                )
            if len(scripts) > 5:
                console.print(
                    f"    [dim]... and {len(scripts) - 5} more[/dim]"
                )
        console.print()

    # Кориснички crontab-ови.
    if user_crontabs:
        console.print(
            f"[bold cyan]User crontabs ({len(user_crontabs)})[/bold cyan]\n"
        )
        for entry in user_crontabs:
            jobs = entry.get("jobs", [])
            if not jobs:
                continue
            console.print(f"  [bold]{entry['user']}:[/bold]")
            for job in jobs:
                _print_job(job, indent=4)
        console.print()

    # Ако нема ничега.
    if summary.get("total_jobs", 0) == 0:
        console.print("  [dim]No cron jobs found.[/dim]\n")


def _print_suspicious(item: dict) -> None:
    """Приказује један сумњив задатак."""
    console.print(
        f"  [bold red]●[/bold red] "
        f"[yellow]{item['reason']}[/yellow]"
    )
    console.print(
        f"    Source:   [dim]{item['source']}:"
        f"{item.get('line_number', '?')}[/dim]"
    )
    if item.get("user"):
        console.print(f"    User:     {item['user']}")
    console.print(f"    Schedule: {item.get('schedule', '?')}")
    console.print(
        f"    Command:  [dim]{item['command']}[/dim]"
    )
    console.print()


def _print_job(job: dict, indent: int = 2) -> None:
    """Приказује један cron задатак."""
    schedule = job.get("schedule", "?")
    user = job.get("user")
    command = job.get("command", "")

    # Скраћујемо команду.
    if len(command) > 70:
        command = command[:67] + "..."

    prefix = " " * indent

    if user:
        console.print(
            f"{prefix}[dim]{schedule:20s}[/dim]  "
            f"[cyan]{user:10s}[/cyan]  {command}"
        )
    else:
        console.print(
            f"{prefix}[dim]{schedule:20s}[/dim]  {command}"
        )