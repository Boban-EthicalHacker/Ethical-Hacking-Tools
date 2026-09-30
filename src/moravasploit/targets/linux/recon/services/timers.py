# Модул за приказ systemd timers.
# Systemd timers су модерна замена за cron. Покрећу сервисе
# на основу времена или догађаја. Све више persistence
# механизама иде преко timers уместо cron-а.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми са systemd timer фајловима.
SYSTEMD_DIRS = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
]

# Патерни који указују на сумњиве timer јединице.
SUSPICIOUS_PATTERNS = [
    (r"/tmp/", "executes from /tmp"),
    (r"/var/tmp/", "executes from /var/tmp"),
    (r"/dev/shm/", "executes from /dev/shm"),
    (r"curl\s+.*\|\s*(ba)?sh", "pipe from curl to shell"),
    (r"wget\s+.*\|\s*(ba)?sh", "pipe from wget to shell"),
    (r"base64\s+-d", "decodes base64 (obfuscation)"),
    (r"/bin/(ba)?sh\s+-i", "reverse shell"),
]

# Компајлирамо патерне.
SUSPICIOUS_RE = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in SUSPICIOUS_PATTERNS
]


def run() -> dict:
    """Приказује systemd timers.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Systemd timers[/bold cyan]\n")

    # Проверавамо да ли systemctl постоји.
    if not shutil.which("systemctl"):
        console.print(
            "  [yellow]systemctl not found. "
            "This system may not use systemd.[/yellow]\n"
        )
        return _empty_result()

    # Читамо timers.
    timers = _read_timers()

    if not timers:
        console.print(
            "  [dim]No timers found or unable to query.[/dim]\n"
        )
        return _empty_result()

    # Проналазимо сумњиве.
    suspicious = _find_suspicious(timers)

    # Правимо резиме.
    summary = _make_summary(timers, suspicious)

    data = {
        "timers": timers,
        "suspicious": suspicious,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "timers": [],
        "suspicious": [],
        "summary": {
            "total": 0,
            "active": 0,
            "suspicious_count": 0,
        },
    }


def _read_timers() -> list[dict]:
    """Чита све systemd timers."""
    # Прва опција — systemctl list-timers.
    timers = _read_with_systemctl()

    # Ако није успело, читамо директно из фајлова.
    if not timers:
        timers = _read_timer_files()

    return timers


def _read_with_systemctl() -> list[dict]:
    """Чита timers помоћу `systemctl list-timers --all`."""
    try:
        proc = subprocess.run(
            [
                "systemctl", "list-timers",
                "--all",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    output = proc.stdout
    if not output:
        return []

    return _parse_systemctl_output(output)


def _parse_systemctl_output(output: str) -> list[dict]:
    """Парсира излаз `systemctl list-timers`.

    Пример:
        NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
        Thu 2026-10-01 01:00:00 CEST 5min          Thu 2026-10-01 00:00:00 CEST 55min ago    logrotate.timer              logrotate.service
    """
    timers = []
    lines = output.splitlines()

    # Прескачемо заглавље (прва линија).
    for line in lines[1:]:
        line = line.rstrip()
        if not line.strip():
            continue

        # Прескачемо footer ("X timers listed.").
        if re.match(r"^\d+\s+timers?\s+listed", line.strip()):
            continue
        if "timers listed" in line.lower():
            continue

        parsed = _parse_timer_line(line)
        if parsed:
            timers.append(parsed)

    return timers


def _parse_timer_line(line: str) -> dict | None:
    """Парсира једну линију из `systemctl list-timers`.

    Колоне могу бити празне (нпр. NEXT може бити "n/a").
    Користимо regex да ухватимо датумске обрасце.
    """
    # Типичан формат има 6 колона.
    # Користимо regex да ухватимо "UNIT" и "ACTIVATES" на крају.
    # Прво налазимо .timer и .service имена.
    timer_match = re.search(r"(\S+\.timer)", line)
    service_match = re.search(r"(\S+\.service)", line)

    if not timer_match:
        return None

    unit = timer_match.group(1)
    activates = service_match.group(1) if service_match else None

    # Скраћујемо — узимамо део пре .timer имена за парсирање времена.
    prefix = line[:timer_match.start()].strip()

    # Парсирамо NEXT, LEFT, LAST, PASSED.
    # Формат: "Thu 2026-10-01 01:00:00 CEST 5min Thu 2026-10-01 00:00:00 CEST 55min ago"
    # Или кратак: "n/a n/a n/a n/a"
    next_time = None
    left = None
    last_time = None
    passed = None

    # Проверавамо да ли је "n/a".
    if prefix.strip() == "n/a n/a n/a n/a" or prefix.strip() == "":
        # Нема активног времена.
        pass
    else:
        # Regex за датум: "Day YYYY-MM-DD HH:MM:SS TZ"
        date_re = re.compile(
            r"(?:[A-Z][a-z]{2}\s+)?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
        )
        dates = date_re.findall(prefix)

        if len(dates) >= 1:
            next_time = dates[0]
        if len(dates) >= 2:
            last_time = dates[1]

        # LEFT и PASSED су између датума.
        # Ово је грубо, али довољно за приказ.
        time_parts = re.findall(
            r"(\d+(?:min|h|s|days?|hours?|minutes?|seconds?)(?:\s+ago)?)",
            prefix,
        )
        if len(time_parts) >= 1:
            left = time_parts[0]
        if len(time_parts) >= 2:
            passed = time_parts[1]

    return {
        "unit": unit,
        "name": unit.replace(".timer", ""),
        "activates": activates,
        "next_run": next_time,
        "time_left": left,
        "last_run": last_time,
        "time_passed": passed,
        "active": next_time is not None,
    }


def _read_timer_files() -> list[dict]:
    """Чита .timer фајлове директно (fallback)."""
    timers = []
    seen = set()

    for base_dir in SYSTEMD_DIRS:
        if not base_dir.exists() or not base_dir.is_dir():
            continue

        try:
            entries = sorted(base_dir.iterdir())
        except (PermissionError, Exception):
            continue

        for file_path in entries:
            if not file_path.is_file():
                continue
            if not file_path.name.endswith(".timer"):
                continue

            # Избегавамо дупликате.
            if file_path.name in seen:
                continue
            seen.add(file_path.name)

            timers.append({
                "unit": file_path.name,
                "name": file_path.name.replace(".timer", ""),
                "activates": None,
                "next_run": None,
                "time_left": None,
                "last_run": None,
                "time_passed": None,
                "active": False,
                "source_file": str(file_path),
            })

    return timers


def _find_suspicious(timers: list[dict]) -> list[dict]:
    """Проналази сумњиве timers.

    Проверавамо:
        - сам timer фајл (име)
        - сервис који покреће (activates)
    """
    suspicious = []

    for timer in timers:
        unit = timer.get("unit", "")
        activates = timer.get("activates") or ""

        # Проверавамо патерне у имену и у сервису који покреће.
        combined = f"{unit} {activates}"

        for pattern, description in SUSPICIOUS_RE:
            if pattern.search(combined):
                suspicious.append({
                    "unit": unit,
                    "activates": activates,
                    "reason": description,
                    "severity": "red",
                })
                break

    return suspicious


def _make_summary(
    timers: list[dict], suspicious: list[dict]
) -> dict:
    """Прави резиме."""
    active = [t for t in timers if t.get("active")]

    return {
        "total": len(timers),
        "active": len(active),
        "suspicious_count": len(suspicious),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    timers = data.get("timers", [])
    suspicious = data.get("suspicious", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total timers:[/bold]     {summary.get('total', 0)}"
    )
    console.print(
        f"  [green]Active:[/green]         {summary.get('active', 0)}"
    )

    if suspicious:
        console.print(
            f"  [bold red]Suspicious:[/bold red]     "
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
                f"[yellow]{item['unit']}[/yellow]  "
                f"[dim]({item['reason']})[/dim]"
            )
            if item.get("activates"):
                console.print(
                    f"    Activates: {item['activates']}"
                )
        console.print()

    # Приказујемо активне timers.
    active = [t for t in timers if t.get("active")]
    if active:
        console.print(
            f"[bold]Active timers ({len(active)}):[/bold]\n"
        )
        console.print(
            f"  {'NEXT RUN':20s}  {'LEFT':10s}  "
            f"{'UNIT':30s}  ACTIVATES"
        )

        # Сортирамо по next_run (најближи први).
        sorted_active = sorted(
            active,
            key=lambda x: x.get("next_run") or "9999",
        )

        for timer in sorted_active:
            _print_timer(timer)

        console.print()

    # Приказујемо неактивне timers (само број).
    inactive = [t for t in timers if not t.get("active")]
    if inactive:
        console.print(
            f"[bold]Inactive timers ({len(inactive)}):[/bold]\n"
        )
        for timer in inactive[:20]:
            console.print(f"  [dim]{timer['unit']}[/dim]")

        if len(inactive) > 20:
            console.print(
                f"  [dim]... and {len(inactive) - 20} more[/dim]"
            )
        console.print()


def _print_timer(timer: dict) -> None:
    """Приказује један активни timer."""
    next_run = timer.get("next_run") or "n/a"
    left = timer.get("time_left") or "n/a"
    unit = timer.get("unit", "?")
    activates = timer.get("activates") or "?"

    # Скраћујемо.
    if len(next_run) > 19:
        next_run = next_run[:19]
    if len(left) > 10:
        left = left[:10]
    if len(unit) > 28:
        unit = unit[:25] + "..."
    if len(activates) > 30:
        activates = activates[:27] + "..."

    console.print(
        f"  [cyan]{next_run:20s}[/cyan]  "
        f"{left:10s}  "
        f"[bold]{unit:30s}[/bold]  "
        f"[dim]{activates}[/dim]"
    )