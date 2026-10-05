# Модул за анализу kernel логова.
# Kernel логови откривају hardware проблеме, driver грешке,
# OOM killer догађаје, kernel panic, USB догађаје и
# AppArmor/SELinux denials.
#
# Извори:
#   - /var/log/kern.log (Debian/Ubuntu)
#   - /var/log/dmesg
#   - dmesg команда (kernel ring buffer)
#   - journalctl -k (systemd)
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до kernel логова.
KERNEL_LOG_PATHS = [
    Path("/var/log/kern.log"),
    Path("/var/log/kern.log.1"),
    Path("/var/log/dmesg"),
    Path("/var/log/messages"),
]

# Патерни за различите типове kernel догађаја.
# Патерни за различите типове kernel догађаја.
KERNEL_PATTERNS = {
    "oom_killer": re.compile(
        r"(?:Out of memory: Killed process|oom-kill:|oom_reaper:"
        r"\s+reaped|Killed process \d+)",
        re.IGNORECASE,
    ),
    "kernel_panic": re.compile(
        r"(?:Kernel panic|kernel BUG at|BUG:\s+unable|Oops:)",
        re.IGNORECASE,
    ),
    # Hardware error — само праве грешке, не иницијализација.
    "hardware_error": re.compile(
        r"(?:Hardware Error|machine check|MCE:|"
        r"CPU[0-9]+: Core temperature above threshold|"
        r"thermal.*critical|"
        r"EDAC.*(?:error|CE|UE)\s+[0-9]|"
        r"\[Hardware Error\])",
        re.IGNORECASE,
    ),
    # I/O error — само праве грешке, не "SATA link down".
    "io_error": re.compile(
        r"(?:I/O error|blk_update_request:\s+.*error|"
        r"EXT4-fs error|XFS.*error|btrfs.*error|"
        r"Buffer I/O error|"
        r"ata[0-9]+\.[0-9]+:\s+failed command|"
        r"ata[0-9]+\.[0-9]+:\s+error|"
        r"critical medium error)",
        re.IGNORECASE,
    ),
    "memory_error": re.compile(
        r"(?:Memory error|memory failure|"
        r"page allocation failure|"
        r"SLUB.*corrupt)",
        re.IGNORECASE,
    ),
    "usb_event": re.compile(
        r"(?:new (?:high|full|low)-speed USB device|"
        r"USB disconnect)",
        re.IGNORECASE,
    ),
    "network_driver": re.compile(
        r"(?:(?:eth|wlan|enp|eno|wlp)[0-9]+:\s+link (?:up|down)|"
        r"carrier (?:lost|acquired)|"
        r"NIC Link is (?:Up|Down))",
        re.IGNORECASE,
    ),
    # AppArmor denial — само "DENIED" поруке.
    "apparmor_denied": re.compile(
        r"apparmor.*DENIED",
        re.IGNORECASE,
    ),
    # SELinux denial — само "avc: denied" поруке.
    "selinux_denied": re.compile(
        r"avc:\s+denied",
        re.IGNORECASE,
    ),
    "tainted_kernel": re.compile(
        r"(?:tainted kernel|Tainted:)",
        re.IGNORECASE,
    ),
    "firewall": re.compile(
        r"(?:iptables|nftables|netfilter)",
        re.IGNORECASE,
    ),
    "segfault": re.compile(
        r"segfault",
        re.IGNORECASE,
    ),
    "gp_fault": re.compile(
        r"general protection fault",
        re.IGNORECASE,
    ),
    "call_trace": re.compile(
        r"Call Trace:",
    ),
}
# Категорије за приказ.
CATEGORY_MAP = {
    "oom_killer": ("Memory", "red"),
    "kernel_panic": ("Crash", "bold red"),
    "hardware_error": ("Hardware", "red"),
    "io_error": ("I/O", "red"),
    "memory_error": ("Memory", "red"),
    "usb_event": ("USB", "dim"),
    "network_driver": ("Network", "dim"),
    "apparmor_denied": ("Security", "yellow"),
    "selinux_denied": ("Security", "yellow"),
    "tainted_kernel": ("Kernel", "yellow"),
    "firewall": ("Firewall", "dim"),
    "segfault": ("Crash", "red"),
    "gp_fault": ("Crash", "red"),
    "call_trace": ("Crash", "yellow"),
}

# Максималан број линија које читамо.
MAX_LINES = 50000

# Максималан број линија из dmesg/journal.
MAX_BUFFER_LINES = 10000


def run() -> dict:
    """Анализира kernel логове.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Kernel logs[/bold cyan]\n")

    # Проналазимо изворе.
    sources = []
    all_lines = []

    # Прво класични фајлови.
    for path in KERNEL_LOG_PATHS:
        if path.exists() and path.is_file():
            lines = _read_log_file(path)
            if lines:
                for line in lines:
                    line["source"] = str(path)
                all_lines.extend(lines)
                sources.append(str(path))

    # Ако немамо довољно, додајемо dmesg.
    if not all_lines and shutil.which("dmesg"):
        dmesg_lines = _read_dmesg()
        if dmesg_lines:
            all_lines.extend(dmesg_lines)
            sources.append("dmesg")

    # Ако и даље немамо, користимо journalctl -k.
    if not all_lines and shutil.which("journalctl"):
        journal_lines = _read_journal_kernel()
        if journal_lines:
            all_lines.extend(journal_lines)
            sources.append("journalctl -k")

    if not all_lines:
        console.print(
            "  [yellow]No kernel logs found.[/yellow]\n"
        )
        console.print(
            "  [dim]Checked: /var/log/kern.log, dmesg, "
            "journalctl -k[/dim]\n"
        )
        console.print(
            "  [dim]Try running with sudo for full access.[/dim]\n"
        )
        return _empty_result()

    # Анализирамо догађаје.
    events = _parse_events(all_lines)

    # Правимо статистике.
    stats = _make_statistics(events)

    data = {
        "sources": sources,
        "total_lines": len(all_lines),
        "events": events,
        "statistics": stats,
        "summary": {
            "total_lines": len(all_lines),
            "total_events": sum(len(v) for v in events.values()),
            "crashes": len(events.get("kernel_panic", [])) + len(events.get("segfault", [])),
            "hardware_errors": len(events.get("hardware_error", [])),
            "io_errors": len(events.get("io_error", [])),
            "oom_events": len(events.get("oom_killer", [])),
            "usb_events": len(events.get("usb_event", [])),
            "security_denials": (
                len(events.get("apparmor_denied", []))
                + len(events.get("selinux_denied", []))
            ),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "sources": [],
        "total_lines": 0,
        "events": {},
        "statistics": {},
        "summary": {
            "total_lines": 0,
            "total_events": 0,
            "crashes": 0,
            "hardware_errors": 0,
            "io_errors": 0,
            "oom_events": 0,
            "usb_events": 0,
            "security_denials": 0,
        },
    }


def _read_log_file(path: Path) -> list[dict]:
    """Чита kernel лог фајл."""
    lines = []

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


def _read_dmesg() -> list[dict]:
    """Чита dmesg (kernel ring buffer)."""
    lines = []

    try:
        proc = subprocess.run(
            ["dmesg", "--time-format", "iso"],
            capture_output=True,
            text=True,
            timeout=15,
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
                "source": "dmesg",
            })

    return lines


def _read_journal_kernel() -> list[dict]:
    """Чита kernel поруке из journal-а."""
    lines = []

    try:
        proc = subprocess.run(
            [
                "journalctl", "-k",
                "-o", "short",
                "--no-pager",
                "-n", str(MAX_BUFFER_LINES),
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
                "source": "journalctl -k",
            })

    return lines


def _parse_events(lines: list[dict]) -> dict:
    """Парсира kernel лог линије."""
    events = {}

    for line_info in lines:
        text = line_info.get("text", "")
        source = line_info.get("source", "")

        # Проверавамо сваки патерн.
        for event_type, pattern in KERNEL_PATTERNS.items():
            if pattern.search(text):
                if event_type not in events:
                    events[event_type] = []

                events[event_type].append({
                    "text": text[:300],
                    "source": source,
                })
                # Не прекидамо — једна линија може имати више типова
                # (нпр. Call Trace може бити део OOM-а).

    return events


def _make_statistics(events: dict) -> dict:
    """Прави статистике из kernel догађаја."""
    result = {}

    # Категорије.
    category_counts = Counter()

    for event_type, items in events.items():
        category, _ = CATEGORY_MAP.get(event_type, ("Other", "dim"))
        category_counts[category] += len(items)

    result["by_category"] = dict(category_counts)

    # USB уређаји (извучени из порука).
    usb_devices = _extract_usb_devices(events.get("usb_event", []))
    result["usb_devices"] = usb_devices

    # OOM процеси који су убијени.
    oom_processes = _extract_oom_processes(events.get("oom_killer", []))
    result["oom_processes"] = oom_processes

    return result


def _extract_usb_devices(usb_events: list[dict]) -> list[dict]:
    """Извлачи USB уређаје из порука."""
    devices = []
    seen = set()

    pattern = re.compile(
        r"usb\s+\d+-\d+:.*?(?:new\s+\S+\s+USB device.*?)?"
        r"(?:Product:\s*([^\s,]+))?",
        re.IGNORECASE,
    )

    for event in usb_events:
        text = event.get("text", "")

        # Тражимо "Product: XXX" у тексту.
        product_match = re.search(r"Product:\s*([^\n]+)", text)
        if product_match:
            product = product_match.group(1).strip()
            if product and product not in seen:
                seen.add(product)
                devices.append({
                    "product": product,
                    "text": text[:200],
                })

    return devices


def _extract_oom_processes(oom_events: list[dict]) -> list[dict]:
    """Извлачи процесе убијене од OOM killer-а."""
    processes = []

    pattern = re.compile(r"Killed process \d+ \(([^)]+)\)")

    for event in oom_events:
        text = event.get("text", "")
        match = pattern.search(text)

        if match:
            processes.append({
                "process": match.group(1),
                "text": text[:200],
            })

    return processes


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    sources = data.get("sources", [])
    total_lines = data.get("total_lines", 0)
    events = data.get("events", {})
    stats = data.get("statistics", {})
    summary = data.get("summary", {})

    # Извори.
    console.print("[bold]Sources:[/bold]\n")

    for source in sources:
        console.print(f"  [dim]{source}[/dim]")

    console.print()
    console.print(
        f"[bold]Total lines:[/bold]  {total_lines}"
    )
    console.print()

    # Резиме.
    console.print("[bold]Event summary:[/bold]\n")

    crashes = summary.get("crashes", 0)
    hw_errors = summary.get("hardware_errors", 0)
    io_errors = summary.get("io_errors", 0)
    oom_events = summary.get("oom_events", 0)
    usb_events = summary.get("usb_events", 0)
    security = summary.get("security_denials", 0)

    if crashes > 0:
        console.print(
            f"  [bold red]Crashes (panic/segfault):[/bold red]  {crashes}"
        )
    else:
        console.print("  [green]Crashes:[/green]                  0")

    if hw_errors > 0:
        console.print(
            f"  [red]Hardware errors:[/red]            {hw_errors}"
        )
    else:
        console.print("  [green]Hardware errors:[/green]          0")

    if io_errors > 0:
        console.print(
            f"  [red]I/O errors:[/red]                 {io_errors}"
        )
    else:
        console.print("  [green]I/O errors:[/green]               0")

    if oom_events > 0:
        console.print(
            f"  [red]OOM events:[/red]                 {oom_events}"
        )
    else:
        console.print("  [green]OOM events:[/green]               0")

    if security > 0:
        console.print(
            f"  [yellow]Security denials:[/yellow]         {security}"
        )
    else:
        console.print("  [green]Security denials:[/green]         0")

    console.print(
        f"  [dim]USB events:                 {usb_events}[/dim]"
    )

    console.print()

    # По категоријама.
    by_category = stats.get("by_category", {})

    if by_category:
        console.print("[bold]Events by category:[/bold]\n")

        # Сортирамо по броју.
        for category, count in sorted(
            by_category.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            # Боја по категорији.
            category_colors = {
                "Crash": "bold red",
                "Hardware": "red",
                "Memory": "red",
                "I/O": "red",
                "Security": "yellow",
                "Kernel": "yellow",
                "USB": "dim",
                "Network": "dim",
                "Firewall": "dim",
                "Other": "white",
            }

            color = category_colors.get(category, "white")

            console.print(
                f"  [{color}]{category:15s}[/{color}]  {count}"
            )

        console.print()

    # OOM процеси.
    oom_processes = stats.get("oom_processes", [])

    if oom_processes:
        console.print(
            f"[bold red]Processes killed by OOM "
            f"({len(oom_processes)}):[/bold red]\n"
        )

        for proc in oom_processes[:10]:
            console.print(
                f"  [red]{proc['process']}[/red]"
            )

        console.print()

    # USB уређаји.
    usb_devices = stats.get("usb_devices", [])

    if usb_devices:
        console.print(
            f"[bold]USB devices seen ({len(usb_devices)}):[/bold]\n"
        )

        for device in usb_devices[:15]:
            console.print(
                f"  {device['product']}"
            )

        if len(usb_devices) > 15:
            console.print(
                f"  [dim]... and {len(usb_devices) - 15} more[/dim]"
            )

        console.print()

    # Приказујемо критичне догађаје.
    _print_critical_events(events)


def _print_critical_events(events: dict) -> None:
    """Приказује критичне догађаје."""
    # Приоритет приказа.
    priority = [
        ("kernel_panic", "Kernel panic / BUG"),
        ("gp_fault", "General protection fault"),
        ("hardware_error", "Hardware error"),
        ("io_error", "I/O error"),
        ("memory_error", "Memory error"),
        ("oom_killer", "OOM killer"),
        ("segfault", "Segfault"),
        ("apparmor_denied", "AppArmor denial"),
        ("selinux_denied", "SELinux denial"),
    ]

    shown_any = False

    for event_type, label in priority:
        items = events.get(event_type, [])

        if not items:
            continue

        if not shown_any:
            console.print("[bold]Critical events:[/bold]\n")
            shown_any = True

        console.print(
            f"  [bold red]{label} ({len(items)}):[/bold red]"
        )

        # Приказујемо задњих 3.
        for item in items[-3:]:
            text = item.get("text", "")

            if len(text) > 100:
                text = text[:97] + "..."

            console.print(f"    [dim]{text}[/dim]")

        if len(items) > 3:
            console.print(
                f"    [dim]... and {len(items) - 3} more[/dim]"
            )

        console.print()