# Модул за анализу systemd journal-а.
# Journal је модерни систем логовања на systemd системима.
# Може бити:
#   - volatile (само у меморији, /run/log/journal)
#   - persistent (на диску, /var/log/journal)
#
# Ако је volatile, логови нестају после рестарта система.
# То отежава forenзику и откривање напада.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до journal директоријума.
PERSISTENT_JOURNAL_DIR = Path("/var/log/journal")
VOLATILE_JOURNAL_DIR = Path("/run/log/journal")

# Максималан број boot-ова за приказ.
MAX_BOOTS_DISPLAY = 10


def run() -> dict:
    """Анализира systemd journal.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Systemd journal[/bold cyan]\n")

    # Проверавамо да ли је journalctl доступан.
    if not shutil.which("journalctl"):
        console.print(
            "  [yellow]journalctl is not available.[/yellow]\n"
        )
        console.print(
            "  [dim]This system may not use systemd.[/dim]\n"
        )
        return _empty_result()

    # Читамо disk usage.
    disk_usage = _read_disk_usage()

    # Читамо storage тип (persistent vs volatile).
    storage = _detect_storage()

    # Читамо листу boot-ова.
    boots = _read_boots()

    # Читамо статистике по boot-у (број грешака за тренутни boot).
    current_boot_stats = _read_current_boot_stats()

    # Читамо конфигурацију journald.
    config = _read_journald_config()

    # Правимо резиме.
    summary = {
        "storage_type": storage.get("type", "unknown"),
        "disk_usage": disk_usage.get("raw", "unknown"),
        "total_boots": len(boots),
        "current_boot_id": boots[0].get("boot_id") if boots else None,
        "current_boot_errors": current_boot_stats.get("errors", 0),
        "current_boot_warnings": current_boot_stats.get("warnings", 0),
    }

    data = {
        "storage": storage,
        "disk_usage": disk_usage,
        "boots": boots,
        "current_boot_stats": current_boot_stats,
        "config": config,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "storage": {},
        "disk_usage": {},
        "boots": [],
        "current_boot_stats": {},
        "config": {},
        "summary": {
            "storage_type": "unknown",
            "disk_usage": "unknown",
            "total_boots": 0,
            "current_boot_id": None,
            "current_boot_errors": 0,
            "current_boot_warnings": 0,
        },
    }


def _read_disk_usage() -> dict:
    """Чита колико простора journal заузима."""
    result = {
        "raw": None,
        "bytes": None,
        "human": None,
    }

    try:
        proc = subprocess.run(
            ["journalctl", "--disk-usage"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return result
    except Exception:
        return result

    if proc.returncode != 0:
        return result

    output = proc.stdout.strip()
    result["raw"] = output

    # Формат: "Archived and active journals take up 123.4M in the file system."
    match = re.search(r"take up (\S+)", output)
    if match:
        result["human"] = match.group(1)
        result["bytes"] = _parse_size(match.group(1))

    return result


def _parse_size(size_str: str) -> int | None:
    """Парсира величину из формата "1.2G", "500M", "123K"."""
    match = re.match(r"^([\d.]+)\s*([KMGT]?)B?$", size_str.strip())

    if not match:
        return None

    value = float(match.group(1))
    unit = match.group(2)

    multipliers = {
        "": 1,
        "K": 1024,
        "M": 1024 ** 2,
        "G": 1024 ** 3,
        "T": 1024 ** 4,
    }

    return int(value * multipliers.get(unit, 1))


def _detect_storage() -> dict:
    """Препознаје да ли је journal persistent или volatile.

    Persistent: /var/log/journal постоји и има фолдере.
    Volatile: само /run/log/journal (губи се после рестарта).
    """
    result = {
        "type": "unknown",
        "persistent_dir_exists": PERSISTENT_JOURNAL_DIR.exists(),
        "volatile_dir_exists": VOLATILE_JOURNAL_DIR.exists(),
        "persistent_dir_readable": False,
        "persistent_size_bytes": None,
    }

    # Проверавамо да ли persistent директоријум има садржај.
    if PERSISTENT_JOURNAL_DIR.exists():
        try:
            entries = list(PERSISTENT_JOURNAL_DIR.iterdir())
            # Обично има подфолдер са именом машине.
            if entries:
                result["persistent_dir_readable"] = True
                result["type"] = "persistent"
            else:
                result["type"] = "volatile"
        except (PermissionError, Exception):
            # Не можемо да читамо, али директоријум постоји.
            result["type"] = "persistent (unreadable)"
    elif VOLATILE_JOURNAL_DIR.exists():
        result["type"] = "volatile"
    else:
        result["type"] = "not found"

    return result


def _read_boots() -> list[dict]:
    """Чита листу boot-ова из journal-а."""
    boots = []

    try:
        proc = subprocess.run(
            ["journalctl", "--list-boots", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return boots
    except Exception:
        return boots

    if proc.returncode != 0:
        return boots

    output = proc.stdout
    boots = _parse_boots_output(output)

    return boots


def _parse_boots_output(output: str) -> list[dict]:
    """Парсира излаз journalctl --list-boots.

    Формат варира по верзији journalctl. Користимо regex да
    пронађемо датуме, јер се раздвајачи разликују.
    """
    boots = []

    # Regex за датум-време формат: "Mon 2026-10-05 14:00:00 CEST".
    # Подржава и формате без дана у недељи.
    date_pattern = re.compile(
        r"(?:[A-Z][a-z]{2}\s+)?\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\s+\S+)?"
    )

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue
        if line.startswith(("IDX", "BOOT ID")):
            continue

        # Прво узимамо индекс и boot ID.
        # Индекс може бити негативан, boot ID је hex.
        match = re.match(r"^(-?\d+)\s+([0-9a-f]+)\s*(.*)$", line)
        if not match:
            continue

        try:
            idx = int(match.group(1))
        except ValueError:
            continue

        boot_id = match.group(2)
        rest = match.group(3)

        # Проналазимо све датуме у остатку линије.
        dates = date_pattern.findall(rest)

        first_entry = dates[0].strip() if len(dates) >= 1 else None
        last_entry = dates[1].strip() if len(dates) >= 2 else None

        boots.append({
            "index": idx,
            "boot_id": boot_id,
            "is_current": idx == 0,
            "first_entry": first_entry,
            "last_entry": last_entry,
        })

    # Сортирамо по индексу опадајуће (најновији прво).
    boots.sort(key=lambda x: x["index"], reverse=True)

    return boots


def _read_current_boot_stats() -> dict:
    """Чита статистике за тренутни boot.

    Броји грешке и упозорења у тренутном boot-у.
    """
    result = {
        "errors": 0,
        "warnings": 0,
        "critical": 0,
    }

    # Бројимо critical (priority 2 = crit).
    result["critical"] = _count_journal_lines(["-p", "2", "-b"])

    # Бројимо грешке (priority 3 = err).
    result["errors"] = _count_journal_lines(["-p", "3", "-b"])

    # Бројимо упозорења (priority 4 = warning).
    result["warnings"] = _count_journal_lines(["-p", "4", "-b"])

    return result


def _count_journal_lines(extra_args: list[str]) -> int:
    """Броји линије у journal-у са датим филтерима."""
    try:
        proc = subprocess.run(
            ["journalctl", "--no-pager"] + extra_args,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 0
    except Exception:
        return 0

    if proc.returncode != 0:
        return 0

    # Бројимо линије које нису заглавље.
    lines = proc.stdout.splitlines()

    # Прескачемо линије заглавља ("-- Logs begin at ...").
    count = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("-- Logs begin"):
            continue
        if line.startswith("-- No entries"):
            continue
        count += 1

    return count


def _read_journald_config() -> dict:
    """Чита конфигурацију journald.

    Чита /etc/systemd/journald.conf и drop-in фајлове.
    """
    result = {
        "config_file": "/etc/systemd/journald.conf",
        "storage": None,
        "system_max_use": None,
        "system_keep_free": None,
        "max_retention_sec": None,
        "compress": None,
        "forward_to_syslog": None,
    }

    # Читамо главни конфиг фајл.
    config_path = Path("/etc/systemd/journald.conf")
    _merge_config_file(config_path, result)

    # Читамо drop-in фајлове.
    dropin_dir = Path("/etc/systemd/journald.conf.d")

    if dropin_dir.exists() and dropin_dir.is_dir():
        try:
            entries = sorted(dropin_dir.iterdir())
        except (PermissionError, Exception):
            entries = []

        for entry in entries:
            if not entry.is_file():
                continue
            if not entry.name.endswith(".conf"):
                continue

            _merge_config_file(entry, result)

    return result


def _merge_config_file(path: Path, result: dict) -> None:
    """Чита један конфиг фајл и спаја у резултат."""
    if not path.exists():
        return

    try:
        content = path.read_text(
            encoding="utf-8", errors="replace"
        )
    except (PermissionError, Exception):
        return

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        key_lower = key.lower()

        if key_lower == "storage":
            result["storage"] = value
        elif key_lower == "systemmaxuse":
            result["system_max_use"] = value
        elif key_lower == "systemkeepfree":
            result["system_keep_free"] = value
        elif key_lower == "maxretentionsec":
            result["max_retention_sec"] = value
        elif key_lower == "compress":
            result["compress"] = value
        elif key_lower == "forwardtosyslog":
            result["forward_to_syslog"] = value


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    storage = data.get("storage", {})
    disk_usage = data.get("disk_usage", {})
    boots = data.get("boots", [])
    boot_stats = data.get("current_boot_stats", {})
    config = data.get("config", {})

    # Storage тип.
    console.print("[bold]Storage:[/bold]\n")

    storage_type = storage.get("type", "unknown")

    if storage_type == "persistent":
        console.print(
            "  Type:  [green]persistent[/green] "
            "[dim](/var/log/journal)[/dim]"
        )
        console.print(
            "  [dim]Logs are kept across reboots.[/dim]"
        )
    elif storage_type.startswith("persistent"):
        console.print(
            f"  Type:  [yellow]{storage_type}[/yellow]"
        )
    elif storage_type == "volatile":
        console.print(
            "  Type:  [red]volatile[/red] "
            "[dim](/run/log/journal)[/dim]"
        )
        console.print(
            "  [red]⚠ Logs are lost on reboot![/red]"
        )
    else:
        console.print(f"  Type:  [yellow]{storage_type}[/yellow]")

    console.print()

    # Disk usage.
    console.print("[bold]Disk usage:[/bold]\n")

    if disk_usage.get("human"):
        human = disk_usage["human"]
        # Упозорење ако је journal велики.
        size_bytes = disk_usage.get("bytes", 0)
        if size_bytes and size_bytes > 1024 ** 3:  # > 1 GB
            console.print(
                f"  Journal takes up:  [red]{human}[/red] "
                f"[dim](large, consider cleanup)[/dim]"
            )
        elif size_bytes and size_bytes > 500 * 1024 * 1024:  # > 500 MB
            console.print(
                f"  Journal takes up:  [yellow]{human}[/yellow]"
            )
        else:
            console.print(
                f"  Journal takes up:  [cyan]{human}[/cyan]"
            )
    elif disk_usage.get("raw"):
        console.print(f"  {disk_usage['raw']}")
    else:
        console.print("  [dim]Unknown[/dim]")

    console.print()

    # Boot историја.
    if boots:
        console.print(
            f"[bold]Boot history ({len(boots)} total):[/bold]\n"
        )

        # Приказујемо најновије (првих N након сортирања).
        display_boots = boots[:MAX_BOOTS_DISPLAY]

        for boot in display_boots:
            _print_boot(boot)

        if len(boots) > MAX_BOOTS_DISPLAY:
            console.print(
                f"  [dim]... and {len(boots) - MAX_BOOTS_DISPLAY} "
                f"more older boots[/dim]"
            )

        console.print()

    # Статистике тренутног boot-а.
    if boot_stats:
        console.print("[bold]Current boot statistics:[/bold]\n")

        errors = boot_stats.get("errors", 0)
        warnings = boot_stats.get("warnings", 0)
        critical = boot_stats.get("critical", 0)

        if critical > 0:
            console.print(
                f"  [bold red]Critical:[/bold red]  {critical}"
            )
        else:
            console.print("  [green]Critical:[/green]  0")

        if errors > 0:
            console.print(f"  [red]Errors:[/red]    {errors}")
        else:
            console.print("  [green]Errors:[/green]    0")

        if warnings > 0:
            console.print(f"  [yellow]Warnings:[/yellow]  {warnings}")
        else:
            console.print("  [green]Warnings:[/green]  0")

        console.print()

    # Конфигурација.
    if any(v for v in config.values() if v):
        console.print("[bold]Configuration:[/bold]\n")

        if config.get("storage"):
            console.print(
                f"  Storage:           {config['storage']}"
            )
        if config.get("system_max_use"):
            console.print(
                f"  SystemMaxUse:      {config['system_max_use']}"
            )
        if config.get("system_keep_free"):
            console.print(
                f"  SystemKeepFree:    {config['system_keep_free']}"
            )
        if config.get("max_retention_sec"):
            console.print(
                f"  MaxRetentionSec:   {config['max_retention_sec']}"
            )
        if config.get("compress"):
            console.print(
                f"  Compress:          {config['compress']}"
            )

        console.print()

    # Закључак.
    _print_conclusion(storage, boot_stats)


def _print_boot(boot: dict) -> None:
    """Приказује један boot."""
    idx = boot.get("index", 0)
    boot_id = boot.get("boot_id", "?")
    is_current = boot.get("is_current", False)
    first = boot.get("first_entry")
    last = boot.get("last_entry")

    # Скраћујемо boot ID.
    boot_id_short = boot_id[:12] if boot_id else "?"

    # Ознака за тренутни boot.
    if is_current:
        marker = " [green](current)[/green]"
    else:
        marker = ""

    first_display = first if first else "?"
    console.print(
        f"  [{idx:>4d}]  "
        f"[dim]{boot_id_short}[/dim]  "
        f"{first_display}"
        f"{marker}"
    )

    if last and last != first:
        console.print(f"          → {last}")


def _print_conclusion(storage: dict, boot_stats: dict) -> None:
    """Приказује закључак."""
    console.print("[bold]Conclusion:[/bold]\n")

    storage_type = storage.get("type", "unknown")

    if storage_type == "persistent":
        console.print(
            "  [green]✓ Journal is persistent.[/green] "
            "Logs survive reboots."
        )
    elif storage_type == "volatile":
        console.print(
            "  [red]⚠ Journal is volatile.[/red]\n"
            "    Logs are lost on reboot. Consider enabling "
            "persistent storage."
        )
    else:
        console.print(
            f"  [yellow]• Storage type: {storage_type}[/yellow]"
        )

    # Ако има пуно грешака.
    errors = boot_stats.get("errors", 0)
    if errors > 100:
        console.print(
            f"  [yellow]⚠ {errors} errors in current boot.[/yellow] "
            "Investigate."
        )
    elif errors > 0:
        console.print(
            f"  [dim]• {errors} errors in current boot.[/dim]"
        )
    else:
        console.print(
            "  [green]✓ No errors in current boot.[/green]"
        )

    console.print()