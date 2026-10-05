# Модул за приказ audit конфигурације (Linux Audit система).
# Audit прати безбедносно важне догађаје — промене /etc/passwd,
# sudo команде, syscall-ове. Ако није активан, нема трагова о нападу.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до audit конфигурације.
AUDIT_DIR = Path("/etc/audit")
AUDITD_CONF = AUDIT_DIR / "auditd.conf"
AUDIT_RULES = AUDIT_DIR / "audit.rules"
RULES_D_DIR = AUDIT_DIR / "rules.d"
AUDIT_LOG_DIR = Path("/var/log/audit")

# Кључни параметри из auditd.conf.
IMPORTANT_CONF_KEYS = {
    "log_file": "Log file location",
    "log_format": "Log format (raw or enriched)",
    "max_log_file": "Maximum log file size (MB)",
    "num_logs": "Number of rotated log files",
    "space_left": "Free space threshold (MB)",
    "admin_space_left": "Admin space threshold (MB)",
    "space_left_action": "Action when space is low",
    "admin_space_left_action": "Admin action when space is low",
    "disk_full_action": "Action when disk is full",
    "disk_error_action": "Action on disk error",
    "max_log_file_action": "Action when log file is full",
    "flush": "Flush behavior",
    "freq": "Flush frequency",
    "disp_qos": "Dispatcher queue quality of service",
    "dispatcher": "Dispatcher path",
    "name_format": "Host name format",
    "local_events": "Include local events",
}

# Категорије audit правила.
RULE_CATEGORIES = {
    "-a": "Append rule",
    "-A": "Append rule",
    "-d": "Delete rule",
    "-w": "Watch file",
    "-p": "Permission filter",
    "-F": "Field filter",
    "-b": "Buffer size",
    "-f": "Failure mode",
    "-e": "Enable/disable audit",
    "-r": "Rate limit",
    "-i": "Ignore errors",
    "--backlog_wait_time": "Backlog wait",
}


def run() -> dict:
    """Приказује audit конфигурацију.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Audit configuration[/bold cyan]\n")

    # Проверавамо да ли је auditd инсталиран.
    installed = _is_installed()

    if not installed:
        console.print(
            "  [yellow]auditd is not installed.[/yellow]\n"
        )
        return _empty_result()

    # Статус сервиса.
    service = _get_service_status()

    # Главна конфигурација.
    config = _read_auditd_conf()

    # Правила.
    rules = _read_rules()

    # Анализирамо.
    analysis = _analyze(config, rules)

    data = {
        "installed": True,
        "service": service,
        "config": config,
        "rules": rules,
        "analysis": analysis,
        "summary": {
            "installed": True,
            "service_active": service.get("active", False),
            "service_enabled": service.get("enabled", False),
            "total_rules": len(rules),
            "immutable": analysis.get("immutable", False),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "installed": False,
        "service": {},
        "config": {},
        "rules": [],
        "analysis": {},
        "summary": {
            "installed": False,
            "service_active": False,
            "service_enabled": False,
            "total_rules": 0,
            "immutable": False,
        },
    }


def _is_installed() -> bool:
    """Проверава да ли је auditd инсталиран."""
    if shutil.which("auditctl") or shutil.which("auditd"):
        return True

    if AUDIT_DIR.exists() or AUDITD_CONF.exists():
        return True

    return False


def _get_service_status() -> dict:
    """Проверава статус auditd сервиса."""
    result = {
        "active": False,
        "enabled": False,
    }

    if not shutil.which("systemctl"):
        return result

    # Проверавамо да ли је активан.
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["active"] = proc.stdout.strip() == "active"
    except Exception:
        pass

    # Проверавамо да ли је омогућен.
    try:
        proc = subprocess.run(
            ["systemctl", "is-enabled", "auditd"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["enabled"] = proc.stdout.strip() == "enabled"
    except Exception:
        pass

    # Проверавамо статус кроз auditctl.
    if shutil.which("auditctl"):
        try:
            proc = subprocess.run(
                ["auditctl", "-s"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                kernel_status = _parse_auditctl_status(proc.stdout)
                result.update(kernel_status)
        except Exception:
            pass

    return result


def _parse_auditctl_status(output: str) -> dict:
    """Парсира `auditctl -s` излаз."""
    result = {
        "kernel_enabled": False,
        "enabled_value": None,
        "failure_mode": None,
        "backlog_limit": None,
        "lost": None,
        "rate_limit": None,
    }

    for line in output.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key == "enabled":
            result["enabled_value"] = value
            # 1 = enabled, 2 = immutable, 0 = disabled
            result["kernel_enabled"] = value in ("1", "2")
            result["immutable"] = value == "2"
        elif key == "failure":
            result["failure_mode"] = value
        elif key == "backlog_limit":
            result["backlog_limit"] = value
        elif key == "lost":
            result["lost"] = value
        elif key == "rate_limit":
            result["rate_limit"] = value

    return result


def _read_auditd_conf() -> dict:
    """Чита /etc/audit/auditd.conf."""
    result = {
        "path": str(AUDITD_CONF),
        "readable": False,
        "values": {},
    }

    if not AUDITD_CONF.exists():
        return result

    try:
        content = AUDITD_CONF.read_text(encoding="utf-8", errors="replace")
        result["readable"] = True
    except (PermissionError, Exception):
        return result

    for line in content.splitlines():
        line = line.strip()

        # Прескачемо празне линије и коментаре.
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key in IMPORTANT_CONF_KEYS:
            result["values"][key] = {
                "value": value,
                "description": IMPORTANT_CONF_KEYS[key],
            }

    return result


def _read_rules() -> list[dict]:
    """Чита audit правила.

    Чита /etc/audit/audit.rules и /etc/audit/rules.d/*.rules.
    Такође чита и активна правила из кернела преко auditctl -l.
    """
    rules = []

    # Читамо фајлове.
    rule_files = []

    if AUDIT_RULES.exists():
        rule_files.append(AUDIT_RULES)

    if RULES_D_DIR.exists() and RULES_D_DIR.is_dir():
        try:
            for file_path in sorted(RULES_D_DIR.iterdir()):
                if file_path.is_file() and file_path.name.endswith(".rules"):
                    rule_files.append(file_path)
        except (PermissionError, Exception):
            pass

    for rule_file in rule_files:
        file_rules = _parse_rule_file(rule_file)
        rules.extend(file_rules)

    # Ако auditctl ради, узимамо и активна правила (можда се разликују).
    kernel_rules = _read_kernel_rules()

    # Спајамо — користимо kernel правила ако постоје, иначе фајлове.
    if kernel_rules:
        # Означавамо извор.
        for rule in kernel_rules:
            rule["source"] = "kernel"
        return kernel_rules

    return rules


def _parse_rule_file(path: Path) -> list[dict]:
    """Парсира један .rules фајл."""
    result = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return result

    file_path_str = str(path)

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parsed = _parse_rule_line(line, file_path_str, line_number)
        if parsed:
            result.append(parsed)

    return result


def _parse_rule_line(
    line: str, source: str, line_number: int
) -> dict | None:
    """Парсира једну audit rule линију."""
    parts = line.split()
    if not parts:
        return None

    first = parts[0]

    # Препознајемо тип.
    rule_type = RULE_CATEGORIES.get(first, "unknown")

    # Категорија за приказ.
    category = "other"

    if first == "-w":
        category = "watch"
    elif first in ("-a", "-A"):
        # Проверавамо шта филтрира.
        if "-S" in line or "-F" in line and "syscall" in line.lower():
            category = "syscall"
        elif "identity" in line.lower() or "passwd" in line.lower():
            category = "identity"
        elif "execve" in line.lower():
            category = "execution"
        elif "network" in line.lower() or "socket" in line.lower():
            category = "network"
        elif "delete" in line.lower() or "unlink" in line.lower():
            category = "file_delete"
        else:
            category = "system_call"
    elif first in ("-b", "-f", "-e", "-r", "--backlog_wait_time"):
        category = "control"
    elif first in ("-d",):
        category = "delete"

    return {
        "raw": line,
        "type": rule_type,
        "category": category,
        "source": source,
        "line_number": line_number,
    }


def _read_kernel_rules() -> list[dict]:
    """Чита активна правила из кернела преко `auditctl -l`."""
    if not shutil.which("auditctl"):
        return []

    try:
        proc = subprocess.run(
            ["auditctl", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    rules = []

    for line_number, line in enumerate(proc.stdout.splitlines(), start=1):
        line = line.strip()

        # auditctl -l враћа "No rules" ако нема правила.
        if not line or line.lower() == "no rules":
            continue

        parsed = _parse_rule_line(line, "kernel", line_number)
        if parsed:
            rules.append(parsed)

    return rules


def _analyze(config: dict, rules: list[dict]) -> dict:
    """Анализира конфигурацију и правила."""
    result = {
        "immutable": False,
        "has_watch_rules": False,
        "has_syscall_rules": False,
        "has_identity_rules": False,
        "has_execution_rules": False,
        "categories": {},
        "remote_logging": False,
    }

    # Анализирамо правила.
    for rule in rules:
        category = rule.get("category", "other")

        # Бројимо по категоријама.
        result["categories"][category] = (
            result["categories"].get(category, 0) + 1
        )

        # Проверавамо кључне категорије.
        if category == "watch":
            result["has_watch_rules"] = True
        elif category == "syscall":
            result["has_syscall_rules"] = True
        elif category == "identity":
            result["has_identity_rules"] = True
        elif category == "execution":
            result["has_execution_rules"] = True

        # Проверавамо immutable mode.
        raw = rule.get("raw", "")
        if raw.startswith("-e") and "2" in raw:
            result["immutable"] = True

    # Анализирамо конфигурацију.
    values = config.get("values", {})

    # Проверавамо да ли се логови шаљу на удаљени сервер.
    log_file = values.get("log_file", {}).get("value", "")
    if log_file and log_file.startswith(("tcp://", "udp://", "remote")):
        result["remote_logging"] = True

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    service = data.get("service", {})
    config = data.get("config", {})
    rules = data.get("rules", [])
    analysis = data.get("analysis", {})
    summary = data.get("summary", {})

    # Статус сервиса.
    console.print("[bold]Service status:[/bold]\n")

    if service.get("active"):
        console.print("  Active:   [green]yes[/green]")
    else:
        console.print("  Active:   [red]no[/red]")

    if service.get("enabled"):
        console.print("  Enabled:  [green]yes[/green]")
    else:
        console.print("  Enabled:  [red]no[/red]")

    if service.get("immutable"):
        console.print(
            "  Immutable: [green]yes[/green] "
            "[dim](rules cannot be changed at runtime)[/dim]"
        )

    console.print()

    # Упозорење ако није активан.
    if not service.get("active"):
        console.print(
            "[bold yellow]⚠ auditd is not running.[/bold yellow]\n"
        )
        console.print(
            "  [dim]System has no audit trail of security events.[/dim]\n"
        )

    # Конфигурација.
    values = config.get("values", {})
    if values:
        console.print("[bold]Configuration:[/bold]\n")

        for key in [
            "log_file", "max_log_file", "num_logs",
            "flush", "space_left_action", "disk_full_action",
        ]:
            entry = values.get(key)
            if not entry:
                continue

            value = entry.get("value", "")
            console.print(f"  {key:25s}  [cyan]{value}[/cyan]")

        console.print()

    # Резиме правила.
    if rules:
        console.print(f"[bold]Rules ({len(rules)}):[/bold]\n")

        categories = analysis.get("categories", {})

        # Приказујемо по категоријама.
        category_labels = {
            "watch": "File watches",
            "syscall": "Syscall rules",
            "identity": "Identity rules",
            "execution": "Execution rules",
            "network": "Network rules",
            "file_delete": "File delete rules",
            "system_call": "System call rules",
            "control": "Control directives",
            "delete": "Delete rules",
            "other": "Other",
        }

        for cat, count in sorted(
            categories.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            label = category_labels.get(cat, cat)
            console.print(f"  {label:25s}  {count}")

        console.print()

        # Приказујемо првих 10 правила.
        console.print("[bold]Sample rules:[/bold]\n")

        for rule in rules[:10]:
            raw = rule.get("raw", "")
            if len(raw) > 80:
                raw = raw[:77] + "..."
            console.print(f"  [dim]{raw}[/dim]")

        if len(rules) > 10:
            console.print(
                f"  [dim]... and {len(rules) - 10} more[/dim]"
            )

        console.print()

    else:
        console.print(
            "[bold yellow]No audit rules found.[/bold yellow]\n"
        )

    # Закључак.
    _print_conclusion(service, analysis)


def _print_conclusion(service: dict, analysis: dict) -> None:
    """Приказује безбедносни закључак."""
    console.print("[bold]Conclusion:[/bold]\n")

    active = service.get("active", False)
    immutable = analysis.get("immutable", False)

    if active:
        console.print(
            "  [green]✓ auditd is running.[/green]"
        )

        if analysis.get("has_identity_rules"):
            console.print(
                "  [green]✓ Identity changes are logged.[/green]"
            )
        else:
            console.print(
                "  [yellow]• No rules watching identity files "
                "(/etc/passwd, /etc/shadow).[/yellow]"
            )

        if analysis.get("has_execution_rules"):
            console.print(
                "  [green]✓ Command execution is logged.[/green]"
            )

        if immutable:
            console.print(
                "  [green]✓ Immutable mode active.[/green] "
                "Rules cannot be changed at runtime."
            )
    else:
        console.print(
            "  [yellow]⚠ auditd is not running.[/yellow]\n"
            "    Security events are not being logged."
        )

    console.print()