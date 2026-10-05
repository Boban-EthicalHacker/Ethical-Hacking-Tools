# Модул за анализу SSH сервер конфигурације.
# SSH је главни улаз на већину сервера. Ако је лоше
# конфигурисан, нападач може да брутфорсује лозинке,
# приступи root налогу, или искористи друге слабости.
#
# Чита /etc/ssh/sshd_config и /etc/ssh/sshd_config.d/*.conf.
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до SSH конфигурације.
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")

# Безбедносне препоруке за кључне параметре.
# Формат: (препоручена_вредност, опис, озбиљност)
SECURITY_CHECKS = {
    "PermitRootLogin": {
        "recommended": "no",
        "description": "Root should not be allowed to login directly",
        "severity": "red",
        "check": lambda v: v.lower() in ("no", "prohibit-password", "forced-commands-only"),
    },
    "PasswordAuthentication": {
        "recommended": "no",
        "description": "Password auth should be disabled (use SSH keys)",
        "severity": "yellow",
        "check": lambda v: v.lower() == "no",
    },
    "PermitEmptyPasswords": {
        "recommended": "no",
        "description": "Empty passwords should never be allowed",
        "severity": "red",
        "check": lambda v: v.lower() == "no",
    },
    "X11Forwarding": {
        "recommended": "no",
        "description": "X11 forwarding should be disabled if not needed",
        "severity": "yellow",
        "check": lambda v: v.lower() == "no",
    },
    "MaxAuthTries": {
        "recommended": "3-6",
        "description": "Limit authentication attempts",
        "severity": "yellow",
        "check": lambda v: _check_max_auth_tries(v),
    },
    "Protocol": {
        "recommended": "2",
        "description": "Only SSH protocol 2 should be used",
        "severity": "red",
        "check": lambda v: v.strip() == "2",
    },
    "PermitUserEnvironment": {
        "recommended": "no",
        "description": "User environment should not be accepted",
        "severity": "yellow",
        "check": lambda v: v.lower() == "no",
    },
    "AllowAgentForwarding": {
        "recommended": "no",
        "description": "Agent forwarding can be a security risk",
        "severity": "dim",
        "check": lambda v: v.lower() == "no",
    },
    "AllowTcpForwarding": {
        "recommended": "no",
        "description": "TCP forwarding can be used for tunneling",
        "severity": "dim",
        "check": lambda v: v.lower() in ("no", "local"),
    },
    "UsePAM": {
        "recommended": "yes",
        "description": "PAM integration for account management",
        "severity": "dim",
        "check": lambda v: v.lower() == "yes",
    },
    "StrictModes": {
        "recommended": "yes",
        "description": "Check permissions of user files",
        "severity": "yellow",
        "check": lambda v: v.lower() == "yes",
    },
    "IgnoreRhosts": {
        "recommended": "yes",
        "description": "Ignore .rhosts files",
        "severity": "yellow",
        "check": lambda v: v.lower() == "yes",
    },
    "HostbasedAuthentication": {
        "recommended": "no",
        "description": "Host-based auth is insecure",
        "severity": "yellow",
        "check": lambda v: v.lower() == "no",
    },
    "ClientAliveInterval": {
        "recommended": "300",
        "description": "Timeout for inactive clients",
        "severity": "dim",
        "check": lambda v: _check_int_range(v, 60, 600),
    },
    "LogLevel": {
        "recommended": "INFO or VERBOSE",
        "description": "Log level for SSH events",
        "severity": "dim",
        "check": lambda v: v.upper() in ("INFO", "VERBOSE"),
    },
}

# Дефаултне вредности (ако параметар није у конфигурацији).
# OpenSSH користи ове вредности када није експлицитно наведено.
DEFAULTS = {
    "PermitRootLogin": "prohibit-password",
    "PasswordAuthentication": "yes",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "MaxAuthTries": "6",
    "Protocol": "2",
    "PermitUserEnvironment": "no",
    "AllowAgentForwarding": "yes",
    "AllowTcpForwarding": "yes",
    "UsePAM": "no",
    "StrictModes": "yes",
    "IgnoreRhosts": "yes",
    "HostbasedAuthentication": "no",
    "ClientAliveInterval": "0",
    "LogLevel": "INFO",
    "Port": "22",
}


def _check_max_auth_tries(value: str) -> bool:
    """Проверава да ли је MaxAuthTries у препорученом опсегу."""
    try:
        num = int(value)
        return 1 <= num <= 6
    except (ValueError, TypeError):
        return False


def _check_int_range(value: str, min_val: int, max_val: int) -> bool:
    """Проверава да ли је број у опсегу."""
    try:
        num = int(value)
        return min_val <= num <= max_val
    except (ValueError, TypeError):
        return False


def run() -> dict:
    """Анализира SSH сервер конфигурацију.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]SSH server configuration[/bold cyan]\n")

    # Проверавамо да ли је SSH сервер инсталиран.
    if not SSHD_CONFIG.exists():
        console.print(
            "  [yellow]SSH server configuration not found.[/yellow]\n"
        )
        return _empty_result()

    # Читамо конфигурацију.
    config = _read_config()

    if not config.get("readable"):
        console.print(
            "  [yellow]Cannot read SSH configuration.[/yellow]\n"
        )
        return _empty_result()

    # Примењујемо дефаулте за параметре који нису наведени.
    effective = _apply_defaults(config["settings"])

    # Анализирамо безбедност.
    findings = _analyze_security(effective)

    # Читамо AllowUsers/DenyUsers.
    access_control = _read_access_control(config["settings"])

    # Правимо резиме.
    summary = {
        "total_settings": len(effective),
        "issues_count": len(findings),
        "critical_count": len(
            [f for f in findings if f.get("severity") == "red"]
        ),
    }

    data = {
        "config_files": config.get("files", []),
        "settings": effective,
        "findings": findings,
        "access_control": access_control,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "config_files": [],
        "settings": {},
        "findings": [],
        "access_control": {},
        "summary": {
            "total_settings": 0,
            "issues_count": 0,
            "critical_count": 0,
        },
    }


def _read_config() -> dict:
    """Чита главни конфиг и drop-in фајлове."""
    result = {
        "readable": False,
        "files": [],
        "settings": {},
    }

    # Читамо главни фајл.
    if SSHD_CONFIG.exists():
        settings = _parse_ssh_config(SSHD_CONFIG)
        if settings is not None:
            result["readable"] = True
            result["settings"].update(settings)
            result["files"].append(str(SSHD_CONFIG))

    # Читамо drop-in фајлове.
    if SSHD_CONFIG_D.exists() and SSHD_CONFIG_D.is_dir():
        try:
            entries = sorted(SSHD_CONFIG_D.iterdir())
        except (PermissionError, Exception):
            entries = []

        for file_path in entries:
            if not file_path.is_file():
                continue
            if not file_path.name.endswith(".conf"):
                continue

            settings = _parse_ssh_config(file_path)
            if settings is not None:
                # Drop-in фајлови имају приоритет.
                result["settings"].update(settings)
                result["files"].append(str(file_path))

    return result


def _parse_ssh_config(path: Path) -> dict | None:
    """Парсира један sshd_config фајл."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return None

    settings = {}

    for line in content.splitlines():
        line = line.strip()

        # Прескачемо празне линије и коментаре.
        if not line or line.startswith("#"):
            continue

        # Формат: Keyword value
        # Раздвајамо на првом размаку или табу.
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        key = parts[0].strip()
        value = parts[1].strip()

        # Уклањамо inline коментаре.
        if "#" in value:
            value = value.split("#", 1)[0].strip()

        # OpenSSH користи "keyword value" формат. Прво појављивање
        # обично побеђује, али за неке параметре последње.
        # Овде узимамо последњу вредност (drop-in фајлови имају приоритет).
        settings[key] = value

    return settings


def _apply_defaults(settings: dict) -> dict:
    """Примењује дефаултне вредности за параметре који недостају."""
    result = {}

    for key, value in settings.items():
        result[key] = {
            "value": value,
            "explicit": True,
            "default": False,
        }

    for key, default_value in DEFAULTS.items():
        if key not in result:
            result[key] = {
                "value": default_value,
                "explicit": False,
                "default": True,
            }

    return result


def _analyze_security(settings: dict) -> list[dict]:
    """Анализира безбедност конфигурације."""
    findings = []

    for key, check in SECURITY_CHECKS.items():
        entry = settings.get(key)
        if not entry:
            continue

        value = entry.get("value", "")
        recommended = check.get("recommended", "")
        description = check.get("description", "")
        severity = check.get("severity", "dim")
        check_func = check.get("check")

        # Проверавамо да ли је вредност безбедна.
        try:
            is_secure = check_func(value)
        except Exception:
            is_secure = False

        if not is_secure:
            findings.append({
                "setting": key,
                "value": value,
                "recommended": recommended,
                "description": description,
                "severity": severity,
                "explicit": entry.get("explicit", False),
                "is_default": entry.get("default", False),
            })

    # Сортирамо по озбиљности.
    severity_order = {"red": 0, "yellow": 1, "dim": 2}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    return findings


def _read_access_control(settings: dict) -> dict:
    """Чита AllowUsers, DenyUsers, AllowGroups, DenyGroups."""
    result = {
        "allow_users": [],
        "deny_users": [],
        "allow_groups": [],
        "deny_groups": [],
        "port": settings.get("Port", {}).get("value", "22"),
        "listen_addresses": [],
    }

    # AllowUsers / DenyUsers
    for key, field in [
        ("AllowUsers", "allow_users"),
        ("DenyUsers", "deny_users"),
        ("AllowGroups", "allow_groups"),
        ("DenyGroups", "deny_groups"),
    ]:
        entry = settings.get(key)
        if not entry:
            continue

        value = entry.get("value", "")
        if value:
            result[field] = value.split()

    # ListenAddress — на којим адресама слуша.
    entry = settings.get("ListenAddress")
    if entry:
        value = entry.get("value", "")
        if value:
            result["listen_addresses"] = value.split()

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    config_files = data.get("config_files", [])
    settings = data.get("settings", {})
    findings = data.get("findings", [])
    access_control = data.get("access_control", {})
    summary = data.get("summary", {})

    # Конфигурациони фајлови.
    if config_files:
        console.print("[bold]Config files:[/bold]\n")
        for f in config_files:
            console.print(f"  [dim]{f}[/dim]")
        console.print()

    # Основне информације.
    console.print("[bold]Basic settings:[/bold]\n")

    port = access_control.get("port", "22")
    if port != "22":
        console.print(
            f"  Port:                    [yellow]{port}[/yellow] "
            f"[dim](non-standard)[/dim]"
        )
    else:
        console.print(f"  Port:                    {port}")

    listen = access_control.get("listen_addresses", [])
    if listen:
        console.print(
            f"  Listen address:          {', '.join(listen)}"
        )
    else:
        console.print(
            "  Listen address:          [red]all (0.0.0.0)[/red]"
        )

    console.print()

    # Access control.
    _print_access_control(access_control)

    # Findings (проблеми).
    if findings:
        console.print(
            f"[bold]Security issues ({len(findings)}):[/bold]\n"
        )

        for finding in findings:
            _print_finding(finding)

        console.print()
    else:
        console.print(
            "[bold green]No security issues found.[/bold green]\n"
        )

    # Закључак.
    _print_conclusion(summary)


def _print_access_control(access: dict) -> None:
    """Приказује access control листе."""
    has_any = False

    if access.get("allow_users"):
        console.print(
            f"  AllowUsers:              "
            f"[cyan]{', '.join(access['allow_users'])}[/cyan]"
        )
        has_any = True

    if access.get("deny_users"):
        console.print(
            f"  DenyUsers:               "
            f"[yellow]{', '.join(access['deny_users'])}[/yellow]"
        )
        has_any = True

    if access.get("allow_groups"):
        console.print(
            f"  AllowGroups:             "
            f"[cyan]{', '.join(access['allow_groups'])}[/cyan]"
        )
        has_any = True

    if access.get("deny_groups"):
        console.print(
            f"  DenyGroups:              "
            f"[yellow]{', '.join(access['deny_groups'])}[/yellow]"
        )
        has_any = True

    if not has_any:
        console.print(
            "  [dim]No access control lists defined "
            "(all users can attempt login).[/dim]"
        )

    console.print()


def _print_finding(finding: dict) -> None:
    """Приказује један безбедносни проблем."""
    severity = finding.get("severity", "dim")
    setting = finding.get("setting", "?")
    value = finding.get("value", "?")
    recommended = finding.get("recommended", "")
    description = finding.get("description", "")
    is_default = finding.get("is_default", False)

    # Ознака ако је дефаултна вредност.
    default_marker = ""
    if is_default:
        default_marker = " [dim](default)[/dim]"

    console.print(
        f"  [{severity}]● {setting}[/{severity}] = "
        f"[bold]{value}[/bold]{default_marker}"
    )

    if recommended:
        console.print(
            f"    Recommended: [green]{recommended}[/green]"
        )

    if description:
        console.print(f"    [dim]{description}[/dim]")

    console.print()


def _print_conclusion(summary: dict) -> None:
    """Приказује безбедносни закључак."""
    issues = summary.get("issues_count", 0)
    critical = summary.get("critical_count", 0)

    console.print("[bold]Conclusion:[/bold]\n")

    if critical > 0:
        console.print(
            f"  [bold red]⚠ {critical} critical issue(s) found.[/bold red]\n"
            "    SSH configuration is insecure. Fix immediately."
        )
    elif issues > 0:
        console.print(
            f"  [yellow]⚠ {issues} issue(s) found.[/yellow]\n"
            "    SSH configuration has minor weaknesses."
        )
    else:
        console.print(
            "  [green]✓ SSH configuration is secure.[/green]"
        )

    console.print()