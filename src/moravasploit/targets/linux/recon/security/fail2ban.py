# Модул за приказ fail2ban конфигурације.
# Fail2ban је основна заштита од brute force напада.
# Ако није активан, SSH и друге услуге су отворене за нападе.
#
# Чита /etc/fail2ban/jail.conf и jail.local, приказује
# активне jail-ове и њихова подешавања.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess
from configparser import ConfigParser
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до fail2ban конфигурације.
FAIL2BAN_DIR = Path("/etc/fail2ban")
JAIL_CONF = FAIL2BAN_DIR / "jail.conf"
JAIL_LOCAL = FAIL2BAN_DIR / "jail.local"
JAIL_D_DIR = FAIL2BAN_DIR / "jail.d"
FILTER_D_DIR = FAIL2BAN_DIR / "filter.d"

# Подразумеване вредности (из jail.conf).
DEFAULT_MAXRETRY = 5
DEFAULT_BANTIME = 600
DEFAULT_FINDTIME = 600


def run() -> dict:
    """Приказује fail2ban конфигурацију.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Fail2ban[/bold cyan]\n")

    # Проверавамо да ли је fail2ban инсталиран.
    installed = _is_installed()

    if not installed:
        console.print(
            "  [yellow]fail2ban is not installed.[/yellow]\n"
        )
        return _empty_result()

    # Проверавамо да ли је сервис активан.
    service_status = _get_service_status()

    # Читамо конфигурацију.
    config = _read_config()

    # Читамо активне jail-ове.
    jails = _read_jails(config)

    # Проверавамо статус преко fail2ban-client (ако је активан).
    client_status = _get_client_status()

    # Правимо резиме.
    summary = {
        "installed": True,
        "service_active": service_status.get("active", False),
        "service_enabled": service_status.get("enabled", False),
        "total_jails": len(jails),
        "active_jails": len(
            [j for j in jails if j.get("enabled")]
        ),
    }

    data = {
        "installed": True,
        "service": service_status,
        "jails": jails,
        "client_status": client_status,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "installed": False,
        "service": {},
        "jails": [],
        "client_status": {},
        "summary": {
            "installed": False,
            "service_active": False,
            "service_enabled": False,
            "total_jails": 0,
            "active_jails": 0,
        },
    }


def _is_installed() -> bool:
    """Проверава да ли је fail2ban инсталиран."""
    if shutil.which("fail2ban-client"):
        return True

    if FAIL2BAN_DIR.exists():
        return True

    return False


def _get_service_status() -> dict:
    """Проверава статус fail2ban сервиса."""
    result = {
        "active": False,
        "enabled": False,
        "status_text": None,
    }

    if not shutil.which("systemctl"):
        return result

    # Проверавамо да ли је активан.
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "fail2ban"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["active"] = proc.stdout.strip() == "active"
        result["status_text"] = proc.stdout.strip()
    except Exception:
        pass

    # Проверавамо да ли је омогућен при покретању.
    try:
        proc = subprocess.run(
            ["systemctl", "is-enabled", "fail2ban"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["enabled"] = proc.stdout.strip() == "enabled"
    except Exception:
        pass

    return result


def _read_config() -> dict:
    """Чита fail2ban конфигурацију.

    Чита jail.conf, jail.local и све фајлове у jail.d/.
    """
    result = {
        "defaults": {},
        "jails": {},
    }

    # Читамо све изворе редом (каснији преписују раније).
    sources = [JAIL_CONF]

    if JAIL_LOCAL.exists():
        sources.append(JAIL_LOCAL)

    # Фајлови у jail.d/.
    if JAIL_D_DIR.exists() and JAIL_D_DIR.is_dir():
        try:
            for file_path in sorted(JAIL_D_DIR.iterdir()):
                if file_path.is_file() and file_path.name.endswith(".conf"):
                    sources.append(file_path)
        except (PermissionError, Exception):
            pass

    # Парсирамо све фајлове.
    parser = ConfigParser(strict=False)
    parser.optionxform = str

    for source in sources:
        if not source.exists():
            continue

        try:
            parser.read(source, encoding="utf-8")
        except Exception:
            continue

    # Извлачимо default подешавања.
    if "DEFAULT" in parser:
        defaults = dict(parser["DEFAULT"])
        result["defaults"] = {
            "bantime": _to_int(defaults.get("bantime")),
            "findtime": _to_int(defaults.get("findtime")),
            "maxretry": _to_int(defaults.get("maxretry")),
            "ignoreip": defaults.get("ignoreip"),
            "banaction": defaults.get("banaction"),
            "backend": defaults.get("backend"),
        }

    # Извлачимо jail-ове.
    for section in parser.sections():
        # Прескачемо [DEFAULT] и сличне.
        if section in ("DEFAULT", "INCLUDES"):
            continue

        options = dict(parser[section])

        # Издвајамо кључне вредности.
        enabled = _to_bool(options.get("enabled", "false"))
        logpath = options.get("logpath")
        maxretry = _to_int(options.get("maxretry"))
        bantime = _to_int(options.get("bantime"))
        findtime = _to_int(options.get("findtime"))
        action = options.get("action")
        filter_name = options.get("filter")

        result["jails"][section] = {
            "name": section,
            "enabled": enabled,
            "logpath": logpath,
            "maxretry": maxretry,
            "bantime": bantime,
            "findtime": findtime,
            "filter": filter_name,
            "action": action,
        }

    return result


def _read_jails(config: dict) -> list[dict]:
    """Припрема листу jail-ова са применом дефаулта."""
    defaults = config.get("defaults", {})
    jails_config = config.get("jails", {})

    jails = []

    for name, jail in jails_config.items():
        # Примењујемо дефаулте ако вредност није дефинисана.
        maxretry = jail.get("maxretry")
        if maxretry is None:
            maxretry = defaults.get("maxretry") or DEFAULT_MAXRETRY

        bantime = jail.get("bantime")
        if bantime is None:
            bantime = defaults.get("bantime") or DEFAULT_BANTIME

        findtime = jail.get("findtime")
        if findtime is None:
            findtime = defaults.get("findtime") or DEFAULT_FINDTIME

        jails.append({
            "name": name,
            "enabled": jail.get("enabled", False),
            "logpath": jail.get("logpath"),
            "maxretry": maxretry,
            "bantime": bantime,
            "findtime": findtime,
            "filter": jail.get("filter"),
        })

    # Сортирамо — омогућени прво, па по имену.
    jails.sort(key=lambda x: (not x["enabled"], x["name"]))

    return jails


def _get_client_status() -> dict:
    """Чита статус преко fail2ban-client (ако је активан)."""
    result = {
        "available": False,
        "jails": {},
    }

    if not shutil.which("fail2ban-client"):
        return result

    # Покушавамо да добијемо статус.
    try:
        proc = subprocess.run(
            ["fail2ban-client", "status"],
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

    result["available"] = True

    # Парсирамо статус.
    # Пример:
    # Status
    # |- Number of jail:	2
    # `- Jail list:	sshd, recidive
    for line in proc.stdout.splitlines():
        line = line.strip()

        if "Jail list:" in line:
            jails_str = line.split("Jail list:", 1)[1].strip()
            jails = [j.strip() for j in jails_str.split(",") if j.strip()]
            result["jail_names"] = jails

            # За сваки jail узимамо детаље.
            for jail_name in jails:
                details = _get_jail_details(jail_name)
                if details:
                    result["jails"][jail_name] = details

    return result


def _get_jail_details(jail_name: str) -> dict | None:
    """Чита детаље једног jail-а."""
    try:
        proc = subprocess.run(
            ["fail2ban-client", "status", jail_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    details = {
        "currently_banned": 0,
        "total_banned": 0,
        "banned_ips": [],
    }

    for line in proc.stdout.splitlines():
        line = line.strip()

        if "Currently banned:" in line:
            try:
                details["currently_banned"] = int(
                    line.split(":", 1)[1].strip()
                )
            except (ValueError, IndexError):
                pass
        elif "Total banned:" in line:
            try:
                details["total_banned"] = int(
                    line.split(":", 1)[1].strip()
                )
            except (ValueError, IndexError):
                pass
        elif "Banned IP list:" in line:
            ips_str = line.split(":", 1)[1].strip()
            ips = [ip.strip() for ip in ips_str.split() if ip.strip()]
            details["banned_ips"] = ips

    return details


def _to_int(value) -> int | None:
    """Безбедно претвара вредност у int."""
    if value is None:
        return None

    # Уклањамо могуће наводнике и суфиксе (нпр. "10m", "1d").
    if isinstance(value, str):
        value = value.strip().strip("'\"")

        # Обрађујемо суфиксе времена (m, h, d).
        multipliers = {
            "s": 1,
            "m": 60,
            "h": 3600,
            "d": 86400,
            "w": 604800,
        }

        if value and value[-1].lower() in multipliers:
            try:
                number = int(value[:-1])
                return number * multipliers[value[-1].lower()]
            except ValueError:
                pass

    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _to_bool(value) -> bool:
    """Безбедно претвара вредност у bool."""
    if value is None:
        return False

    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in ("true", "yes", "1", "on")


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    service = data.get("service", {})
    jails = data.get("jails", [])
    client_status = data.get("client_status", {})
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

    console.print()

    # Упозорење ако није активан.
    if not service.get("active"):
        console.print(
            "[bold yellow]⚠ fail2ban is not running.[/bold yellow]\n"
        )
        console.print(
            "  [dim]System is vulnerable to brute force attacks.[/dim]\n"
        )

    # Приказујемо jail-ове.
    if jails:
        console.print(f"[bold]Jails ({len(jails)}):[/bold]\n")

        # Прво омогућени.
        enabled_jails = [j for j in jails if j.get("enabled")]
        disabled_jails = [j for j in jails if not j.get("enabled")]

        if enabled_jails:
            console.print("[bold green]Enabled:[/bold green]\n")

            for jail in enabled_jails:
                _print_jail(jail, client_status)

            console.print()

        if disabled_jails:
            console.print("[bold dim]Disabled:[/bold dim]\n")

            for jail in disabled_jails[:10]:
                console.print(f"  [dim]{jail['name']}[/dim]")

            if len(disabled_jails) > 10:
                console.print(
                    f"  [dim]... and {len(disabled_jails) - 10} more[/dim]"
                )

            console.print()

    else:
        console.print(
            "  [yellow]No jails configured.[/yellow]\n"
        )

    # Приказујемо активно блокиране IP-ове.
    _print_banned_ips(client_status)


def _print_jail(jail: dict, client_status: dict) -> None:
    """Приказује један jail."""
    name = jail.get("name", "?")
    maxretry = jail.get("maxretry")
    bantime = jail.get("bantime")
    findtime = jail.get("findtime")
    logpath = jail.get("logpath")

    console.print(f"  [bold cyan]{name}[/bold cyan]")

    if maxretry:
        console.print(f"    Max retry:  {maxretry}")

    if bantime:
        console.print(f"    Ban time:   {_format_duration(bantime)}")

    if findtime:
        console.print(f"    Find time:  {_format_duration(findtime)}")

    if logpath:
        # Скраћујемо путању.
        if len(logpath) > 60:
            logpath = logpath[:57] + "..."
        console.print(f"    Log:        [dim]{logpath}[/dim]")

    # Приказујемо статус из fail2ban-client.
    jail_status = client_status.get("jails", {}).get(name, {})

    if jail_status:
        current = jail_status.get("currently_banned", 0)
        total = jail_status.get("total_banned", 0)

        if current > 0:
            console.print(
                f"    [red]Currently banned: {current}[/red]"
            )
        if total > 0:
            console.print(
                f"    [dim]Total banned: {total}[/dim]"
            )

    console.print()


def _print_banned_ips(client_status: dict) -> None:
    """Приказује активно блокиране IP адресе."""
    jails_status = client_status.get("jails", {})

    if not jails_status:
        return

    has_bans = False

    for jail_name, details in jails_status.items():
        ips = details.get("banned_ips", [])
        if ips:
            has_bans = True

    if not has_bans:
        return

    console.print("[bold red]Banned IPs:[/bold red]\n")

    for jail_name, details in jails_status.items():
        ips = details.get("banned_ips", [])
        if not ips:
            continue

        console.print(f"  [bold]{jail_name}:[/bold]")
        for ip in ips[:20]:
            console.print(f"    [red]{ip}[/red]")

        if len(ips) > 20:
            console.print(
                f"    [dim]... and {len(ips) - 20} more[/dim]"
            )

    console.print()


def _format_duration(seconds: int) -> str:
    """Претвара секунде у читљив облик."""
    if seconds < 60:
        return f"{seconds}s"

    if seconds < 3600:
        return f"{seconds // 60}m"

    if seconds < 86400:
        return f"{seconds // 3600}h"

    return f"{seconds // 86400}d"