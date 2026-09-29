# Модул за приказ променљивих окружења.
# Променљиве окружења могу да садрже осетљиве податке —
# API кључеве, токене, лозинке, путање до конфигурација.
# Ово је чест пропуст у Docker контејнерима и CI/CD системима.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Путања до фајла са environment тренутног процеса.
PROC_ENVIRON = Path("/proc/self/environ")

# Патерни који указују на осетљиве променљиве.
# Ако се име променљиве поклопи са неким од ових, означавамо је.
SENSITIVE_PATTERNS = [
    r"PASSWORD",
    r"PASSWD",
    r"PASS$",
    r"SECRET",
    r"TOKEN",
    r"API_?KEY",
    r"APIKEY",
    r"PRIVATE_?KEY",
    r"ACCESS_?KEY",
    r"CREDENTIAL",
    r"BEARER",
    r"JWT",
    r"COOKIE",
    r"DATABASE_URL",
    r"DB_?PASS",
    r"REDIS_?PASS",
    r"AWS_",
    r"AZURE_",
    r"GCP_",
    r"GOOGLE_",
    r"STRIPE_",
    r"SENDGRID_",
    r"MAILGUN_",
    r"TWILIO_",
    r"SLACK_",
    r"DISCORD_",
    # Специфични за аутентикацију (уместо генеричког AUTH).
    r"AUTH_?TOKEN",
    r"AUTHORIZATION",
    r"OAUTH",
]

# Компајлирамо патерне у један regex за брзу проверу.
SENSITIVE_RE = re.compile("|".join(SENSITIVE_PATTERNS), re.IGNORECASE)

# Променљиве које нису осетљиве и не приказујемо их
# (велике, бескорисне или системске).
IGNORED_VARS = {
    "LS_COLORS",
    "PS1",
    "PS2",
}


def run() -> dict:
    """Приказује променљиве окружења.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Environment variables[/bold cyan]\n")

    # Читамо променљиве из тренутног процеса.
    env_vars = _read_current_env()

    # Проверавамо и /proc/self/environ као додатни извор.
    proc_env = _read_proc_environ()

    # Спајамо — /proc/self/environ може имати више од os.environ.
    all_vars = {**proc_env, **env_vars}

    # Раздвајамо на осетљиве и остале.
    sensitive = []
    normal = []

    for key, value in all_vars.items():
        # Прескачемо велике променљиве које не вреди приказивати.
        if key in IGNORED_VARS:
            continue

        entry = {
            "name": key,
            "value": value,
            "sensitive": bool(SENSITIVE_RE.search(key)),
        }

        if entry["sensitive"]:
            sensitive.append(entry)
        else:
            normal.append(entry)

    data = {
        "total": len(all_vars),
        "sensitive": sorted(sensitive, key=lambda x: x["name"]),
        "normal": sorted(normal, key=lambda x: x["name"]),
    }

    _print_data(data)

    return data


def _read_current_env() -> dict:
    """Чита променљиве из os.environ."""
    try:
        return dict(os.environ)
    except Exception:
        return {}


def _read_proc_environ() -> dict:
    """Чита променљиве из /proc/self/environ.

    Формат фајла је "NAME=value\\0NAME=value\\0..." (раздвојено NUL).
    """
    if not PROC_ENVIRON.exists():
        return {}

    try:
        content = PROC_ENVIRON.read_bytes()
    except Exception:
        return {}

    result = {}

    # Раздвајамо по NUL бајту.
    for entry in content.split(b"\x00"):
        if not entry:
            continue

        # Свака променљива је NAME=value.
        if b"=" not in entry:
            continue

        name_bytes, value_bytes = entry.split(b"=", 1)

        try:
            name = name_bytes.decode("utf-8", errors="replace")
            value = value_bytes.decode("utf-8", errors="replace")
            result[name] = value
        except Exception:
            continue

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    total = data.get("total", 0)
    sensitive = data.get("sensitive", [])
    normal = data.get("normal", [])

    console.print(f"[bold]Total variables:[/bold] {total}")

    if sensitive:
        console.print(
            f"[bold]Sensitive variables:[/bold] "
            f"[bold red]{len(sensitive)}[/bold red]\n"
        )
    else:
        console.print("[bold]Sensitive variables:[/bold] [green]0[/green]\n")

    # Приказујемо осетљиве.
    if sensitive:
        console.print("[bold red]Sensitive:[/bold red]\n")
        for entry in sensitive:
            # За осетљиве приказујемо маскирану вредност.
            value = entry["value"]
            masked = _mask_value(value)

            console.print(
                f"  [bold red]{entry['name']}[/bold red] = "
                f"[red]{masked}[/red]"
            )
        console.print()

    # Приказујемо нормалне (првих 30).
    if normal:
        console.print(f"[bold]All variables ({len(normal)}):[/bold]\n")

        limit = 30
        for entry in normal[:limit]:
            value = entry["value"]

            # Скраћујемо предугачке вредности.
            if len(value) > 80:
                value = value[:77] + "..."

            console.print(f"  {entry['name']} = {value}")

        if len(normal) > limit:
            remaining = len(normal) - limit
            console.print(f"  [dim]... and {remaining} more[/dim]")

        console.print()


def _mask_value(value: str) -> str:
    """Маскира осетљиву вредност.

    Кратке вредности (до 12 знакова) маскира целе,
    дуге приказује првих 12 знакова.
    """
    if not value:
        return "(empty)"

    if len(value) <= 12:
        return "*" * len(value)

    return value[:12] + "..."