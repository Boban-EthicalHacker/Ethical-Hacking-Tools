# Модул за приказ информација о времену и синхронизацији.
# Чита временску зону, NTP статус и тренутно време.
# Погрешно време може да утиче на TLS сертификате, логове,
# Kerberos аутентикацију и cron задатке.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
LOCALTIME_LINK = Path("/etc/localtime")
TIMEZONE_FILE = Path("/etc/timezone")


def run() -> dict:
    """Приказује информације о времену и синхронизацији.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Time information[/bold cyan]\n")

    data = {
        "current_time_utc": datetime.now(timezone.utc).isoformat(),
        "current_time_local": datetime.now().isoformat(),
        "timezone": _read_timezone(),
        "ntp": _read_ntp_status(),
        "timedatectl": _read_timedatectl(),
    }

    _print_data(data)

    return data


def _read_timezone() -> dict:
    """Чита временску зону.

    Прво покушава /etc/timezone, затим симлинк /etc/localtime.
    """
    result = {
        "name": None,
        "source": None,
    }

    # Прва опција — /etc/timezone фајл.
    if TIMEZONE_FILE.exists():
        try:
            value = TIMEZONE_FILE.read_text().strip()
            if value:
                result["name"] = value
                result["source"] = "/etc/timezone"
                return result
        except Exception:
            pass

    # Друга опција — симлинк /etc/localtime.
    if LOCALTIME_LINK.exists() and LOCALTIME_LINK.is_symlink():
        try:
            target = str(LOCALTIME_LINK.resolve())
            # Путања је типа /usr/share/zoneinfo/Europe/Belgrade
            if "zoneinfo/" in target:
                tz_name = target.split("zoneinfo/", 1)[1]
                result["name"] = tz_name
                result["source"] = "/etc/localtime"
        except Exception:
            pass

    return result


def _read_ntp_status() -> dict:
    """Чита NTP статус помоћу timedatectl команде."""
    result = {
        "synchronized": None,
        "ntp_service": None,
        "ntp_enabled": None,
    }

    # Покушавамо са timedatectl.
    try:
        proc = subprocess.run(
            ["timedatectl", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if proc.returncode != 0:
            return result

        # Парсирамо KEY=VALUE линије.
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key == "NTPSynchronized":
                result["synchronized"] = value.lower() == "yes"
            elif key == "NTP":
                result["ntp_enabled"] = value.lower() == "yes"
            elif key == "NTPMessage":
                pass

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return result
    except Exception:
        return result

    return result


def _read_timedatectl() -> dict:
    """Чита пуну timedatectl информацију."""
    result = {}

    try:
        proc = subprocess.run(
            ["timedatectl", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if proc.returncode != 0:
            return result

        # Кључни параметри које желимо.
        interesting = [
            "Timezone",
            "LocalRTC",
            "CanNTP",
            "NTP",
            "NTPSynchronized",
            "TimeUSec",
            "RTCUSec",
        ]

        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key in interesting:
                result[key] = value

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return result
    except Exception:
        return result

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    # Тренутно време.
    console.print(f"[bold]UTC time:[/bold]        {data['current_time_utc']}")
    console.print(f"[bold]Local time:[/bold]      {data['current_time_local']}")

    # Временска зона.
    tz = data.get("timezone", {})
    if tz.get("name"):
        source = f" [dim](from {tz['source']})[/dim]" if tz.get("source") else ""
        console.print(f"[bold]Timezone:[/bold]        {tz['name']}{source}")
    else:
        console.print("[bold]Timezone:[/bold]        [dim]unknown[/dim]")

    # NTP.
    ntp = data.get("ntp", {})
    console.print()

    if ntp.get("synchronized") is True:
        console.print(
            "[bold]NTP sync:[/bold]       [green]synchronized[/green]"
        )
    elif ntp.get("synchronized") is False:
        console.print(
            "[bold]NTP sync:[/bold]       [red]not synchronized[/red]"
        )
    else:
        console.print("[bold]NTP sync:[/bold]       [dim]unknown[/dim]")

    if ntp.get("ntp_enabled") is True:
        console.print("[bold]NTP enabled:[/bold]    [green]yes[/green]")
    elif ntp.get("ntp_enabled") is False:
        console.print("[bold]NTP enabled:[/bold]    [yellow]no[/yellow]")

    # timedatectl детаљи.
    td = data.get("timedatectl", {})
    if td:
        console.print()
        console.print("[bold]Details:[/bold]\n")

        labels = {
            "Timezone": "Timezone",
            "LocalRTC": "Local RTC",
            "CanNTP": "Can use NTP",
            "NTP": "NTP enabled",
            "NTPSynchronized": "NTP synchronized",
        }

        for key, label in labels.items():
            if key in td:
                console.print(f"  {label:20s}  {td[key]}")

    console.print()