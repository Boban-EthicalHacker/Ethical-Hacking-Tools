# Модул за приказ основних информација о Linux систему.
# Чита податке из /etc/os-release и покреће основне команде
# (uname, uptime). Ради на локалном систему без потребе за
# привилегијама.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import platform
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console

console = Console()

# Путања до фајла са информацијама о дистрибуцији.
OS_RELEASE = Path("/etc/os-release")


def run() -> dict:
    """Приказује основне информације о систему.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]System information[/bold cyan]\n")

    # Прикупљамо податке у речник.
    data: dict = {}

    data["hostname"] = _get_hostname()
    data.update(_get_os_info())
    data["kernel"] = platform.release()
    data["architecture"] = platform.machine()

    uptime_data = _get_uptime_data()
    data.update(uptime_data)

    # Приказујемо на екран.
    _print_data(data)

    return data


def _get_hostname() -> str:
    """Враћа име рачунара."""
    return platform.node()


def _get_os_info() -> dict:
    """Чита /etc/os-release и враћа речник са подацима о дистрибуцији."""
    result = {
        "os_pretty_name": None,
        "os_id": None,
        "os_version_id": None,
    }

    if not OS_RELEASE.exists():
        return result

    try:
        content = OS_RELEASE.read_text(encoding="utf-8")
    except Exception:
        return result

    # Парсирамо KEY=VALUE линије.
    data: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        value = value.strip().strip("'\"")
        data[key] = value

    result["os_pretty_name"] = data.get("PRETTY_NAME")
    result["os_id"] = data.get("ID")
    result["os_version_id"] = data.get("VERSION_ID")

    return result


def _get_uptime_data() -> dict:
    """Враћа речник са uptime и boot time."""
    result = {
        "uptime_seconds": None,
        "uptime_human": None,
        "boot_time": None,
    }

    uptime_seconds = _get_uptime_seconds()
    if uptime_seconds is None:
        return result

    result["uptime_seconds"] = int(uptime_seconds)
    result["uptime_human"] = _format_uptime(uptime_seconds)

    boot_time = datetime.now() - timedelta(seconds=uptime_seconds)
    result["boot_time"] = boot_time.strftime("%Y-%m-%d %H:%M:%S")

    return result


def _get_uptime_seconds() -> float | None:
    """Враћа број секунди од подизања система.

    Прво покушава да чита /proc/uptime, затим као резерву
    користи команду `uptime`.
    """
    proc_uptime = Path("/proc/uptime")
    if proc_uptime.exists():
        try:
            content = proc_uptime.read_text().strip()
            first_value = content.split()[0]
            return float(first_value)
        except Exception:
            pass

    try:
        result = subprocess.run(
            ["uptime", "-p"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return None
    except Exception:
        pass

    return None


def _format_uptime(seconds: float) -> str:
    """Претвара секунде у читљив облик (дани, сати, минути)."""
    total = int(seconds)

    days = total // 86400
    hours = (total % 86400) // 3600
    minutes = (total % 3600) // 60

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0 or not parts:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return ", ".join(parts)


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    console.print(f"[bold]Hostname:[/bold]       {data['hostname']}")

    if data.get("os_pretty_name"):
        console.print(f"[bold]OS:[/bold]             {data['os_pretty_name']}")
    if data.get("os_id"):
        console.print(f"[bold]OS ID:[/bold]          {data['os_id']}")
    if data.get("os_version_id"):
        console.print(f"[bold]OS version:[/bold]     {data['os_version_id']}")

    console.print(f"[bold]Kernel:[/bold]         {data['kernel']}")
    console.print(f"[bold]Architecture:[/bold]   {data['architecture']}")

    if data.get("uptime_human"):
        console.print(f"[bold]Uptime:[/bold]         {data['uptime_human']}")
    if data.get("boot_time"):
        console.print(f"[bold]Boot time:[/bold]      {data['boot_time']}")