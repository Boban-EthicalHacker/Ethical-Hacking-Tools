# Модул за приказ основних информација о Linux систему.
# Чита податке из /etc/os-release и покреће основне команде
# (uname, uptime). Ради на локалном систему без потребе за
# привилегијама.
import platform
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console

console = Console()

# Путања до фајла са информацијама о дистрибуцији.
OS_RELEASE = Path("/etc/os-release")


def run() -> None:
    """Приказује основне информације о систему."""
    console.print("\n[bold cyan]System information[/bold cyan]\n")

    # Основни подаци.
    _print_hostname()
    _print_os_info()
    _print_kernel()
    _print_architecture()
    _print_uptime()


def _print_hostname() -> None:
    """Приказује име рачунара."""
    hostname = platform.node()
    console.print(f"[bold]Hostname:[/bold]       {hostname}")


def _print_os_info() -> None:
    """Приказује информације о дистрибуцији из /etc/os-release."""
    if not OS_RELEASE.exists():
        console.print("[bold]OS:[/bold]             [dim]unknown[/dim]")
        return

    try:
        # Читамо фајл као текст.
        content = OS_RELEASE.read_text(encoding="utf-8")
    except Exception as error:
        console.print(f"[bold]OS:[/bold]             [red]error: {error}[/red]")
        return

    # Парсирамо KEY=VALUE линије.
    data: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)

        # Уклањамо наводнике око вредности.
        value = value.strip().strip("'\"")

        data[key] = value

    # Приказујемо основне податке.
    name = data.get("NAME", "Unknown")
    version = data.get("VERSION", "")
    pretty = data.get("PRETTY_NAME", "")

    if pretty:
        console.print(f"[bold]OS:[/bold]             {pretty}")
    else:
        console.print(f"[bold]OS:[/bold]             {name} {version}".strip())

    # ID и VERSION_ID су корисни за програме.
    os_id = data.get("ID")
    version_id = data.get("VERSION_ID")

    if os_id:
        console.print(f"[bold]OS ID:[/bold]          {os_id}")
    if version_id:
        console.print(f"[bold]OS version:[/bold]     {version_id}")


def _print_kernel() -> None:
    """Приказује верзију кернела."""
    kernel = platform.release()
    console.print(f"[bold]Kernel:[/bold]         {kernel}")


def _print_architecture() -> None:
    """Приказује архитектуру процесора."""
    arch = platform.machine()
    console.print(f"[bold]Architecture:[/bold]   {arch}")


def _print_uptime() -> None:
    """Приказује колико дуго систем ради.

    Користи /proc/uptime (Linux специфично) или команду uptime
    као резервну опцију.
    """
    uptime_seconds = _get_uptime_seconds()

    if uptime_seconds is None:
        console.print("[bold]Uptime:[/bold]         [dim]unknown[/dim]")
        return

    # Форматирамо време.
    uptime_str = _format_uptime(uptime_seconds)
    console.print(f"[bold]Uptime:[/bold]         {uptime_str}")

    # Приказујемо и кад је систем подигнут.
    boot_time = datetime.now() - timedelta(seconds=uptime_seconds)
    boot_str = boot_time.strftime("%Y-%m-%d %H:%M:%S")
    console.print(f"[bold]Boot time:[/bold]      {boot_str}")


def _get_uptime_seconds() -> float | None:
    """Враћа број секунди од подизања система.

    Прво покушава да чита /proc/uptime (најбрже и најтачније),
    затим као резерву користи команду `uptime`.
    """
    # Прва опција — /proc/uptime.
    proc_uptime = Path("/proc/uptime")
    if proc_uptime.exists():
        try:
            content = proc_uptime.read_text().strip()
            # Формат: "12345.67 98765.43"
            # Први број је укупан uptime у секундама.
            first_value = content.split()[0]
            return float(first_value)
        except Exception:
            pass

    # Друга опција — команда uptime са -p форматом.
    try:
        result = subprocess.run(
            ["uptime", "-p"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            # Парсирање није тривијално, па враћамо None
            # и корисник види "unknown".
            # Алтернативно, могли бисмо да парсирамо излаз
            # као "up 5 days, 3 hours, 20 minutes".
            return _parse_uptime_text(result.stdout.strip())
    except Exception:
        pass

    return None


def _parse_uptime_text(text: str) -> float | None:
    """Парсира излаз команде 'uptime -p'.

    Пример: "up 2 weeks, 3 days, 4 hours, 5 minutes"
    """
    # Ово је резервна функција — не користимо је ако
    # /proc/uptime постоји. За сада враћамо None.
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