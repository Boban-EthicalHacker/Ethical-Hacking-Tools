# Модул за приказ информација о подизању система.
# Чита bootloader конфигурацију (GRUB), init систем
# (systemd или OpenRC) и време последњег подизања.
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова и фолдера.
GRUB_CONFIG = Path("/boot/grub/grub.cfg")
GRUB_DEFAULT = Path("/etc/default/grub")
GRUB_DIR = Path("/etc/grub.d")
SYSTEMD_DIR = Path("/etc/systemd/system")
INIT_SYSTEMS = [
    ("systemd", Path("/run/systemd/system")),
    ("openrc", Path("/run/openrc")),
    ("sysvinit", Path("/etc/init.d")),
]


def run() -> dict:
    """Приказује информације о подизању система.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Boot information[/bold cyan]\n")

    data = {
        "init_system": _detect_init_system(),
        "grub": _read_grub_info(),
        "boot_entries": _read_boot_entries(),
    }

    _print_data(data)

    return data


def _detect_init_system() -> str | None:
    """Препознаје који init систем се користи."""
    for name, path in INIT_SYSTEMS:
        if path.exists():
            return name
    return None


def _read_grub_info() -> dict:
    """Чита основне GRUB параметре из /etc/default/grub."""
    result = {
        "default": None,
        "timeout": None,
        "cmdline": None,
    }

    if not GRUB_DEFAULT.exists():
        return result

    try:
        content = GRUB_DEFAULT.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")

        if key == "GRUB_DEFAULT":
            result["default"] = value
        elif key == "GRUB_TIMEOUT":
            result["timeout"] = value
        elif key == "GRUB_CMDLINE_LINUX_DEFAULT":
            result["cmdline"] = value

    return result


def _read_boot_entries() -> list[dict]:
    """Чита доступне boot entries из grub.cfg.

    Ово је груба анализа — тражимо "menuentry" линије.
    """
    if not GRUB_CONFIG.exists():
        return []

    try:
        content = GRUB_CONFIG.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return []
    except Exception:
        return []

    entries = []

    for line in content.splitlines():
        line = line.strip()

        # GRUB користи "menuentry 'Name' {" синтаксу.
        if not line.startswith("menuentry"):
            continue

        # Извлачимо име између наводника.
        # Пример: menuentry 'Kali GNU/Linux' --class kali {
        name = _extract_menuentry_name(line)
        if name:
            entries.append({"name": name})

    return entries


def _extract_menuentry_name(line: str) -> str | None:
    """Извлачи име из GRUB menuentry линије."""
    # Тражимо први наводник.
    quote_start = None
    quote_char = None

    for i, ch in enumerate(line):
        if ch in ("'", '"'):
            quote_start = i
            quote_char = ch
            break

    if quote_start is None:
        return None

    # Тражимо затварајући наводник.
    quote_end = line.find(quote_char, quote_start + 1)
    if quote_end == -1:
        return None

    return line[quote_start + 1 : quote_end]


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    # Init систем.
    init_system = data.get("init_system")
    if init_system:
        console.print(f"[bold]Init system:[/bold]    {init_system}")
    else:
        console.print("[bold]Init system:[/bold]    [dim]unknown[/dim]")

    # GRUB.
    grub = data.get("grub", {})
    if grub.get("default") or grub.get("timeout") or grub.get("cmdline"):
        console.print("\n[bold]GRUB configuration[/bold]\n")

        if grub.get("default"):
            console.print(f"  [bold]Default:[/bold]    {grub['default']}")
        if grub.get("timeout"):
            console.print(f"  [bold]Timeout:[/bold]    {grub['timeout']}s")
        if grub.get("cmdline"):
            console.print(f"  [bold]Cmdline:[/bold]    {grub['cmdline']}")

        console.print()

    # Boot entries.
    entries = data.get("boot_entries", [])
    if entries:
        console.print(f"[bold]Boot entries ({len(entries)}):[/bold]\n")
        for entry in entries:
            console.print(f"  {entry['name']}")
        console.print()
    else:
        console.print(
            "[bold]Boot entries:[/bold]  [dim]none readable "
            "(requires root)[/dim]\n"
        )