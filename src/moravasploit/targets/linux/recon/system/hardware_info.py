# Модул за приказ информација о хардверу.
# Чита податке из /proc/cpuinfo, /proc/meminfo, /sys/class/dmi
# и других системских фајлова. Не захтева root привилегије.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
PROC_CPUINFO = Path("/proc/cpuinfo")
PROC_MEMINFO = Path("/proc/meminfo")
SYS_DMI = Path("/sys/class/dmi/id")
SYS_BLOCK = Path("/sys/block")


def run() -> dict:
    """Приказује информације о хардверу.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Hardware information[/bold cyan]\n")

    # Прикупљамо податке.
    data: dict = {}

    data["system"] = _read_system_vendor()
    data["cpu"] = _read_cpu()
    data["memory"] = _read_memory()
    data["disks"] = _read_disks()

    # Приказујемо на екран.
    _print_data(data)

    return data


def _read_system_vendor() -> dict:
    """Чита DMI податке о произвођачу и моделу."""
    result = {}

    if not SYS_DMI.exists():
        return result

    fields = {
        "sys_vendor": "vendor",
        "product_name": "product",
        "product_version": "version",
        "board_vendor": "board_vendor",
        "board_name": "board_name",
        "bios_vendor": "bios_vendor",
        "bios_version": "bios_version",
    }

    for file_name, key in fields.items():
        path = SYS_DMI / file_name
        if not path.exists():
            continue

        try:
            value = path.read_text().strip()
        except (PermissionError, Exception):
            continue

        if value:
            result[key] = value

    return result


def _read_cpu() -> dict:
    """Чита информације о процесору из /proc/cpuinfo."""
    result = {
        "model": None,
        "vendor": None,
        "cores_logical": os.cpu_count() or 0,
        "flags_security": [],
    }

    if not PROC_CPUINFO.exists():
        return result

    try:
        content = PROC_CPUINFO.read_text()
    except Exception:
        return result

    flags = []

    for line in content.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key == "model name" and result["model"] is None:
            result["model"] = value
        elif key == "vendor_id" and result["vendor"] is None:
            result["vendor"] = value
        elif key == "flags" and not flags:
            flags = value.split()

    # Безбедносно важни flags.
    interesting = [
        "nx", "smep", "smap", "pti", "aes", "sha_ni",
        "rdrand", "vmx", "svm",
    ]

    result["flags_security"] = [f for f in interesting if f in flags]

    return result


def _read_memory() -> dict:
    """Чита информације о меморији из /proc/meminfo."""
    result = {
        "total_bytes": None,
        "free_bytes": None,
        "available_bytes": None,
        "buffers_bytes": None,
        "cached_bytes": None,
        "swap_total_bytes": None,
        "swap_free_bytes": None,
    }

    if not PROC_MEMINFO.exists():
        return result

    try:
        content = PROC_MEMINFO.read_text()
    except Exception:
        return result

    # Парсирамо /proc/meminfo.
    values = {}
    for line in content.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        parts = value.split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0]) * 1024  # у бајтове

    result["total_bytes"] = values.get("MemTotal")
    result["free_bytes"] = values.get("MemFree")
    result["available_bytes"] = values.get("MemAvailable")
    result["buffers_bytes"] = values.get("Buffers")
    result["cached_bytes"] = values.get("Cached")
    result["swap_total_bytes"] = values.get("SwapTotal")
    result["swap_free_bytes"] = values.get("SwapFree")

    return result


def _read_disks() -> list[dict]:
    """Чита физичке дискове из /sys/block."""
    if not SYS_BLOCK.exists():
        return []

    try:
        disks = [d for d in SYS_BLOCK.iterdir() if d.is_dir()]
    except Exception:
        return []

    result = []

    for disk in sorted(disks, key=lambda x: x.name):
        name = disk.name

        # Прескачемо виртуелне уређаје.
        if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
            continue

        size = _read_disk_size(disk)
        model = _read_disk_model(disk)

        result.append({
            "name": name,
            "size_bytes": size,
            "model": model,
        })

    return result


def _read_disk_size(disk_path: Path) -> int | None:
    """Чита величину диска из /sys/block/<disk>/size (у 512B секторима)."""
    size_file = disk_path / "size"
    if not size_file.exists():
        return None

    try:
        sectors = int(size_file.read_text().strip())
        return sectors * 512
    except Exception:
        return None


def _read_disk_model(disk_path: Path) -> str | None:
    """Чита модел диска из /sys/block/<disk>/device/model."""
    model_file = disk_path / "device" / "model"
    if not model_file.exists():
        return None

    try:
        return model_file.read_text().strip()
    except Exception:
        return None


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    # Систем.
    system = data.get("system", {})
    if system:
        if system.get("vendor"):
            console.print(f"[bold]System vendor:[/bold]  {system['vendor']}")
        if system.get("product"):
            console.print(f"[bold]System model:[/bold]   {system['product']}")
        if system.get("bios_vendor"):
            console.print(f"[bold]BIOS vendor:[/bold]    {system['bios_vendor']}")
        if system.get("bios_version"):
            console.print(f"[bold]BIOS version:[/bold]   {system['bios_version']}")
        console.print()

    # CPU.
    cpu = data.get("cpu", {})
    if cpu.get("model"):
        console.print("[bold]CPU[/bold]\n")
        console.print(f"  [bold]Model:[/bold]     {cpu['model']}")
        if cpu.get("vendor"):
            console.print(f"  [bold]Vendor:[/bold]    {cpu['vendor']}")
        console.print(f"  [bold]Cores:[/bold]     {cpu['cores_logical']} logical")

        flags = cpu.get("flags_security", [])
        if flags:
            console.print(
                f"\n  [bold]Security flags:[/bold]  "
                f"[green]{', '.join(flags)}[/green]"
            )
        console.print()

    # Меморија.
    mem = data.get("memory", {})
    if mem.get("total_bytes"):
        console.print("[bold]Memory[/bold]\n")
        console.print(
            f"  [bold]Total:[/bold]      {_format_size(mem['total_bytes'])}"
        )
        if mem.get("available_bytes"):
            console.print(
                f"  [bold]Available:[/bold]  "
                f"{_format_size(mem['available_bytes'])}"
            )
        if mem.get("swap_total_bytes"):
            console.print(
                f"  [bold]Swap:[/bold]       "
                f"{_format_size(mem['swap_free_bytes'])} / "
                f"{_format_size(mem['swap_total_bytes'])}"
            )
        console.print()

    # Дискови.
    disks = data.get("disks", [])
    if disks:
        console.print("[bold]Disks[/bold]\n")
        for disk in disks:
            line = f"  [bold]{disk['name']}[/bold]"
            if disk.get("size_bytes"):
                line += f"  [dim]{_format_size(disk['size_bytes'])}[/dim]"
            if disk.get("model"):
                line += f"  [dim]({disk['model']})[/dim]"
            console.print(line)
        console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"