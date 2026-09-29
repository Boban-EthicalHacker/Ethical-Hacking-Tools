# Модул за приказ информација о кернелу.
# Кернел је срце Linux система. Његова верзија, учитани
# модули и параметри могу открити познате рањивости или
# необичне конфигурације.
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
PROC_VERSION = Path("/proc/version")
PROC_CMDLINE = Path("/proc/cmdline")
PROC_MODULES = Path("/proc/modules")
PROC_SYS_KERNEL = Path("/proc/sys/kernel")


def run() -> dict:
    """Приказује информације о кернелу.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Kernel information[/bold cyan]\n")

    # Прикупљамо податке.
    data: dict = {}

    data["version"] = _read_version()
    data["boot_parameters"] = _read_cmdline()
    data["loaded_modules"] = _read_modules()
    data["sysctl"] = _read_sysctl()

    # Приказујемо на екран.
    _print_data(data)

    return data


def _read_version() -> str | None:
    """Чита /proc/version."""
    if not PROC_VERSION.exists():
        return None

    try:
        return PROC_VERSION.read_text().strip()
    except Exception:
        return None


def _read_cmdline() -> list[str]:
    """Чита /proc/cmdline и враћа листу параметара."""
    if not PROC_CMDLINE.exists():
        return []

    try:
        content = PROC_CMDLINE.read_text().strip()
    except Exception:
        return []

    if not content:
        return []

    return content.split()


def _read_modules() -> list[dict]:
    """Чита /proc/modules и враћа листу модула."""
    if not PROC_MODULES.exists():
        return []

    try:
        content = PROC_MODULES.read_text()
    except Exception:
        return []

    modules = []

    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue

        name = parts[0]
        size = int(parts[1]) if parts[1].isdigit() else 0

        try:
            refcount = int(parts[2])
        except ValueError:
            refcount = 0

        modules.append({
            "name": name,
            "size_bytes": size,
            "refcount": refcount,
        })

    return modules


def _read_sysctl() -> dict:
    """Чита кључне sysctl параметре.

    Враћа речник са вредностима. Само они параметри који
    су доступни (неки захтевају root).
    """
    params = [
        "hostname",
        "ostype",
        "osrelease",
        "version",
        "randomize_va_space",
        "kptr_restrict",
        "dmesg_restrict",
        "yama/ptrace_scope",
        "unprivileged_bpf_disabled",
        "kexec_load_disabled",
    ]

    result = {}

    for key in params:
        path = PROC_SYS_KERNEL / key
        if not path.exists():
            continue

        try:
            value = path.read_text().strip()
            result[key] = value
        except Exception:
            continue

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    # Верзија.
    if data.get("version"):
        console.print(f"[bold]Version:[/bold]        {data['version']}")
        console.print()

    # Boot параметри.
    params = data.get("boot_parameters", [])
    if params:
        console.print("[bold]Boot parameters:[/bold]\n")
        for param in params:
            console.print(f"  {param}")
        console.print()

    # Модули.
    modules = data.get("loaded_modules", [])
    if modules:
        console.print(f"[bold]Loaded modules:[/bold] {len(modules)}\n")

        limit = 30
        for m in sorted(modules, key=lambda x: x["name"])[:limit]:
            size_str = _format_size(m["size_bytes"])
            console.print(
                f"  {m['name']:30s}  "
                f"[dim]{size_str:>10s}  refcount={m['refcount']}[/dim]"
            )

        if len(modules) > limit:
            remaining = len(modules) - limit
            console.print(f"  [dim]... and {remaining} more[/dim]")

        console.print()

    # Sysctl.
    sysctl = data.get("sysctl", {})
    if sysctl:
        console.print("[bold]Security-relevant sysctl:[/bold]\n")

        descriptions = {
            "randomize_va_space": "ASLR (2 = full, 0 = disabled)",
            "kptr_restrict": "Kernel pointer restriction",
            "dmesg_restrict": "dmesg access restriction",
            "yama/ptrace_scope": "ptrace scope",
            "unprivileged_bpf_disabled": "BPF for unprivileged",
            "kexec_load_disabled": "kexec disabled",
        }

        for key, value in sysctl.items():
            console.print(f"  {key:30s}  [cyan]{value}[/cyan]")
            if key in descriptions:
                console.print(f"  [dim]{descriptions[key]}[/dim]")
                console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"