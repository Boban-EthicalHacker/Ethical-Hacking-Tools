# Модул за приказ информација о кернелу.
# Кернел је срце Linux система. Његова верзија, учитани
# модули и параметри могу открити познате рањивости или
# необичне конфигурације.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до системских фајлова.
PROC_VERSION = Path("/proc/version")
PROC_CMDLINE = Path("/proc/cmdline")
PROC_MODULES = Path("/proc/modules")
PROC_SYS_KERNEL = Path("/proc/sys/kernel")


def run() -> None:
    """Приказује информације о кернелу."""
    console.print("\n[bold cyan]Kernel information[/bold cyan]\n")

    # Основне информације.
    _print_version()

    # Параметри покретања кернела.
    _print_cmdline()

    # Учитани модули кернела.
    _print_modules()

    # Кључни sysctl параметри.
    _print_sysctl()


def _print_version() -> None:
    """Приказује верзију кернела из /proc/version."""
    if not PROC_VERSION.exists():
        return

    try:
        content = PROC_VERSION.read_text().strip()
    except Exception:
        return

    # /proc/version изгледа овако:
    # "Linux version 6.11.2-amd64 (debian-kernel@lists.debian.org)
    #  (gcc-12 ...) #1 SMP PREEMPT_DYNAMIC ..."
    console.print(f"[bold]Version:[/bold]        {content}")
    console.print()


def _print_cmdline() -> None:
    """Приказује параметре покретања кернела."""
    if not PROC_CMDLINE.exists():
        return

    try:
        content = PROC_CMDLINE.read_text().strip()
    except Exception:
        return

    if not content:
        console.print("[bold]Boot parameters:[/bold] [dim]none[/dim]\n")
        return

    console.print("[bold]Boot parameters:[/bold]\n")

    # Параметри су раздвојени размацима.
    params = content.split()

    for param in params:
        console.print(f"  {param}")

    console.print()


def _print_modules() -> None:
    """Приказује учитане модуле кернела."""
    if not PROC_MODULES.exists():
        return

    try:
        content = PROC_MODULES.read_text()
    except Exception:
        return

    # Свака линија има формат:
    # name size refcount dependencies state address
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
            "size": size,
            "refcount": refcount,
        })

    if not modules:
        console.print("[bold]Loaded modules:[/bold] [dim]none[/dim]\n")
        return

    console.print(f"[bold]Loaded modules:[/bold] {len(modules)}\n")

    # Приказујемо првих 30 модула.
    limit = 30
    for m in sorted(modules, key=lambda x: x["name"])[:limit]:
        size_str = _format_size(m["size"])
        console.print(
            f"  {m['name']:30s}  "
            f"[dim]{size_str:>10s}  refcount={m['refcount']}[/dim]"
        )

    if len(modules) > limit:
        remaining = len(modules) - limit
        console.print(f"  [dim]... and {remaining} more[/dim]")

    console.print()


def _print_sysctl() -> None:
    """Приказује кључне sysctl параметре."""
    # Параметри који су важни за безбедност.
    params = {
        "hostname": "Hostname",
        "ostype": "OS type",
        "osrelease": "OS release",
        "version": "Full version",
        "randomize_va_space": "ASLR (2 = full, 0 = disabled)",
        "kptr_restrict": "Kernel pointer restriction",
        "dmesg_restrict": "dmesg access restriction",
        "yama/ptrace_scope": "ptrace scope",
        "unprivileged_bpf_disabled": "BPF for unprivileged",
        "kexec_load_disabled": "kexec disabled",
    }

    console.print("[bold]Security-relevant sysctl:[/bold]\n")

    found_any = False

    for key, description in params.items():
        path = PROC_SYS_KERNEL / key
        if not path.exists():
            continue

        try:
            value = path.read_text().strip()
        except Exception:
            continue

        found_any = True
        console.print(f"  {key:30s}  [cyan]{value}[/cyan]")
        console.print(f"  [dim]{description}[/dim]")
        console.print()

    if not found_any:
        console.print("  [dim]No sysctl values accessible.[/dim]\n")


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"