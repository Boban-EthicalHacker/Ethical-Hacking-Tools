# Модул за проналажење фајлова са Linux capabilities.
# Capabilities су финије дозволе од SUID-а. Ако фајл има
# cap_sys_admin или сличне, може да постане root.
# Ово је често заборављен пут за privilege escalation.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми које прескачемо при претрази.
SKIP_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/lib/containers",
    "/mnt",
    "/media",
}

# Опасне capabilities које могу да доведу до privilege escalation.
DANGEROUS_CAPS = {
    "cap_sys_admin": "Full system administration (close to root)",
    "cap_sys_ptrace": "Trace any process (can inject code)",
    "cap_sys_module": "Load kernel modules",
    "cap_sys_rawio": "Raw I/O access",
    "cap_sys_boot": "Reboot system",
    "cap_sys_chroot": "Change root directory",
    "cap_setuid": "Change user ID (can become root)",
    "cap_setgid": "Change group ID",
    "cap_setpcap": "Change capabilities",
    "cap_dac_override": "Bypass file permission checks",
    "cap_dac_read_search": "Read any file",
    "cap_fowner": "Bypass file owner checks",
    "cap_chown": "Change file ownership",
    "cap_net_admin": "Network administration",
    "cap_net_raw": "Raw network access",
    "cap_kill": "Send signals to any process",
    "cap_audit_write": "Write to audit log",
    "cap_mac_admin": "MAC administration",
    "cap_mac_override": "Bypass MAC",
    "cap_linux_immutable": "Set immutable flag",
}

# Максимална дубина претраге.
MAX_DEPTH = 8


def run() -> dict:
    """Проналази фајлове са Linux capabilities.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Linux capabilities[/bold cyan]\n")

    # Проверавамо да ли је getcap доступан.
    if not shutil.which("getcap"):
        console.print(
            "  [yellow]Command 'getcap' not found.[/yellow]\n"
        )
        console.print(
            "  [dim]Install 'libcap2-bin' to enable this module.[/dim]\n"
        )
        return _empty_result()

    console.print(
        "[dim]Searching for files with capabilities set. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо све фајлове са capabilities.
    files = _find_capability_files()

    # Анализирамо опасне.
    dangerous = _find_dangerous(files)

    data = {
        "capability_files": files,
        "dangerous": dangerous,
        "summary": {
            "total_files": len(files),
            "dangerous_count": len(dangerous),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат кад getcap није доступан."""
    return {
        "capability_files": [],
        "dangerous": [],
        "summary": {
            "total_files": 0,
            "dangerous_count": 0,
        },
    }


def _find_capability_files() -> list[dict]:
    """Претражује систем за фајловима са capabilities.

    Користимо getcap -r / који рекурзивно претражује.
    """
    try:
        result = subprocess.run(
            ["getcap", "-r", "/"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    # getcap писање грешке на stderr (нпр. permission denied),
    # а резултате на stdout. Читамо само stdout.
    output = result.stdout
    if not output:
        return []

    files = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Формат: /path/to/file cap_name=value,cap_name=value
        # На пример: /usr/bin/ping cap_net_raw=ep
        if " " not in line:
            continue

        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        file_path = parts[0]
        caps_str = parts[1]

        # Парсирамо capabilities.
        caps = _parse_caps(caps_str)

        files.append({
            "path": file_path,
            "capabilities_raw": caps_str,
            "capabilities": caps,
        })

    return files


def _parse_caps(caps_str: str) -> list[dict]:
    """Парсира capabilities из getcap формата.

    getcap формат може бити:
        cap_net_raw=ep
        cap_net_bind_service,cap_net_admin,cap_net_raw=eip

    У другом случају, flags важе за СВЕ наведене capability-је.
    """
    caps_str = caps_str.strip()
    if not caps_str:
        return []

    # Прво раздвајамо по "=" — flags су након знака.
    if "=" in caps_str:
        names_part, flags = caps_str.rsplit("=", 1)
    else:
        names_part = caps_str
        flags = ""

    # Затим раздвајамо имена по зарезу.
    result = []
    for name in names_part.split(","):
        name = name.strip()
        if not name:
            continue

        result.append({
            "name": name,
            "flags": flags,
        })

    return result

def _find_dangerous(files: list[dict]) -> list[dict]:
    """Проналази фајлове са опасним capabilities."""
    dangerous = []

    for entry in files:
        for cap in entry.get("capabilities", []):
            cap_name = cap["name"].lower()

            if cap_name in DANGEROUS_CAPS:
                dangerous.append({
                    "path": entry["path"],
                    "capability": cap_name,
                    "flags": cap["flags"],
                    "description": DANGEROUS_CAPS[cap_name],
                    "raw": entry["capabilities_raw"],
                })

    return dangerous


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    files = data.get("capability_files", [])
    dangerous = data.get("dangerous", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Files with capabilities:[/bold]  "
        f"{summary.get('total_files', 0)}"
    )
    console.print(
        f"[bold]Dangerous capabilities:[/bold]   "
        f"{summary.get('dangerous_count', 0)}"
    )
    console.print()

    if not files:
        console.print(
            "  [dim]No files with capabilities found.[/dim]\n"
        )
        return

    # Приказујемо опасне прво.
    if dangerous:
        console.print(
            f"[bold red]Dangerous findings ({len(dangerous)}):[/bold red]\n"
        )
        for item in dangerous:
            _print_dangerous(item)
        console.print()

    # Приказујемо све фајлове.
    console.print(f"[bold]All capability files ({len(files)}):[/bold]\n")

    for entry in files:
        _print_file(entry)

    console.print()


def _print_dangerous(item: dict) -> None:
    """Приказује један опасан налаз."""
    console.print(
        f"  [bold red]{item['path']}[/bold red]"
    )
    console.print(
        f"    Capability: [red]{item['capability']}[/red] "
        f"({item['description']})"
    )
    console.print(
        f"    [dim]Flags: {item['flags']}[/dim]"
    )
    console.print()


def _print_file(entry: dict) -> None:
    """Приказује један фајл са capabilities."""
    console.print(f"  [bold]{entry['path']}[/bold]")

    for cap in entry.get("capabilities", []):
        cap_name = cap["name"]
        flags = cap["flags"]

        # Боја — црвено за опасне.
        if cap_name.lower() in DANGEROUS_CAPS:
            console.print(
                f"    [red]{cap_name}={flags}[/red]"
            )
        else:
            console.print(
                f"    [dim]{cap_name}={flags}[/dim]"
            )

    console.print()