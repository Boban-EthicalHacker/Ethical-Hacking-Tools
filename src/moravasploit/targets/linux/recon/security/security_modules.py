# Модул за приказ учитаних LSM модула и kernel security опција.
# Гледа дубље од selinux_apparmor — анализира kernel boot
# параметре, CPU vulnerability mitigations и memory hardening.
#
# Ово је "дубља" безбедносна анализа која открива да ли је
# кернел хардверски заштићен од познатих напада.
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до kernel security информација.
LSM_PATH = Path("/sys/kernel/security/lsm")
CPU_VULN_DIR = Path("/sys/devices/system/cpu/vulnerabilities")
PROC_CMDLINE = Path("/proc/cmdline")

# Kernel boot параметри који су важни за безбедност.
# Формат: (параметар, добар_да_постоји, опис)
SECURITY_BOOT_PARAMS = {
    "lockdown": {
        "values": {
            "none": ("dim", "no lockdown"),
            "integrity": ("green", "kernel integrity protected"),
            "confidentiality": ("green", "kernel confidentiality protected"),
        },
        "description": "Kernel lockdown mode",
    },
    "pti": {
        "values": {
            "on": ("green", "enabled (Meltdown protection)"),
            "off": ("red", "DISABLED (Meltdown vulnerable)"),
        },
        "description": "Page Table Isolation",
    },
    "slab_nomerge": {
        "values": {
            "": ("green", "enabled (heap hardening)"),
        },
        "description": "Slab allocator hardening",
        "flag": True,
    },
    "init_on_alloc": {
        "values": {
            "1": ("green", "enabled"),
            "0": ("yellow", "disabled"),
        },
        "description": "Zero memory on allocation",
    },
    "init_on_free": {
        "values": {
            "1": ("green", "enabled"),
            "0": ("yellow", "disabled"),
        },
        "description": "Zero memory on free",
    },
    "page_poison": {
        "values": {
            "1": ("green", "enabled"),
            "on": ("green", "enabled"),
        },
        "description": "Poison freed pages",
        "flag": True,
    },
    "page_alloc.shuffle": {
        "values": {
            "1": ("green", "enabled"),
            "on": ("green", "enabled"),
        },
        "description": "Randomize page allocator",
        "flag": True,
    },
    "randomize_kstack_offset": {
        "values": {
            "1": ("green", "enabled"),
            "on": ("green", "enabled"),
        },
        "description": "Randomize kernel stack offset",
        "flag": True,
    },
    "vsyscall": {
        "values": {
            "none": ("green", "disabled (secure)"),
            "xonly": ("yellow", "emulated"),
            "emulate": ("yellow", "emulated"),
            "native": ("red", "native (insecure)"),
        },
        "description": "vsyscall mode",
    },
    "debugfs": {
        "values": {
            "no": ("green", "disabled"),
            "off": ("green", "disabled"),
        },
        "description": "debugfs access",
        "inverted": True,  # ако није присутан, то је добро
    },
    "oops": {
        "values": {
            "panic": ("green", "panic on oops"),
        },
        "description": "Panic on kernel oops",
        "inverted": True,
    },
    "slub_debug": {
        "values": {
            "F": ("green", "full debug enabled"),
        },
        "description": "SLUB debug",
        "flag": True,
    },
}

# Познати LSM модули (за опис).
KNOWN_LSMS = {
    "selinux": "SELinux",
    "apparmor": "AppArmor",
    "smack": "Smack",
    "tomoyo": "Tomoyo",
    "yama": "Yama (ptrace restriction)",
    "lockdown": "Lockdown",
    "integrity": "Integrity (IMA/EVM)",
    "bpf": "BPF LSM",
    "landlock": "Landlock",
    "safeSetID": "SafeSetID",
    "capability": "Capability (base LSM)",
    "ipe": "IPE (Integrity Policy Enforcement)",
    "ima": "IMA (Integrity Measurement)",
    "evm": "EVM (Extended Verification)",
}


def run() -> dict:
    """Приказује kernel security информације.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Kernel security[/bold cyan]\n")

    # Читамо активне LSM модуле.
    active_lsms = _read_lsms()

    # Читамо kernel boot параметре.
    boot_params = _read_boot_params()

    # Читамо CPU vulnerability статусе.
    cpu_vulns = _read_cpu_vulnerabilities()

    # Анализирамо boot параметре.
    boot_analysis = _analyze_boot_params(boot_params)

    # Анализирамо CPU рањивости.
    cpu_analysis = _analyze_cpu_vulnerabilities(cpu_vulns)

    # Правимо резиме.
    summary = {
        "total_lsms": len(active_lsms),
        "has_mac": any(
            lsm["name"] in ("selinux", "apparmor", "smack", "tomoyo")
            for lsm in active_lsms
        ),
        "hardening_params": boot_analysis.get("enabled_count", 0),
        "missing_params": boot_analysis.get("missing_count", 0),
        "vulnerable_cpus": cpu_analysis.get("vulnerable_count", 0),
        "mitigated_cpus": cpu_analysis.get("mitigated_count", 0),
    }

    data = {
        "active_lsms": active_lsms,
        "boot_params": boot_params,
        "boot_analysis": boot_analysis,
        "cpu_vulnerabilities": cpu_vulns,
        "cpu_analysis": cpu_analysis,
        "summary": summary,
    }

    _print_data(data)

    return data


def _read_lsms() -> list[dict]:
    """Чита активне LSM модуле."""
    if not LSM_PATH.exists():
        return []

    try:
        content = LSM_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    names = [
        name.strip()
        for name in content.strip().split(",")
        if name.strip()
    ]

    result = []
    for name in names:
        # Категоризујемо модул.
        if name in ("selinux", "apparmor", "smack", "tomoyo"):
            category = "mac"
        elif name in ("yama", "lockdown"):
            category = "restriction"
        elif name in ("integrity", "ima", "evm", "ipe"):
            category = "integrity"
        elif name in ("bpf", "landlock"):
            category = "sandbox"
        else:
            category = "other"

        result.append({
            "name": name,
            "label": KNOWN_LSMS.get(name, name.title()),
            "category": category,
        })

    return result


def _read_boot_params() -> dict:
    """Чита /proc/cmdline и парсира параметре."""
    result = {
        "raw": None,
        "params": {},
    }

    if not PROC_CMDLINE.exists():
        return result

    try:
        content = PROC_CMDLINE.read_text(encoding="utf-8", errors="replace").strip()
        result["raw"] = content
    except Exception:
        return result

    # Парсирамо параметре.
    # Формат: key=value или само flag.
    for part in content.split():
        if not part:
            continue

        if "=" in part:
            key, value = part.split("=", 1)
            result["params"][key] = value
        else:
            # Flag без вредности.
            result["params"][part] = True

    return result


def _analyze_boot_params(boot_data: dict) -> dict:
    """Анализира kernel boot параметре."""
    params = boot_data.get("params", {})

    result = {
        "checked": [],
        "enabled_count": 0,
        "missing_count": 0,
        "problems": [],
    }

    for param_name, config in SECURITY_BOOT_PARAMS.items():
        description = config.get("description", "")
        values_map = config.get("values", {})
        is_flag = config.get("flag", False)
        is_inverted = config.get("inverted", False)

        # Проверавамо да ли је параметар присутан.
        if param_name in params:
            value = params[param_name]

            # Ако је flag (нема вредност).
            if is_flag or value is True:
                display_value = "(flag)"
                status = "enabled"
                color = "green"
                message = description
            else:
                # Тражимо у values_map.
                display_value = value
                if value in values_map:
                    color, message = values_map[value]
                    if color == "green":
                        status = "enabled"
                    elif color == "red":
                        status = "problem"
                    else:
                        status = "info"
                else:
                    color = "dim"
                    message = f"{description} (value: {value})"
                    status = "info"
        else:
            # Параметар није присутан.
            display_value = None

            if is_inverted:
                # Ако није присутан, то је добро (нпр. debugfs=no).
                status = "enabled"
                color = "green"
                message = f"{description} (default, not present)"
            else:
                status = "missing"
                color = "yellow"
                message = f"{description} (not set)"

        entry = {
            "parameter": param_name,
            "value": display_value,
            "status": status,
            "color": color,
            "description": description,
            "message": message,
        }

        result["checked"].append(entry)

        if status == "enabled":
            result["enabled_count"] += 1
        elif status in ("missing", "problem"):
            result["missing_count"] += 1
            if status == "problem":
                result["problems"].append(entry)

    return result


def _read_cpu_vulnerabilities() -> list[dict]:
    """Чита CPU vulnerability статусе."""
    result = []

    if not CPU_VULN_DIR.exists() or not CPU_VULN_DIR.is_dir():
        return result

    try:
        entries = sorted(CPU_VULN_DIR.iterdir())
    except (PermissionError, Exception):
        return result

    for entry in entries:
        if not entry.is_file():
            continue

        try:
            content = entry.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
        except Exception:
            continue

        # Оцењујемо статус.
        status, color = _evaluate_vulnerability_status(content)

        result.append({
            "name": entry.name,
            "status": content,
            "evaluated": status,
            "color": color,
        })

    return result


def _evaluate_vulnerability_status(status_text: str) -> tuple[str, str]:
    """Оцењује CPU vulnerability статус.

    Враћа (статус_ознака, боја).
    """
    text_lower = status_text.lower()

    # Ако је у потпуности митиговано.
    if "not affected" in text_lower:
        return ("not_affected", "dim")

    # Ако је митиговано.
    if "mitigation:" in text_lower or "mitigated" in text_lower:
        # Али проверавамо да није "vulnerable" у тексту.
        if "vulnerable" not in text_lower:
            return ("mitigated", "green")

    # Ако је рањиво.
    if "vulnerable" in text_lower:
        return ("vulnerable", "red")

    # Непознато.
    return ("unknown", "yellow")


def _analyze_cpu_vulnerabilities(vulns: list[dict]) -> dict:
    """Анализира CPU vulnerability статусе."""
    result = {
        "vulnerable": [],
        "mitigated": [],
        "not_affected": [],
        "unknown": [],
        "vulnerable_count": 0,
        "mitigated_count": 0,
        "not_affected_count": 0,
    }

    for vuln in vulns:
        evaluated = vuln.get("evaluated", "unknown")

        if evaluated == "vulnerable":
            result["vulnerable"].append(vuln)
            result["vulnerable_count"] += 1
        elif evaluated == "mitigated":
            result["mitigated"].append(vuln)
            result["mitigated_count"] += 1
        elif evaluated == "not_affected":
            result["not_affected"].append(vuln)
            result["not_affected_count"] += 1
        else:
            result["unknown"].append(vuln)

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    active_lsms = data.get("active_lsms", [])
    boot_analysis = data.get("boot_analysis", {})
    cpu_vulns = data.get("cpu_vulnerabilities", [])
    cpu_analysis = data.get("cpu_analysis", {})
    summary = data.get("summary", {})

    # Резиме.
    console.print(
        f"[bold]Active LSM modules:[/bold]     "
        f"{summary.get('total_lsms', 0)}"
    )

    if summary.get("has_mac"):
        console.print(
            "[bold green]MAC system:[/bold green]              active"
        )
    else:
        console.print(
            "[bold yellow]MAC system:[/bold yellow]              "
            "not active"
        )

    console.print(
        f"[bold]Kernel hardening:[/bold]       "
        f"{summary.get('hardening_params', 0)} enabled, "
        f"{summary.get('missing_params', 0)} missing/weak"
    )

    if summary.get("vulnerable_cpus", 0) > 0:
        console.print(
            f"[bold red]CPU vulnerabilities:[/bold red]    "
            f"{summary['vulnerable_cpus']} vulnerable"
        )
    else:
        console.print(
            f"[bold green]CPU vulnerabilities:[/bold green]    "
            f"all mitigated or not affected"
        )

    console.print()

    # LSM модули.
    if active_lsms:
        console.print("[bold]LSM modules:[/bold]\n")

        # Групишемо по категорији.
        by_category: dict[str, list] = {}

        for lsm in active_lsms:
            cat = lsm.get("category", "other")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(lsm)

        category_labels = {
            "mac": ("MAC (Mandatory Access Control)", "green"),
            "restriction": ("Restrictions", "cyan"),
            "integrity": ("Integrity", "cyan"),
            "sandbox": ("Sandboxing", "cyan"),
            "other": ("Other", "dim"),
        }

        for cat in ["mac", "restriction", "integrity", "sandbox", "other"]:
            modules = by_category.get(cat, [])
            if not modules:
                continue

            label, color = category_labels.get(cat, (cat, "dim"))

            console.print(f"  [{color}]{label}:[/{color}]")

            for lsm in modules:
                console.print(
                    f"    {lsm['name']:15s}  [dim]{lsm['label']}[/dim]"
                )

        console.print()

    # Kernel hardening параметри.
    checked = boot_analysis.get("checked", [])

    if checked:
        console.print("[bold]Kernel hardening parameters:[/bold]\n")

        # Прво проблеми.
        problems = [c for c in checked if c["status"] == "problem"]

        if problems:
            console.print(
                "[bold red]Problems:[/bold red]\n"
            )
            for item in problems:
                _print_hardening_item(item, "red")
            console.print()

        # Онда добри.
        enabled = [c for c in checked if c["status"] == "enabled"]

        if enabled:
            console.print("[bold green]Enabled:[/bold green]\n")
            for item in enabled:
                _print_hardening_item(item, "green")
            console.print()

        # Онда недостајући.
        missing = [
            c for c in checked
            if c["status"] == "missing"
        ]

        if missing:
            console.print("[bold yellow]Not enabled:[/bold yellow]\n")
            for item in missing:
                _print_hardening_item(item, "yellow")
            console.print()

    # CPU рањивости.
    if cpu_vulns:
        console.print(
            f"[bold]CPU vulnerabilities ({len(cpu_vulns)}):[/bold]\n"
        )

        # Вулнерабилни прво.
        vulnerable = cpu_analysis.get("vulnerable", [])

        if vulnerable:
            console.print("[bold red]Vulnerable:[/bold red]\n")
            for vuln in vulnerable:
                _print_cpu_vuln(vuln, "red")
            console.print()

        # Митиговани.
        mitigated = cpu_analysis.get("mitigated", [])

        if mitigated:
            console.print("[bold green]Mitigated:[/bold green]\n")
            for vuln in mitigated:
                _print_cpu_vuln(vuln, "green")
            console.print()

        # Није погођен.
        not_affected = cpu_analysis.get("not_affected", [])

        if not_affected:
            console.print("[bold]Not affected:[/bold]\n")
            for vuln in not_affected[:10]:
                console.print(
                    f"  [dim]{vuln['name']}[/dim]"
                )
            if len(not_affected) > 10:
                console.print(
                    f"  [dim]... and {len(not_affected) - 10} more[/dim]"
                )
            console.print()


def _print_hardening_item(item: dict, color: str) -> None:
    """Приказује један hardening параметар."""
    parameter = item.get("parameter", "?")
    value = item.get("value")
    message = item.get("message", "")

    value_display = ""
    if value is not None and value is not True:
        value_display = f"= {value}"

    console.print(
        f"  [{color}]{parameter:25s}[/{color}] "
        f"{value_display:10s}  "
        f"[dim]{message}[/dim]"
    )


def _print_cpu_vuln(vuln: dict, color: str) -> None:
    """Приказује једну CPU рањивост."""
    name = vuln.get("name", "?")
    status = vuln.get("status", "")

    # Скраћујемо статус.
    if len(status) > 100:
        status = status[:97] + "..."

    console.print(f"  [{color}]{name:25s}[/{color}]")
    console.print(f"    [dim]{status}[/dim]")