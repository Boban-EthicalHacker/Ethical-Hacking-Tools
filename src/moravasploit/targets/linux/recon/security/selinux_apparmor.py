# Модул за приказ статуса SELinux и AppArmor.
# Ово су Linux Security Modules (LSM) — MAC системи који
# ограничавају шта процеси могу, чак и ако имају root.
#
# SELinux се користи на RHEL/Fedora/CentOS.
# AppArmor се користи на Ubuntu/Debian/Kali.
#
# Ако су искључени, систем је рањивији на privilege escalation.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до sysfs фајлова са LSM информацијама.
LSM_PATH = Path("/sys/kernel/security/lsm")
SELINUX_PATH = Path("/sys/fs/selinux")
APPARMOR_PATH = Path("/sys/kernel/security/apparmor")

# Познати LSM модули.
KNOWN_LSMS = {
    "selinux": "SELinux",
    "apparmor": "AppArmor",
    "smack": "Smack",
    "tomoyo": "Tomoyo",
    "yama": "Yama (ptrace restriction)",
    "lockdown": "Lockdown",
    "integrity": "IMA/EVM integrity",
    "bpf": "BPF LSM",
    "landlock": "Landlock",
    "safeSetID": "SafeSetID",
    "capability": "Capability (base LSM)",
    "ipe": "IPE (Integrity Policy Enforcement)",
    "ima": "IMA (Integrity Measurement)",
    "evm": "EVM (Extended Verification)",
}


def run() -> dict:
    """Приказује статус SELinux и AppArmor.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]SELinux and AppArmor[/bold cyan]\n")

    # Читамо активне LSM модуле из кернела.
    active_lsms = _read_active_lsms()

    # SELinux статус.
    selinux = _get_selinux_status()

    # AppArmor статус.
    apparmor = _get_apparmor_status(active_lsms)

    # Правимо резиме.
    summary = {
        "active_lsms": [lsm["name"] for lsm in active_lsms],
        "selinux_enabled": selinux.get("enabled", False),
        "apparmor_enabled": apparmor.get("enabled", False),
        "selinux_mode": selinux.get("mode"),
        "apparmor_mode": apparmor.get("mode"),
    }

    data = {
        "active_lsms": active_lsms,
        "selinux": selinux,
        "apparmor": apparmor,
        "summary": summary,
    }

    _print_data(data)

    return data


def _read_active_lsms() -> list[dict]:
    """Чита активне LSM модуле из /sys/kernel/security/lsm."""
    if not LSM_PATH.exists():
        return []

    try:
        content = LSM_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    # Формат: comma-separated list, нпр. "capability,yama,apparmor"
    names = [
        name.strip()
        for name in content.strip().split(",")
        if name.strip()
    ]

    result = []
    for name in names:
        result.append({
            "name": name,
            "label": KNOWN_LSMS.get(name, name.title()),
        })

    return result


def _get_selinux_status() -> dict:
    """Чита SELinux статус.

    Прво покушава getenforce, онда чита sysfs.
    """
    result = {
        "enabled": False,
        "mode": None,
        "policy": None,
        "available": SELINUX_PATH.exists(),
    }

    # Проверавамо да ли је SELinux уопште присутан.
    if not SELINUX_PATH.exists() and not shutil.which("getenforce"):
        return result

    # getenforce — најбржи начин да се добије режим.
    if shutil.which("getenforce"):
        mode = _run_command(["getenforce"])
        if mode:
            mode = mode.strip()
            result["enabled"] = mode.lower() != "disabled"
            result["mode"] = mode
    else:
        # Fallback — читамо /sys/fs/selinux/enforce.
        enforce_path = SELINUX_PATH / "enforce"
        if enforce_path.exists():
            try:
                value = enforce_path.read_text().strip()
                result["mode"] = (
                    "Enforcing" if value == "1" else "Permissive"
                )
                result["enabled"] = True
            except Exception:
                pass

    # sestatus — детаљније информације.
    if shutil.which("sestatus"):
        sestatus = _run_command(["sestatus"])
        if sestatus:
            policy = _parse_sestatus(sestatus)
            if policy:
                result["policy"] = policy

    return result


def _parse_sestatus(output: str) -> str | None:
    """Извлачи policy из sestatus излаза."""
    for line in output.splitlines():
        line = line.strip()
        if "Loaded policy name" in line or "Policy from config file" in line:
            if ":" in line:
                return line.split(":", 1)[1].strip()
    return None


def _get_apparmor_status(active_lsms: list[dict]) -> dict:
    """Чита AppArmor статус.

    Прво покушава aa-status, онда чита sysfs.
    Ако је apparmor модул учитан али нема профила,
    приказујемо "loaded (no profiles)".
    """
    result = {
        "enabled": False,
        "mode": None,
        "profiles_loaded": 0,
        "profiles_enforce": 0,
        "profiles_complain": 0,
        "available": APPARMOR_PATH.exists(),
        "module_loaded": False,
    }

    # Проверавамо да ли је apparmor модул учитан у кернел.
    for lsm in active_lsms:
        if lsm.get("name") == "apparmor":
            result["module_loaded"] = True
            break

    # Ако модул није учитан, нема смисла даље тражити.
    if not result["module_loaded"] and not APPARMOR_PATH.exists():
        return result

    # aa-status — најбољи начин.
    if shutil.which("aa-status"):
        output = _run_command(["aa-status"])
        if output:
            parsed = _parse_aa_status(output)
            result.update(parsed)

            # Ако је модул учитан, сматрамо га enabled.
            if parsed.get("profiles_loaded", 0) > 0:
                result["enabled"] = True
                result["mode"] = "enabled"
            elif result["module_loaded"]:
                result["enabled"] = True
                result["mode"] = "loaded (no profiles)"

    # Fallback — читамо /sys/kernel/security/apparmor/profiles.
    if not result["enabled"] and result["module_loaded"]:
        profiles_path = APPARMOR_PATH / "profiles"
        if profiles_path.exists():
            try:
                content = profiles_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                profiles = [l for l in content.splitlines() if l.strip()]
                count = len(profiles)

                if count > 0:
                    result["enabled"] = True
                    result["profiles_loaded"] = count
                    result["mode"] = "enabled"
                else:
                    # Модул учитан али нема профила.
                    result["enabled"] = True
                    result["mode"] = "loaded (no profiles)"
            except Exception:
                # Не можемо да читамо — али модул је учитан.
                result["enabled"] = True
                result["mode"] = "loaded"
        else:
            # Нема profiles фајла — модул је учитан али нема профила.
            result["enabled"] = True
            result["mode"] = "loaded (no profiles)"

    return result


def _parse_aa_status(output: str) -> dict:
    """Парсира aa-status излаз."""
    result = {
        "mode": None,
        "profiles_loaded": 0,
        "profiles_enforce": 0,
        "profiles_complain": 0,
    }

    for line in output.splitlines():
        line = line.strip()

        if "apparmor module is loaded" in line:
            result["mode"] = "enabled"
        elif "profiles are loaded" in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                result["profiles_loaded"] = int(parts[0])
        elif "profiles are in enforce mode" in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                result["profiles_enforce"] = int(parts[0])
        elif "profiles are in complain mode" in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                result["profiles_complain"] = int(parts[0])

    return result


def _run_command(cmd: list[str]) -> str | None:
    """Покреће команду и враћа stdout."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    active_lsms = data.get("active_lsms", [])
    selinux = data.get("selinux", {})
    apparmor = data.get("apparmor", {})

    # Активни LSM модули.
    console.print("[bold]Active LSM modules:[/bold]\n")

    if not active_lsms:
        console.print("  [dim]None detected.[/dim]\n")
    else:
        for lsm in active_lsms:
            name = lsm.get("name", "?")
            label = lsm.get("label", "")

            # Означавамо важне MAC системе зелено.
            if name in ("selinux", "apparmor"):
                color = "green"
            elif name in ("yama", "lockdown"):
                color = "cyan"
            else:
                color = "dim"

            console.print(
                f"  [{color}]{name:15s}[/{color}]  [dim]{label}[/dim]"
            )

        console.print()

    # SELinux.
    console.print("[bold]SELinux:[/bold]\n")

    if not selinux.get("available") and not selinux.get("enabled"):
        console.print("  [dim]Not available on this system.[/dim]\n")
    else:
        enabled = selinux.get("enabled", False)
        mode = selinux.get("mode") or "unknown"

        if not enabled:
            console.print("  Status: [red]disabled[/red]")
        else:
            # Боја за mode.
            if mode.lower() == "enforcing":
                mode_color = "green"
            elif mode.lower() == "permissive":
                mode_color = "yellow"
            else:
                mode_color = "dim"

            console.print(
                f"  Status: [{mode_color}]{mode}[/{mode_color}]"
            )

        if selinux.get("policy"):
            console.print(f"  Policy: [cyan]{selinux['policy']}[/cyan]")

        console.print()

    # AppArmor.
    console.print("[bold]AppArmor:[/bold]\n")

    if not apparmor.get("available") and not apparmor.get("module_loaded"):
        console.print("  [dim]Not available on this system.[/dim]\n")
    else:
        enabled = apparmor.get("enabled", False)
        mode = apparmor.get("mode")
        module_loaded = apparmor.get("module_loaded", False)

        if not enabled:
            console.print("  Status: [red]disabled[/red]")
        else:
            # Ако је модул учитан али нема профила.
            if mode and "no profiles" in mode:
                console.print(
                    "  Status: [yellow]module loaded, "
                    "but no profiles active[/yellow]"
                )
            else:
                console.print("  Status: [green]enabled[/green]")

            loaded = apparmor.get("profiles_loaded", 0)
            enforce = apparmor.get("profiles_enforce", 0)
            complain = apparmor.get("profiles_complain", 0)

            if loaded:
                console.print(
                    f"  Profiles loaded:  [cyan]{loaded}[/cyan]"
                )
            if enforce:
                console.print(
                    f"  In enforce mode:  [green]{enforce}[/green]"
                )
            if complain:
                console.print(
                    f"  In complain mode: [yellow]{complain}[/yellow]"
                )

        if module_loaded and not enabled:
            console.print(
                "  [dim]Module is loaded in kernel but not active.[/dim]"
            )

        console.print()

    # Закључак.
    _print_conclusion(selinux, apparmor, active_lsms)


def _print_conclusion(
    selinux: dict, apparmor: dict, active_lsms: list[dict]
) -> None:
    """Приказује безбедносни закључак."""
    # Проверавамо да ли је неки MAC систем стварно активан.
    has_mac = False
    mac_name = None
    mac_partial = False

    if selinux.get("enabled"):
        has_mac = True
        mac_name = "SELinux"

    if apparmor.get("enabled"):
        mode = apparmor.get("mode") or ""
        if "no profiles" in mode:
            mac_partial = True
            if not has_mac:
                mac_name = "AppArmor (module loaded, no profiles)"
        else:
            has_mac = True
            mac_name = "AppArmor"

    # Проверавамо Yama (ptrace ограничење).
    yama_active = any(
        lsm.get("name") == "yama" for lsm in active_lsms
    )

    # Проверавамо остале корисне LSM.
    other_useful = []
    for lsm in active_lsms:
        name = lsm.get("name")
        if name in ("lockdown", "landlock", "bpf", "ipe", "ima"):
            other_useful.append(name)

    console.print("[bold]Conclusion:[/bold]\n")

    if has_mac:
        console.print(
            f"  [green]✓ {mac_name} is active.[/green] "
            f"MAC provides additional security."
        )
    elif mac_partial:
        console.print(
            f"  [yellow]⚠ {mac_name}[/yellow]\n"
            "    Module is loaded but no profiles are active.\n"
            "    MAC protection is not effective."
        )
    else:
        console.print(
            "  [yellow]⚠ No MAC system (SELinux/AppArmor) is active.[/yellow]\n"
            "    System is more vulnerable to privilege escalation."
        )

    if yama_active:
        console.print(
            "  [green]✓ Yama is active.[/green] "
            "ptrace is restricted."
        )
    else:
        console.print(
            "  [dim]• Yama is not active (ptrace not restricted).[/dim]"
        )

    if other_useful:
        console.print(
            f"  [cyan]• Other LSM modules active: "
            f"{', '.join(other_useful)}[/cyan]"
        )

    console.print()