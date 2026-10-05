# Модул за приказ инсталираних пакета.
# Подржава више package manager-а:
#   - dpkg (Debian/Ubuntu/Kali)
#   - rpm (RHEL/Fedora/SUSE)
#   - pacman (Arch)
#   - apk (Alpine)
#   - snap, flatpak (универзални)
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Пакети који су безбедносно занимљиви (често мета нападача).
INTERESTING_PACKAGES = {
    # Мрежни алати
    "nmap", "masscan", "netcat", "ncat", "socat", "tcpdump",
    "wireshark", "tshark", "traceroute", "mtr",
    # Exploit алати
    "metasploit-framework", "msfpc", "searchsploit", "exploitdb",
    "sqlmap", "beef-xss", "set", "social-engineer-toolkit",
    # Password алати
    "john", "hashcat", "hydra", "medusa", "ncrack", "crunch",
    "wordlists", "seclists",
    # Wireless
    "aircrack-ng", "reaver", "kismet", "wifite", "bettercap",
    # Web
    "burpsuite", "zaproxy", "nikto", "wpscan", "gobuster",
    "dirb", "ffuf", "wfuzz",
    # Мреже
    "ettercap", "dsniff", "mitmproxy", "responder",
    # Остало
    "binwalk", "foremost", "radare2", "gdb", "ghidra",
    "gobuster", "amass", "subfinder", "recon-ng",
    # Компајлери и development
    "gcc", "g++", "clang", "make", "cmake", "rustc", "cargo",
    "python3", "python2", "perl", "ruby", "go", "nodejs",
    "openjdk", "default-jdk",
    # Мрежне услуге
    "openssh-server", "openssh-client", "apache2", "nginx",
    "vsftpd", "postfix", "mysql-server", "mariadb-server",
    "postgresql", "redis-server",
}

# Максималан број пакета које приказујемо/чувамо.
MAX_PACKAGES_DISPLAY = 30


def run() -> dict:
    """Приказује инсталиране пакете.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Installed packages[/bold cyan]\n")

    # Препознајемо package manager-е.
    managers = _detect_package_managers()

    if not managers:
        console.print(
            "  [yellow]No known package manager found.[/yellow]\n"
        )
        return _empty_result()

    # Читамо пакете из сваког manager-а.
    packages_by_manager = {}
    total_packages = 0

    for manager in managers:
        pkgs = _read_packages(manager)
        packages_by_manager[manager] = pkgs
        total_packages += len(pkgs)

    # Скупљамо све пакете у једну листу.
    all_packages = []
    for manager, pkgs in packages_by_manager.items():
        for pkg in pkgs:
            pkg["manager"] = manager
            all_packages.append(pkg)

    # Тражимо занимљиве пакете.
    interesting = _find_interesting(all_packages)

    # Правимо резиме.
    summary = {
        "total": total_packages,
        "managers": {
            manager: len(pkgs)
            for manager, pkgs in packages_by_manager.items()
        },
        "interesting_count": len(interesting),
    }

    data = {
        "packages": all_packages,
        "interesting": interesting,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "packages": [],
        "interesting": [],
        "summary": {
            "total": 0,
            "managers": {},
            "interesting_count": 0,
        },
    }


def _detect_package_managers() -> list[str]:
    """Препознаје који package manager-и су доступни."""
    managers = []

    checks = [
        ("dpkg", ["dpkg", "--version"]),
        ("rpm", ["rpm", "--version"]),
        ("pacman", ["pacman", "--version"]),
        ("apk", ["apk", "--version"]),
        ("snap", ["snap", "version"]),
        ("flatpak", ["flatpak", "--version"]),
    ]

    for name, cmd in checks:
        if shutil.which(cmd[0]):
            managers.append(name)

    return managers


def _read_packages(manager: str) -> list[dict]:
    """Чита пакете из датог manager-а."""
    if manager == "dpkg":
        return _read_dpkg()
    if manager == "rpm":
        return _read_rpm()
    if manager == "pacman":
        return _read_pacman()
    if manager == "apk":
        return _read_apk()
    if manager == "snap":
        return _read_snap()
    if manager == "flatpak":
        return _read_flatpak()
    return []


def _read_dpkg() -> list[dict]:
    """Чита dpkg пакете."""
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Status}\\n"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue

        name = parts[0].strip()
        version = parts[1].strip()
        status = parts[2].strip()

        # Узимамо само инсталиране пакете.
        if "install ok installed" not in status:
            continue

        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name in INTERESTING_PACKAGES,
        })

    return packages


def _read_rpm() -> list[dict]:
    """Чита rpm пакете."""
    try:
        proc = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        name = parts[0].strip()
        version = parts[1].strip()

        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name in INTERESTING_PACKAGES,
        })

    return packages


def _read_pacman() -> list[dict]:
    """Чита pacman пакете."""
    try:
        proc = subprocess.run(
            ["pacman", "-Q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[1]

        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name in INTERESTING_PACKAGES,
        })

    return packages


def _read_apk() -> list[dict]:
    """Чита apk пакете."""
    try:
        proc = subprocess.run(
            ["apk", "info", "-v"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        # Формат: name-version-release
        line = line.strip()
        if not line:
            continue

        # Парсирамо од краја.
        if "-" in line:
            parts = line.rsplit("-", 2)
            if len(parts) == 3:
                name = parts[0]
                version = f"{parts[1]}-{parts[2]}"

                packages.append({
                    "name": name,
                    "version": version,
                    "is_interesting": name in INTERESTING_PACKAGES,
                })

    return packages


def _read_snap() -> list[dict]:
    """Чита snap пакете."""
    try:
        proc = subprocess.run(
            ["snap", "list"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []
    lines = proc.stdout.splitlines()

    # Прескачемо заглавље.
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[1]

        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name in INTERESTING_PACKAGES,
        })

    return packages


def _read_flatpak() -> list[dict]:
    """Чита flatpak пакете."""
    try:
        proc = subprocess.run(
            ["flatpak", "list", "--columns=application,version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[1]

        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name in INTERESTING_PACKAGES,
        })

    return packages


def _find_interesting(packages: list[dict]) -> list[dict]:
    """Проналази безбедносно занимљиве пакете."""
    interesting = []

    for pkg in packages:
        if pkg.get("is_interesting"):
            interesting.append({
                "name": pkg["name"],
                "version": pkg.get("version", ""),
                "manager": pkg.get("manager", "?"),
                "category": _categorize(pkg["name"]),
            })

    return sorted(interesting, key=lambda x: x["name"])


def _categorize(name: str) -> str:
    """Препознаје категорију пакета."""
    categories = {
        "Network": {
            "nmap", "masscan", "netcat", "ncat", "socat", "tcpdump",
            "wireshark", "tshark", "traceroute", "mtr", "ettercap",
            "dsniff", "mitmproxy", "responder",
        },
        "Exploit": {
            "metasploit-framework", "msfpc", "searchsploit", "exploitdb",
            "sqlmap", "beef-xss", "set", "social-engineer-toolkit",
        },
        "Password": {
            "john", "hashcat", "hydra", "medusa", "ncrack", "crunch",
            "wordlists", "seclists",
        },
        "Wireless": {
            "aircrack-ng", "reaver", "kismet", "wifite", "bettercap",
        },
        "Web": {
            "burpsuite", "zaproxy", "nikto", "wpscan", "gobuster",
            "dirb", "ffuf", "wfuzz",
        },
        "Reversing": {
            "binwalk", "foremost", "radare2", "gdb", "ghidra",
        },
        "Development": {
            "gcc", "g++", "clang", "make", "cmake", "rustc", "cargo",
            "python3", "python2", "perl", "ruby", "go", "nodejs",
            "openjdk", "default-jdk",
        },
        "Services": {
            "openssh-server", "openssh-client", "apache2", "nginx",
            "vsftpd", "postfix", "mysql-server", "mariadb-server",
            "postgresql", "redis-server",
        },
    }

    for category, names in categories.items():
        if name in names:
            return category

    return "Other"


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    packages = data.get("packages", [])
    interesting = data.get("interesting", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total packages:[/bold]   {summary.get('total', 0)}"
    )

    # Приказујемо бројеве по manager-у.
    managers = summary.get("managers", {})
    for manager, count in sorted(managers.items()):
        console.print(f"  {manager:10s}  {count}")

    console.print()

    if not interesting:
        console.print(
            "  [dim]No security-relevant packages found.[/dim]\n"
        )
        return

    console.print(
        f"[bold]Security-relevant packages ({len(interesting)}):[/bold]\n"
    )

    # Групишемо по категоријама.
    by_category: dict[str, list[dict]] = {}

    for pkg in interesting:
        cat = pkg.get("category", "Other")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(pkg)

    for category in sorted(by_category.keys()):
        pkgs = by_category[category]

        console.print(
            f"  [bold cyan]{category}[/bold cyan] ({len(pkgs)})"
        )

        for pkg in pkgs[:15]:
            version = pkg.get("version", "")
            if len(version) > 25:
                version = version[:22] + "..."

            console.print(
                f"    [bold]{pkg['name']:35s}[/bold]  "
                f"[dim]{version}[/dim]"
            )

        if len(pkgs) > 15:
            console.print(
                f"    [dim]... and {len(pkgs) - 15} more[/dim]"
            )

        console.print()