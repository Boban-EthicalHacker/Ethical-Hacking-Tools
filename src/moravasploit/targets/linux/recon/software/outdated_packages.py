# Модул за приказ застарелих пакета (са доступним надоградњама).
# Застарели пакети имају познате рањивости. Ово је једна од
# првих ствари које етички хакер проверава.
#
# Подржава:
#   - apt (Debian/Ubuntu/Kali) — apt list --upgradable
#   - dnf (RHEL/Fedora) — dnf check-update
#   - yum (старији RHEL) — yum check-update
#   - pacman (Arch) — pacman -Qu
#   - apk (Alpine) — apk version
#   - zypper (SUSE) — zypper list-updates
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
import shutil
import subprocess

from rich.console import Console

console = Console()

# Патерни који указују на безбедносне надоградње.
SECURITY_KEYWORDS = [
    "security",
    "CVE-",
    "USN-",      # Ubuntu Security Notice
    "DSA-",      # Debian Security Advisory
    "RHSA-",     # Red Hat Security Advisory
    "RHBA-",
    "SUSE-SU-",
]


def run() -> dict:
    """Приказује застареле пакете.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Outdated packages[/bold cyan]\n")

    # Препознајемо доступне package manager-е.
    manager = _detect_manager()

    if manager is None:
        console.print(
            "  [yellow]No supported package manager found.[/yellow]\n"
        )
        return _empty_result()

    console.print(f"[dim]Using: {manager}[/dim]\n")

    # Читамо застареле пакете.
    packages = _read_outdated(manager)

    # Издвајамо безбедносне надоградње.
    security = _find_security_updates(packages)

    # Правимо резиме.
    summary = {
        "total": len(packages),
        "security_count": len(security),
        "manager": manager,
    }

    data = {
        "manager": manager,
        "packages": packages,
        "security_updates": security,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "manager": None,
        "packages": [],
        "security_updates": [],
        "summary": {
            "total": 0,
            "security_count": 0,
            "manager": None,
        },
    }


def _detect_manager() -> str | None:
    """Препознаје који package manager је доступан.

    Редослед приоритета:
        1. apt (најчешћи на Debian базираним системима)
        2. dnf (модерни RHEL/Fedora)
        3. yum (старији RHEL/CentOS)
        4. pacman (Arch)
        5. apk (Alpine)
        6. zypper (SUSE)
    """
    checks = [
        ("apt", "apt"),
        ("dnf", "dnf"),
        ("yum", "yum"),
        ("pacman", "pacman"),
        ("apk", "apk"),
        ("zypper", "zypper"),
    ]

    for manager, cmd in checks:
        if shutil.which(cmd):
            return manager

    return None


def _read_outdated(manager: str) -> list[dict]:
    """Чита застареле пакете за дати manager."""
    if manager == "apt":
        return _read_apt()
    if manager == "dnf":
        return _read_dnf()
    if manager == "yum":
        return _read_yum()
    if manager == "pacman":
        return _read_pacman()
    if manager == "apk":
        return _read_apk()
    if manager == "zypper":
        return _read_zypper()
    return []


def _read_apt() -> list[dict]:
    """Чита застареле пакете помоћу apt."""
    try:
        proc = subprocess.run(
            ["apt", "list", "--upgradable"],
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
        line = line.strip()

        # Прескачемо заглавље и празне линије.
        if not line or line.startswith("Listing"):
            continue

        # Формат: name/suite version arch [upgradable from: old_version]
        # Пример: vim/noble-updates 2:9.1.0016-1ubuntu7.5 amd64 [upgradable from: 2:9.1.0016-1ubuntu7.4]
        parsed = _parse_apt_line(line)
        if parsed:
            packages.append(parsed)

    return packages


def _parse_apt_line(line: str) -> dict | None:
    """Парсира једну линију из `apt list --upgradable`."""
    # Прво раздвајамо по размаку — прва реч је "name/suite".
    parts = line.split()

    if len(parts) < 3:
        return None

    name_suite = parts[0]
    if "/" not in name_suite:
        return None

    name, suite = name_suite.split("/", 1)

    available_version = parts[1]
    arch = parts[2] if len(parts) > 2 else ""

    # Тражимо "upgradable from: old_version".
    # Верзија може имати "]}" на крају због формата apt излаза.
    current_version = ""
    match = re.search(r"upgradable from:\s*(\S+)", line)
    if match:
        current_version = match.group(1).rstrip("]},")

    # Проверавамо да ли је security update (по suite-у).
    is_security = any(
        keyword in suite.lower()
        for keyword in ("security", "securities")
    )

    return {
        "name": name,
        "current_version": current_version,
        "available_version": available_version,
        "arch": arch,
        "suite": suite,
        "is_security": is_security,
    }


def _read_dnf() -> list[dict]:
    """Чита застареле пакете помоћу dnf."""
    try:
        proc = subprocess.run(
            ["dnf", "check-update", "--quiet"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    # dnf враћа излазни код 100 ако има надоградњи, 0 ако нема.
    # У оба случаја излаз је на stdout.
    return _parse_dnf_output(proc.stdout)


def _parse_dnf_output(output: str) -> list[dict]:
    """Парсира dnf check-update излаз.

    Формат:
        package.arch    version    repo
    """
    packages = []

    for line in output.splitlines():
        line = line.strip()

        if not line or line.startswith(("Last metadata", "Obsoleting")):
            continue
        if line.startswith("Security:"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        name_arch = parts[0]
        version = parts[1]
        repo = parts[2]

        # Раздвајамо име и архитектуру.
        if "." in name_arch:
            name, arch = name_arch.rsplit(".", 1)
        else:
            name = name_arch
            arch = ""

        # Проверавамо да ли је security update.
        is_security = _is_security_repo(repo)

        packages.append({
            "name": name,
            "arch": arch,
            "current_version": "",
            "available_version": version,
            "repo": repo,
            "is_security": is_security,
        })

    return packages


def _read_yum() -> list[dict]:
    """Чита застареле пакете помоћу yum."""
    try:
        proc = subprocess.run(
            ["yum", "check-update", "--quiet"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    return _parse_dnf_output(proc.stdout)


def _read_pacman() -> list[dict]:
    """Чита застареле пакете помоћу pacman."""
    try:
        proc = subprocess.run(
            ["pacman", "-Qu"],
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
        line = line.strip()

        if not line:
            continue

        # Формат: name current_version -> available_version
        parts = line.split()
        if len(parts) < 4:
            continue

        name = parts[0]
        current_version = parts[1]
        # parts[2] је "->"
        available_version = parts[3]

        packages.append({
            "name": name,
            "current_version": current_version,
            "available_version": available_version,
            "arch": "",
            "repo": "",
            "is_security": False,
        })

    return packages


def _read_apk() -> list[dict]:
    """Чита застареле пакете помоћу apk."""
    try:
        proc = subprocess.run(
            ["apk", "version", "-l", "<"],
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
        line = line.strip()

        if not line or line.startswith("Installed:"):
            continue

        # Формат: name-version < available-version
        parts = line.split("<")
        if len(parts) != 2:
            continue

        installed = parts[0].strip()
        available = parts[1].strip()

        # Из installed узимамо име и верзију.
        if "-" in installed:
            name_version = installed.rsplit("-", 1)
            if len(name_version) == 2:
                name = name_version[0]
                current_version = name_version[1]
            else:
                name = installed
                current_version = ""
        else:
            name = installed
            current_version = ""

        packages.append({
            "name": name,
            "current_version": current_version,
            "available_version": available,
            "arch": "",
            "repo": "",
            "is_security": False,
        })

    return packages


def _read_zypper() -> list[dict]:
    """Чита застареле пакете помоћу zypper."""
    try:
        proc = subprocess.run(
            ["zypper", "list-updates"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        line = line.strip()

        # Прескачемо заглавље и раздвајаче.
        if not line or line.startswith(("S |", "Repository", "--", "Loading")):
            continue

        # Формат: | name | type | version | arch | repo
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue

        # Узимамо само security patches.
        patch_type = parts[2].lower() if len(parts) > 2 else ""

        name = parts[1] if len(parts) > 1 else ""
        version = parts[3] if len(parts) > 3 else ""
        arch = parts[4] if len(parts) > 4 else ""
        repo = parts[5] if len(parts) > 5 else ""

        if not name:
            continue

        is_security = "security" in patch_type or "security" in repo.lower()

        packages.append({
            "name": name,
            "current_version": "",
            "available_version": version,
            "arch": arch,
            "repo": repo,
            "is_security": is_security,
        })

    return packages


def _is_security_repo(repo: str) -> bool:
    """Проверава да ли repo име указује на security."""
    repo_lower = repo.lower()

    for keyword in SECURITY_KEYWORDS:
        if keyword.lower() in repo_lower:
            return True

    return False


def _find_security_updates(packages: list[dict]) -> list[dict]:
    """Издваја безбедносне надоградње."""
    security = []

    for pkg in packages:
        if pkg.get("is_security"):
            security.append(pkg)

    return security


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    manager = data.get("manager")
    packages = data.get("packages", [])
    security = data.get("security_updates", [])
    summary = data.get("summary", {})

    if manager is None:
        console.print(
            "  [dim]No supported package manager found.[/dim]\n"
        )
        return

    console.print(
        f"[bold]Total outdated:[/bold]   {summary.get('total', 0)}"
    )
    console.print(
        f"  Manager:          {manager}"
    )

    if security:
        console.print(
            f"  [bold red]Security updates:[/bold red] "
            f"{summary.get('security_count', 0)}"
        )

    console.print()

    if not packages:
        console.print(
            "[bold green]No outdated packages found.[/bold green]\n"
        )
        return

    # Безбедносне надоградње прво.
    if security:
        console.print(
            f"[bold red]Security updates ({len(security)}):[/bold red]\n"
        )
        for pkg in security:
            _print_package(pkg, highlight=True)
        console.print()

    # Остале надоградње (првих 20).
    other = [p for p in packages if not p.get("is_security")]

    if other:
        console.print(
            f"[bold]Other updates ({len(other)}):[/bold]\n"
        )

        limit = 20
        for pkg in other[:limit]:
            _print_package(pkg)

        if len(other) > limit:
            console.print(
                f"  [dim]... and {len(other) - limit} more[/dim]"
            )
        console.print()


def _print_package(pkg: dict, highlight: bool = False) -> None:
    """Приказује један пакет."""
    name = pkg.get("name", "?")
    current = pkg.get("current_version", "")
    available = pkg.get("available_version", "")

    if highlight:
        color = "bold red"
    else:
        color = "white"

    line = f"  [{color}]{name:35s}[/{color}]"

    if current:
        # Скраћујемо верзије.
        if len(current) > 20:
            current = current[:17] + "..."
        line += f"  {current}"

    if available:
        if len(available) > 20:
            available = available[:17] + "..."
        line += f"  [green]→ {available}[/green]"

    console.print(line)