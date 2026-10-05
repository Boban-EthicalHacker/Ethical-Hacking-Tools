# Модул за приказ пакета инсталираних преко language-specific
# package manager-а (pip, npm, gem, go, cargo).
# Ови пакети НИСУ у системском dpkg/apt и не добијају
# security update редовно — често имају познате CVE-ове.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import json
import shutil
import subprocess

from rich.console import Console

console = Console()

# Максималан број пакета које приказујемо по manager-у.
MAX_DISPLAY = 15

# Занимљиви пакети (безбедносно релевантни, често са CVE-овима).
INTERESTING_PACKAGES = {
    # Python
    "requests", "urllib3", "pyyaml", "jinja2", "django", "flask",
    "pillow", "cryptography", "paramiko", "lxml", "numpy",
    "tensorflow", "torch", "sqlalchemy", "celery",
    # Node
    "express", "lodash", "axios", "react", "next", "webpack",
    "jsonwebtoken", "socket.io", "mongoose", "ejs", "handlebars",
    # Ruby
    "rails", "sinatra", "nokogiri", "devise", "puma",
    # Остало
    "openssl", "electron", "chrome",
}


def run() -> dict:
    """Приказује language-specific пакете.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Language packages[/bold cyan]\n")

    # Препознајемо доступне manager-е.
    managers = _detect_managers()

    if not managers:
        console.print(
            "  [dim]No language package managers found.[/dim]\n"
        )
        return _empty_result()

    # Читамо пакете из сваког manager-а.
    packages_by_manager = {}
    total = 0

    for manager in managers:
        pkgs = _read_packages(manager)
        packages_by_manager[manager] = pkgs
        total += len(pkgs)

    # Проналазимо занимљиве.
    interesting = _find_interesting(packages_by_manager)

    data = {
        "packages_by_manager": packages_by_manager,
        "interesting": interesting,
        "summary": {
            "total": total,
            "managers": {
                m: len(p) for m, p in packages_by_manager.items()
            },
            "interesting_count": len(interesting),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "packages_by_manager": {},
        "interesting": [],
        "summary": {
            "total": 0,
            "managers": {},
            "interesting_count": 0,
        },
    }


def _detect_managers() -> list[str]:
    """Препознаје доступне language package manager-е."""
    managers = []

    checks = [
        ("pip", "pip3"),
        ("npm", "npm"),
        ("gem", "gem"),
        ("go", "go"),
        ("cargo", "cargo"),
    ]

    for name, cmd in checks:
        if shutil.which(cmd):
            managers.append(name)

    return managers


def _read_packages(manager: str) -> list[dict]:
    """Чита пакете из датог manager-а."""
    if manager == "pip":
        return _read_pip()
    if manager == "npm":
        return _read_npm()
    if manager == "gem":
        return _read_gem()
    if manager == "go":
        return _read_go()
    if manager == "cargo":
        return _read_cargo()
    return []


def _read_pip() -> list[dict]:
    """Чита Python пакете."""
    try:
        proc = subprocess.run(
            ["pip3", "list", "--format=json", "--disable-pip-version-check"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    packages = []
    for item in data:
        name = item.get("name", "")
        version = item.get("version", "")
        if name:
            packages.append({
                "name": name,
                "version": version,
                "is_interesting": name.lower() in INTERESTING_PACKAGES,
            })

    return packages


def _read_npm() -> list[dict]:
    """Чита глобалне Node пакете."""
    try:
        proc = subprocess.run(
            ["npm", "list", "-g", "--depth=0", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0 and not proc.stdout:
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    dependencies = data.get("dependencies", {})

    packages = []
    for name, info in dependencies.items():
        version = info.get("version", "") if isinstance(info, dict) else ""
        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name.lower() in INTERESTING_PACKAGES,
        })

    return packages


def _read_gem() -> list[dict]:
    """Чита Ruby gem-ове."""
    try:
        proc = subprocess.run(
            ["gem", "list", "--no-versions"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        line = line.strip()

        # Прескачемо заглавље и празне линије.
        if not line or line.startswith(("***", "LOCAL")):
            continue

        # Гем може имати више верзија у заградама — узимамо само име.
        if "(" in line:
            name = line.split("(")[0].strip()
        else:
            name = line

        if not name:
            continue

        packages.append({
            "name": name,
            "version": "",
            "is_interesting": name.lower() in INTERESTING_PACKAGES,
        })

    return packages


def _read_go() -> list[dict]:
    """Чита Go modules (global binary пакете).

    Напомена: Go нема глобални registry као pip/npm.
    Читамо само инсталиране Go бинарне фајлове из GOPATH/bin.
    """
    # Проверавамо да ли постоји GOPATH/bin.
    import os
    from pathlib import Path

    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    bin_dir = Path(gopath) / "bin"

    packages = []

    if not bin_dir.exists() or not bin_dir.is_dir():
        return packages

    try:
        entries = sorted(bin_dir.iterdir())
    except (PermissionError, Exception):
        return packages

    for entry in entries:
        if not entry.is_file():
            continue
        if entry.name.startswith("."):
            continue

        packages.append({
            "name": entry.name,
            "version": "",
            "is_interesting": entry.name.lower() in INTERESTING_PACKAGES,
        })

    return packages


def _read_cargo() -> list[dict]:
    """Чита Rust cargo инсталиране пакете."""
    try:
        proc = subprocess.run(
            ["cargo", "install", "--list"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    packages = []

    for line in proc.stdout.splitlines():
        line = line.strip()

        # Формат: "name v1.2.3:"
        if not line or not line.endswith(":"):
            continue

        # Уклањамо ":" и раздвајамо.
        line = line.rstrip(":")

        # Тражимо " v" као раздвајач.
        if " v" in line:
            name, version = line.rsplit(" v", 1)
        else:
            name = line
            version = ""

        if not name:
            continue

        packages.append({
            "name": name,
            "version": version,
            "is_interesting": name.lower() in INTERESTING_PACKAGES,
        })

    return packages


def _find_interesting(
    packages_by_manager: dict
) -> list[dict]:
    """Проналази безбедносно занимљиве пакете."""
    interesting = []

    for manager, packages in packages_by_manager.items():
        for pkg in packages:
            if pkg.get("is_interesting"):
                interesting.append({
                    "manager": manager,
                    "name": pkg["name"],
                    "version": pkg.get("version", ""),
                })

    return sorted(interesting, key=lambda x: (x["manager"], x["name"]))


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    packages_by_manager = data.get("packages_by_manager", {})
    interesting = data.get("interesting", [])
    summary = data.get("summary", {})

    if not packages_by_manager:
        console.print(
            "  [dim]No language packages found.[/dim]\n"
        )
        return

    console.print(
        f"[bold]Total packages:[/bold]  {summary.get('total', 0)}\n"
    )

    # Приказујемо бројеве по manager-у.
    managers = summary.get("managers", {})
    for manager, count in sorted(managers.items()):
        console.print(f"  {manager:10s}  {count}")

    console.print()

    # Занимљиви пакети прво.
    if interesting:
        console.print(
            f"[bold yellow]Interesting packages "
            f"({len(interesting)}):[/bold yellow]\n"
        )

        for pkg in interesting:
            manager = pkg.get("manager", "?")
            name = pkg.get("name", "?")
            version = pkg.get("version", "")

            # Скраћујемо верзију.
            if len(version) > 20:
                version = version[:17] + "..."

            console.print(
                f"  [dim]{manager:8s}[/dim]  "
                f"[bold]{name:30s}[/bold]  "
                f"[yellow]{version}[/yellow]"
            )

        console.print()

    # Приказујемо по manager-у.
    for manager, packages in packages_by_manager.items():
        if not packages:
            continue

        console.print(
            f"[bold cyan]{manager} ({len(packages)}):[/bold cyan]\n"
        )

        # Сортирамо по имену.
        sorted_pkgs = sorted(packages, key=lambda x: x["name"].lower())

        for pkg in sorted_pkgs[:MAX_DISPLAY]:
            name = pkg.get("name", "?")
            version = pkg.get("version", "")
            is_interesting = pkg.get("is_interesting", False)

            # Скраћујемо.
            if len(name) > 30:
                name = name[:27] + "..."
            if len(version) > 25:
                version = version[:22] + "..."

            # Боја — жуто за занимљиве.
            if is_interesting:
                color = "yellow"
            else:
                color = "white"

            console.print(
                f"  [{color}]{name:32s}[/{color}]  "
                f"[dim]{version}[/dim]"
            )

        if len(sorted_pkgs) > MAX_DISPLAY:
            console.print(
                f"  [dim]... and {len(sorted_pkgs) - MAX_DISPLAY} more[/dim]"
            )

        console.print()