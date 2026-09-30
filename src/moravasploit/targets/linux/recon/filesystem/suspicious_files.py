# Модул за проналажење сумњивих фајлова на систему.
# Сумњиви фајлови су они који имају необична имена, налазе се
# на необичним локацијама или имају карактеристике које су
# честе код малициозног софтвера.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
import stat
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми које прескачемо.
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
    "/var/lib/libvirt",
    "/usr/share",
    "/usr/lib",
    "/var/lib/dpkg",
    "/var/lib/apt",
}

# Путање које су познато безбедне — прескачемо их потпуно.
# Ово су локације где "сумњиве" карактеристике нису сумњиве.
SAFE_PATHS = (
    "/etc/skel/",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/etc/cron.yearly/",
    "/etc/sensors.d/",
    "/etc/NetworkManager/system-connections/",
    "/etc/xdg/",
    "/etc/profile.d/",
    "/etc/update-motd.d/",
    "/tmp/.X11-unix/",
    "/tmp/.ICE-unix/",
    "/tmp/.XIM-unix/",
    "/tmp/.font-unix/",
    "/tmp/.Test-unix/",
    "/tmp/com.google.",
    "/tmp/com.brave.",
    "/tmp/com.microsoft.",
    "/tmp/.org.chromium.",
    "/tmp/systemd-private-",
    "/tmp/.xfsm-",
    "/var/tmp/systemd-private-",
    "/usr/share/",
    "/usr/lib/",
    "/var/lib/dpkg/",
    "/var/lib/apt/",
    "/snap/",
    # Кориснички home директоријуми — прескачемо их.
        # За home постоје други модули (credentials, users).
    "/home/",
)

# Позната безбедна имена фајлова (скривена или са размаком).
SAFE_NAMES = {
    # systemd
    ".updated",
    ".pwd.lock",
    ".placeholder",
    # X11
    ".X0-lock",
    ".X11-unix",
    ".ICE-unix",
    ".XIM-unix",
    ".font-unix",
    ".Test-unix",
    # Java
    ".system.lock",
    ".systemRootModFile",
    ".java",
    # Common
    ".gitkeep",
    ".gitignore",
    ".keep",
    ".git",
    ".svn",
}

# Локације где извршни фајлови НЕ БИ ТРЕБАЛО да постоје.
UNUSUAL_EXEC_LOCATIONS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/var/www/",
    "/var/spool/",
    "/srv/",
)

# Наставци који су нормални за скрипте.
SCRIPT_EXTENSIONS = (
    ".sh", ".bash", ".py", ".pl", ".rb", ".php",
    ".js", ".lua", ".tcl",
)

# Опасни наставци (двоструке екстензије).
DOUBLE_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".txt", ".csv",
)

# Патерни за сумњива имена фајлова.
# Уклонили смо "whitespace in name" јер је сувише често
# нормално (WiFi мреже, фолдери са размаком).
SUSPICIOUS_NAME_PATTERNS = [
    (r"^\.\.+", "dot-trick"),
    (r"^\s+", "leading whitespace"),
    (r"\s+$", "trailing whitespace"),
    (r"^-", "starts with dash"),
    (r";", "contains semicolon"),
    (r"\|", "contains pipe"),
    (r"&", "contains ampersand"),
    (r"\$", "contains dollar sign"),
    (r"`", "contains backtick"),
]

# ELF magic bytes.
ELF_MAGIC = b"\x7fELF"

# Максимална дубина претраге.
MAX_DEPTH = 6

# Максималан број резултата.
MAX_RESULTS = 200


def run() -> dict:
    """Проналази сумњиве фајлове на систему."""
    console.print("\n[bold cyan]Suspicious files[/bold cyan]\n")

    console.print(
        "[dim]Searching for files with suspicious characteristics. "
        "This may take a few seconds...[/dim]\n"
    )

    findings = _find_suspicious()

    data = {
        "findings": findings,
        "summary": _make_summary(findings),
    }

    _print_data(data)

    return data


def _find_suspicious() -> list[dict]:
    """Претражује систем за сумњивим фајловима."""
    findings = []

    for root, dirs, files in os.walk("/", topdown=True):
        dirs[:] = [
            d for d in dirs
            if os.path.join(root, d) not in SKIP_DIRS
            and not os.path.join(root, d).startswith(
                tuple(f"{s}/" for s in SKIP_DIRS)
            )
        ]

        depth = root.count(os.sep)
        if depth > MAX_DEPTH:
            dirs[:] = []
            continue

        if not os.access(root, os.R_OK | os.X_OK):
            continue

        # Ако је root у SAFE_PATHS, прескачемо га целог.
        root_with_slash = root + "/"
        if any(root_with_slash.startswith(p) for p in SAFE_PATHS):
            dirs[:] = []
            continue

        for file_name in files:
            path = os.path.join(root, file_name)

            reasons = _check_file(path, file_name)
            if reasons:
                findings.append({
                    "path": path,
                    "reasons": reasons,
                })

                if len(findings) >= MAX_RESULTS:
                    return findings

    return findings


def _check_file(path: str, name: str) -> list[str]:
    """Проверава да ли је фајл сумњив."""
    reasons = []

    # Ако је име у SAFE_NAMES, прескачемо.
    if name in SAFE_NAMES:
        return reasons

    # Ако је путања у SAFE_PATHS, прескачемо.
    if any(path.startswith(p) for p in SAFE_PATHS):
        return reasons

    try:
        st = os.lstat(path)
    except (OSError, PermissionError):
        return reasons

    if stat.S_ISLNK(st.st_mode):
        return reasons

    is_exec = bool(st.st_mode & 0o111)

    # Проверавамо сумњива имена.
    for pattern, reason in SUSPICIOUS_NAME_PATTERNS:
        if re.search(pattern, name):
            reasons.append(reason)

    # Проверавамо двоструке екстензије.
    if _has_double_extension(name):
        reasons.append("double extension")

    # Извршни фајлови на необичним локацијама.
    if is_exec:
        for prefix in UNUSUAL_EXEC_LOCATIONS:
            if path.startswith(prefix):
                file_type = _detect_file_type(path)

                # Прескачемо sockets, FIFOs и остале специјалне
                # типове — они су често извршни по дозволама
                # али нису извршни програми.
                if not stat.S_ISREG(st.st_mode):
                    break

                if file_type == "elf":
                    reasons.append(f"ELF binary in {prefix}")
                elif file_type == "script":
                    reasons.append(f"executable script in {prefix}")

                break

    # Скривени извршни фајл ван home директоријума.
    if is_exec and name.startswith("."):
        if not path.startswith(("/home/", "/root/")):
            if stat.S_ISREG(st.st_mode):
                if "hidden executable" not in reasons:
                    reasons.append("hidden executable")

    return reasons


def _has_double_extension(name: str) -> bool:
    """Проверава да ли фајл има двоструку екстензију."""
    parts = name.split(".")

    if len(parts) < 3:
        return False

    first_ext = "." + parts[-2].lower()
    if first_ext not in DOUBLE_EXTENSIONS:
        return False

    last_ext = "." + parts[-1].lower()
    executable_exts = SCRIPT_EXTENSIONS + (
        ".exe", ".bin", ".elf", ".out",
    )

    return last_ext in executable_exts


def _detect_file_type(path: str) -> str:
    """Препознаје тип фајла (elf, script, unknown)."""
    try:
        with open(path, "rb") as f:
            header = f.read(4)
    except (PermissionError, OSError):
        return "unknown"

    if header == ELF_MAGIC:
        return "elf"

    if header[:2] == b"#!":
        return "script"

    return "unknown"


def _make_summary(findings: list[dict]) -> dict:
    """Прави резиме са бројевима."""
    reason_counts: dict[str, int] = {}

    for item in findings:
        for reason in item.get("reasons", []):
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    return {
        "total_suspicious": len(findings),
        "reason_counts": reason_counts,
        "truncated": len(findings) >= MAX_RESULTS,
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    findings = data.get("findings", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total suspicious files:[/bold]  "
        f"{summary.get('total_suspicious', 0)}"
    )

    if summary.get("truncated"):
        console.print(
            f"  [dim](results truncated to {MAX_RESULTS})[/dim]"
        )

    console.print()

    if not findings:
        console.print(
            "[bold green]No suspicious files found.[/bold green]\n"
        )
        return

    # Сумирање по разлозима.
    reason_counts = summary.get("reason_counts", {})
    if reason_counts:
        console.print("[bold]Reasons:[/bold]\n")
        for reason, count in sorted(
            reason_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            console.print(f"  {reason:40s} {count}")
        console.print()

    # Сумњиви фајлови (првих 30).
    console.print(f"[bold]Files ({len(findings)}):[/bold]\n")

    limit = 30
    for item in findings[:limit]:
        _print_finding(item)

    if len(findings) > limit:
        console.print(
            f"  [dim]... and {len(findings) - limit} more[/dim]"
        )
    console.print()


def _print_finding(item: dict) -> None:
    """Приказује један сумњив фајл."""
    path = item["path"]
    reasons = item.get("reasons", [])

    console.print(f"  [bold red]{path}[/bold red]")
    for reason in reasons:
        console.print(f"    [yellow]→ {reason}[/yellow]")
    console.print()