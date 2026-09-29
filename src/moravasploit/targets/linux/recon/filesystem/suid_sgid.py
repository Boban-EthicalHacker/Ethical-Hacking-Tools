# Модул за проналажење фајлова са SUID и SGID битовима.
# SUID (Set User ID) и SGID (Set Group ID) дозвољавају да
# фајл ради са привилегијама власника, а не онога ко га покрене.
# Ово је чест пут за privilege escalation ако је фајл погрешан.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import stat
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

# Познати безбедни SUID/SGID фајлови и патерни.
KNOWN_SAFE = {
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/bin/su",
    "/bin/mount",
    "/bin/umount",
    "/sbin/mount",
    "/sbin/umount",
    "/usr/bin/dumpcap",
    "/usr/bin/nmap",
    "/usr/lib/wireshark/",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/snapd/snap-confine",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/bin/at",
    "/usr/bin/crontab",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/expiry",
    "/usr/bin/chage",
    "/usr/bin/ssh-agent",
    "chrome-sandbox",
    "kismet_cap_",
    "/usr/sbin/mount.cifs",
    "/usr/sbin/mount.nfs",
    "/usr/bin/ntfs-3g",
    "/usr/sbin/pppd",
    "/usr/bin/dotlockfile",
    "/usr/bin/plocate",
    "/usr/sbin/unix_chkpwd",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/bin/rsh-redone-rlogin",
    "/usr/bin/rsh-redone-rsh",
}

MAX_DEPTH = 8


def run() -> dict:
    """Проналази SUID и SGID фајлове на систему.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]SUID / SGID files[/bold cyan]\n")

    console.print(
        "[dim]Searching for files with SUID or SGID bit set. "
        "This may take a few seconds...[/dim]\n"
    )

    suid_files, sgid_files = _find_special_files()

    data = {
        "suid_files": suid_files,
        "sgid_files": sgid_files,
        "summary": {
            "total_suid": len(suid_files),
            "total_sgid": len(sgid_files),
            "unknown_suid": len([f for f in suid_files if not f["is_safe"]]),
            "unknown_sgid": len([f for f in sgid_files if not f["is_safe"]]),
        },
    }

    _print_data(data)

    return data


def _find_special_files() -> tuple[list[dict], list[dict]]:
    """Претражује систем за SUID и SGID фајловима."""
    suid_files: list[dict] = []
    sgid_files: list[dict] = []

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

        if not os.access(root, os.R_OK):
            continue

        for file_name in files:
            path = os.path.join(root, file_name)

            try:
                st = os.lstat(path)
            except (OSError, PermissionError):
                continue

            if stat.S_ISLNK(st.st_mode):
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            if st.st_mode & stat.S_ISUID:
                suid_files.append(_build_file_info(path, st))

            if st.st_mode & stat.S_ISGID:
                sgid_files.append(_build_file_info(path, st))

    return suid_files, sgid_files


def _build_file_info(path: str, st: os.stat_result) -> dict:
    """Прави речник са информацијама о фајлу."""
    return {
        "path": path,
        "size_bytes": st.st_size,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.filemode(st.st_mode),
        "is_safe": _is_known_safe(path),
    }


def _is_known_safe(path: str) -> bool:
    """Проверава да ли је фајл у листи познатих безбедних."""
    for safe in KNOWN_SAFE:
        if safe.startswith("/"):
            if path == safe or path.startswith(safe):
                return True
        else:
            if safe in path:
                return True
    return False


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    suid_files = data.get("suid_files", [])
    sgid_files = data.get("sgid_files", [])
    summary = data.get("summary", {})

    _print_section("SUID", suid_files, summary.get("unknown_suid", 0))
    _print_section("SGID", sgid_files, summary.get("unknown_sgid", 0))

    console.print("[bold]Summary:[/bold]\n")
    console.print(f"  SUID files:  {summary.get('total_suid', 0)}")
    console.print(f"  SGID files:  {summary.get('total_sgid', 0)}")
    console.print(
        f"  [yellow]Unknown SUID:  {summary.get('unknown_suid', 0)}[/yellow]"
    )
    console.print(
        f"  [yellow]Unknown SGID:  {summary.get('unknown_sgid', 0)}[/yellow]"
    )
    console.print()


def _print_section(title: str, files: list[dict], unknown_count: int) -> None:
    """Приказује једну секцију (SUID или SGID)."""
    if not files:
        console.print(f"[bold]{title} files:[/bold]  [dim]none found[/dim]\n")
        return

    unknown = [f for f in files if not f["is_safe"]]
    known = [f for f in files if f["is_safe"]]

    console.print(
        f"[bold]{title} files:[/bold]  {len(files)} total "
        f"({len(known)} known safe, {len(unknown)} unknown)\n"
    )

    if unknown:
        console.print(
            "[bold yellow]Potentially interesting:[/bold yellow]\n"
        )
        for f in sorted(unknown, key=lambda x: x["path"]):
            _print_file(f)
        console.print()

    if known:
        console.print("[bold]Known safe:[/bold]\n")
        for f in sorted(known, key=lambda x: x["path"]):
            console.print(f"  [dim]{f['path']}[/dim]")
        console.print()


def _print_file(f: dict) -> None:
    """Приказује један фајл са детаљима."""
    console.print(f"  [bold yellow]{f['path']}[/bold yellow]")
    console.print(
        f"    Mode:  {f['mode']}  "
        f"Owner: {f['uid']}:{f['gid']}  "
        f"Size:  {f['size_bytes']} B"
    )