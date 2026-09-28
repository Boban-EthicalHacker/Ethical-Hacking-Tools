# Модул за проналажење фајлова са SUID и SGID битовима.
# SUID (Set User ID) и SGID (Set Group ID) дозвољавају да
# фајл ради са привилегијама власника, а не онога ко га покрене.
# Ово је чест пут за privilege escalation ако је фајл погрешан.
import os
import stat
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми које прескачемо при претрази.
# То су виртуелни фајл системи и мрежни делови, нема смисла
# претраживати их.
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
# Ако ставка почиње са "/", третира се као пуна путања
# (или префикс путање). Ако не почиње са "/", третира се
# као део имена који се може појавити било где у путањи.
KNOWN_SAFE = {
    # Стандардни системски алати.
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
    # Kali специфични (Wireshark, nmap, итд.)
    "/usr/bin/dumpcap",
    "/usr/bin/nmap",
    "/usr/lib/wireshark/",
    # Остали познати системски.
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
    # Browser sandbox-ови ( имају SUID намерно ради изолације).
    "chrome-sandbox",
    # Kali специфични алати за хардвер.
    "kismet_cap_",
    # Системски mount алати.
    "/usr/sbin/mount.cifs",
    "/usr/sbin/mount.nfs",
    "/usr/bin/ntfs-3g",
    "/usr/sbin/pppd",
    # Остали системски алати.
    "/usr/bin/dotlockfile",
    "/usr/bin/plocate",
    "/usr/sbin/unix_chkpwd",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/bin/rsh-redone-rlogin",
    "/usr/bin/rsh-redone-rsh",
}

# Максимална дубина претраге да не бисмо отишли предубоко
# у системске фолдере.
MAX_DEPTH = 8


def run() -> None:
    """Проналази SUID и SGID фајлове на систему."""
    console.print("\n[bold cyan]SUID / SGID files[/bold cyan]\n")

    # Приказујемо објашњење.
    console.print(
        "[dim]Searching for files with SUID or SGID bit set. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо SUID/SGID фајлове.
    suid_files, sgid_files = _find_special_files()

    # Приказујемо SUID.
    _print_suid(suid_files)

    # Приказујемо SGID.
    _print_sgid(sgid_files)

    # Резиме.
    _print_summary(suid_files, sgid_files)


def _find_special_files() -> tuple[list[dict], list[dict]]:
    """Претражује систем за SUID и SGID фајловима.

    Враћа два tuple-а: (suid_files, sgid_files)
    Сваки фајл је речник са подацима.
    """
    suid_files: list[dict] = []
    sgid_files: list[dict] = []

    # Идемо кроз све директоријуме од корена.
    for root, dirs, files in os.walk("/", topdown=True):
        # Прескачемо директоријуме из SKIP_DIRS.
        # Мењамо dirs у месту да os.walk не улази у њих.
        dirs[:] = [
            d for d in dirs
            if os.path.join(root, d) not in SKIP_DIRS
            and not os.path.join(root, d).startswith(
                tuple(f"{s}/" for s in SKIP_DIRS)
            )
        ]

        # Проверавамо дубину.
        depth = root.count(os.sep)
        if depth > MAX_DEPTH:
            dirs[:] = []
            continue

        # Прескачемо ако немамо дозволу да читамо овај директоријум.
        if not os.access(root, os.R_OK):
            continue

        for file_name in files:
            path = os.path.join(root, file_name)

            try:
                # Узимамо stat структуру.
                st = os.lstat(path)
            except (OSError, PermissionError):
                continue

            # Прескачемо symbolic links.
            if stat.S_ISLNK(st.st_mode):
                continue

            # Узимамо само регуларне фајлове.
            if not stat.S_ISREG(st.st_mode):
                continue

            # Проверавамо SUID бит.
            if st.st_mode & stat.S_ISUID:
                suid_files.append(_build_file_info(path, st))

            # Проверавамо SGID бит.
            if st.st_mode & stat.S_ISGID:
                sgid_files.append(_build_file_info(path, st))

    return suid_files, sgid_files


def _build_file_info(path: str, st: os.stat_result) -> dict:
    """Прави речник са информацијама о фајлу."""
    return {
        "path": path,
        "size": st.st_size,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.filemode(st.st_mode),
        "is_safe": _is_known_safe(path),
    }


def _is_known_safe(path: str) -> bool:
    """Проверава да ли је фајл у листи познатих безбедних."""
    for safe in KNOWN_SAFE:
        # Ако је "safe" пуна путања, проверавамо поклапање
        # почетка путање.
        if safe.startswith("/"):
            if path == safe or path.startswith(safe):
                return True
        else:
            # Ако је "safe" само име или део имена, проверавамо
            # да ли се појављује било где у путањи.
            if safe in path:
                return True
    return False


def _print_suid(files: list[dict]) -> None:
    """Приказује SUID фајлове."""
    if not files:
        console.print("[bold]SUID files:[/bold]  [dim]none found[/dim]\n")
        return

    # Раздвајамо на "познате" и "непознате".
    unknown = [f for f in files if not f["is_safe"]]
    known = [f for f in files if f["is_safe"]]

    console.print(
        f"[bold]SUID files:[/bold]  {len(files)} total "
        f"({len(known)} known safe, {len(unknown)} unknown)\n"
    )

    # Прво приказујемо непознате (потенцијално занимљиве).
    if unknown:
        console.print(
            "[bold yellow]Potentially interesting:[/bold yellow]\n"
        )
        for f in sorted(unknown, key=lambda x: x["path"]):
            _print_file(f)
        console.print()

    # Затим познате (само укратко).
    if known:
        console.print("[bold]Known safe:[/bold]\n")
        for f in sorted(known, key=lambda x: x["path"]):
            console.print(f"  [dim]{f['path']}[/dim]")
        console.print()


def _print_sgid(files: list[dict]) -> None:
    """Приказује SGID фајлове."""
    if not files:
        console.print("[bold]SGID files:[/bold]  [dim]none found[/dim]\n")
        return

    unknown = [f for f in files if not f["is_safe"]]
    known = [f for f in files if f["is_safe"]]

    console.print(
        f"[bold]SGID files:[/bold]  {len(files)} total "
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
        f"Size:  {f['size']} B"
    )


def _print_summary(suid: list[dict], sgid: list[dict]) -> None:
    """Приказује резиме на крају."""
    unknown_suid = [f for f in suid if not f["is_safe"]]
    unknown_sgid = [f for f in sgid if not f["is_safe"]]

    console.print("[bold]Summary:[/bold]\n")
    console.print(f"  SUID files:  {len(suid)}")
    console.print(f"  SGID files:  {len(sgid)}")
    console.print(
        f"  [yellow]Unknown SUID:  {len(unknown_suid)}[/yellow]"
    )
    console.print(
        f"  [yellow]Unknown SGID:  {len(unknown_sgid)}[/yellow]"
    )
    console.print()