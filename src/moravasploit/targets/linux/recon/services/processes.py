# Модул за приказ активних процеса на систему.
# Чита /proc/<pid>/ директоријуме и извлачи информације
# о сваком процесу: име, командна линија, власник, стање,
# родитељ, меморија.
#
# Посебно тражи сумњиве процесе:
#   - покренути из /tmp, /dev/shm, /var/tmp
#   - са обрисаним бинаром (deleted)
#   - zombie
#   - без родитеља (осим systemd)
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријум са процесима.
PROC_DIR = Path("/proc")

# Путање из којих је сумњиво покренути процес.
SUSPICIOUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)

# Стања процеса (из /proc/<pid>/status).
PROCESS_STATES = {
    "R": "running",
    "S": "sleeping",
    "D": "disk sleep",
    "Z": "zombie",
    "T": "stopped",
    "t": "tracing stop",
    "X": "dead",
    "I": "idle",
}

# Позната безбедна имена процеса која се често покрећу.
KNOWN_SAFE_PROCESSES = {
    "systemd", "kthreadd", "ksoftirqd", "kworker", "rcu_sched",
    "rcu_bh", "migration", "watchdog", "cpuhp", "kdevtmpfs",
    "netns", "khungtaskd", "oom_reaper", "writeback", "kcompactd",
    "ksmd", "khugepaged", "crypto", "kintegrityd", "bioset",
    "kblockd", "ata_sff", "md", "edac-poller", "devfreq_wq",
    "kdmflush", "xfsalloc", "xfs_mru_cache", "jbd2", "ext4-rsv",
    "init", "bash", "sh", "zsh", "python", "python3", "node",
    "sshd", "sshd-session", "systemd-journald", "systemd-udevd",
    "systemd-logind", "systemd-resolved", "systemd-timesyncd",
    "dbus-daemon", "NetworkManager", "cron", "rsyslogd",
    "lightdm", "Xorg", "gnome-shell", "kwin", "mariadbd", "mysqld",
    "postgres", "redis-server", "nginx", "apache2", "httpd",
    "docker", "containerd", "containerd-shim", "code", "firefox",
    "chrome", "chromium", "brave", "python3.11", "python3.12",
    "python3.13",
}


def run() -> dict:
    """Приказује активне процесе на систему.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Processes[/bold cyan]\n")

    # Читамо све процесе.
    processes = _read_all_processes()

    if not processes:
        console.print(
            "  [dim]No processes found.[/dim]\n"
        )
        return _empty_result()

    # Тражимо сумњиве.
    suspicious = _find_suspicious(processes)

    # Правимо резиме.
    summary = _make_summary(processes, suspicious)

    data = {
        "processes": processes,
        "suspicious": suspicious,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "processes": [],
        "suspicious": [],
        "summary": {
            "total": 0,
            "running": 0,
            "sleeping": 0,
            "zombie": 0,
            "suspicious_count": 0,
        },
    }


def _read_all_processes() -> list[dict]:
    """Чита све процесе из /proc/."""
    processes = []

    try:
        entries = os.listdir(PROC_DIR)
    except (PermissionError, OSError):
        return []

    for entry in entries:
        # Само нумерички директоријуми су PID-ови.
        if not entry.isdigit():
            continue

        pid = int(entry)
        proc_data = _read_process(pid)

        if proc_data:
            processes.append(proc_data)

    return processes


def _read_process(pid: int) -> dict | None:
    """Чита податке о једном процесу."""
    proc_path = PROC_DIR / str(pid)

    # Читамо име процеса.
    name = _read_file(proc_path / "comm")
    if name is None:
        return None

    name = name.strip()

    # Читамо командну линију.
    cmdline = _read_cmdline(proc_path / "cmdline")

    # Ако нема cmdline, користимо име.
    if not cmdline:
        cmdline = f"[{name}]"

    # Читамо статус.
    status = _read_status(proc_path / "status")

    # Читамо exe линк (може бити deleted).
    exe_path = _read_symlink(proc_path / "exe")
    exe_deleted = False
    if exe_path and exe_path.endswith(" (deleted)"):
        exe_deleted = True
        exe_path = exe_path[:-10]

    # Читамо cwd линк.
    cwd = _read_symlink(proc_path / "cwd")

    return {
        "pid": pid,
        "name": name,
        "cmdline": cmdline[:200],  # скраћујемо
        "uid": status.get("uid"),
        "state": status.get("state", "?"),
        "state_name": PROCESS_STATES.get(
            status.get("state", "?"), "unknown"
        ),
        "ppid": status.get("ppid"),
        "vm_rss_kb": status.get("vm_rss_kb"),
        "threads": status.get("threads"),
        "exe_path": exe_path,
        "exe_deleted": exe_deleted,
        "cwd": cwd,
        "is_known_safe": name in KNOWN_SAFE_PROCESSES,
    }


def _read_file(path: Path) -> str | None:
    """Чита фајл и враћа садржај као стринг."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, FileNotFoundError, OSError):
        return None
    except Exception:
        return None


def _read_cmdline(path: Path) -> str:
    """Чита /proc/<pid>/cmdline (NULL-раздвојено)."""
    try:
        content = path.read_bytes()
    except (PermissionError, FileNotFoundError, OSError):
        return ""
    except Exception:
        return ""

    # Раздвајамо по NUL бајту.
    parts = content.split(b"\x00")
    args = []

    for part in parts:
        if not part:
            continue
        try:
            args.append(part.decode("utf-8", errors="replace"))
        except Exception:
            continue

    return " ".join(args)


def _read_status(path: Path) -> dict:
    """Чита /proc/<pid>/status и извлачи кључне вредности."""
    result = {}

    content = _read_file(path)
    if not content:
        return result

    for line in content.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key == "State":
            # "S (sleeping)" -> "S"
            if value:
                result["state"] = value[0]
        elif key == "PPid":
            try:
                result["ppid"] = int(value)
            except ValueError:
                pass
        elif key == "Uid":
            # "1000  1000  1000  1000" -> 1000
            parts = value.split()
            if parts:
                try:
                    result["uid"] = int(parts[0])
                except ValueError:
                    pass
        elif key == "VmRSS":
            # "1234 kB" -> 1234
            parts = value.split()
            if parts:
                try:
                    result["vm_rss_kb"] = int(parts[0])
                except ValueError:
                    pass
        elif key == "Threads":
            try:
                result["threads"] = int(value)
            except ValueError:
                pass

    return result


def _read_symlink(path: Path) -> str | None:
    """Чита симболички линк из /proc/<pid>/."""
    try:
        return str(os.readlink(path))
    except (PermissionError, FileNotFoundError, OSError):
        return None
    except Exception:
        return None


def _find_suspicious(processes: list[dict]) -> list[dict]:
    """Проналази сумњиве процесе."""
    suspicious = []

    for proc in processes:
        pid = proc["pid"]
        name = proc["name"]
        exe_path = proc.get("exe_path") or ""
        cwd = proc.get("cwd") or ""
        state = proc.get("state", "?")

        # 1. Процес покренут из сумњиве локације.
        for sus_path in SUSPICIOUS_PATHS:
            if exe_path.startswith(sus_path) or cwd.startswith(sus_path):
                suspicious.append({
                    "pid": pid,
                    "name": name,
                    "reason": f"running from {sus_path}",
                    "severity": "red",
                    "exe": exe_path,
                })
                break

        # 2. Обрисани бинар.
        if proc.get("exe_deleted"):
            suspicious.append({
                "pid": pid,
                "name": name,
                "reason": "deleted binary (possible malware)",
                "severity": "red",
                "exe": exe_path,
            })

        # 3. Zombie процес.
        if state == "Z":
            suspicious.append({
                "pid": pid,
                "name": name,
                "reason": "zombie process",
                "severity": "yellow",
                "exe": exe_path,
            })

    return suspicious


def _make_summary(
    processes: list[dict], suspicious: list[dict]
) -> dict:
    """Прави резиме."""
    running = [p for p in processes if p.get("state") == "R"]
    sleeping = [p for p in processes if p.get("state") == "S"]
    zombie = [p for p in processes if p.get("state") == "Z"]

    return {
        "total": len(processes),
        "running": len(running),
        "sleeping": len(sleeping),
        "zombie": len(zombie),
        "suspicious_count": len(suspicious),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    processes = data.get("processes", [])
    suspicious = data.get("suspicious", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total processes:[/bold]  {summary.get('total', 0)}"
    )
    console.print(
        f"  [green]Running:[/green]          "
        f"{summary.get('running', 0)}"
    )
    console.print(
        f"  [dim]Sleeping:[/dim]         "
        f"{summary.get('sleeping', 0)}"
    )

    if summary.get("zombie", 0) > 0:
        console.print(
            f"  [yellow]Zombie:[/yellow]           "
            f"{summary.get('zombie', 0)}"
        )

    if suspicious:
        console.print(
            f"  [bold red]Suspicious:[/bold red]       "
            f"{summary.get('suspicious_count', 0)}"
        )

    console.print()

    # Сумњиви прво.
    if suspicious:
        console.print(
            f"[bold red]Suspicious findings ({len(suspicious)}):[/bold red]\n"
        )
        for item in suspicious:
            severity = item.get("severity", "yellow")
            console.print(
                f"  [{severity}]● PID {item['pid']} "
                f"({item['name']})[/{severity}]"
            )
            console.print(
                f"    [dim]Reason: {item['reason']}[/dim]"
            )
            if item.get("exe"):
                console.print(
                    f"    [dim]Exe: {item['exe']}[/dim]"
                )
        console.print()

    # Приказујемо процесе (првих 25 са највише меморије).
    if processes:
        # Сортирамо по меморији (највећи први).
        sorted_procs = sorted(
            processes,
            key=lambda x: x.get("vm_rss_kb") or 0,
            reverse=True,
        )

        console.print(
            f"[bold]Top processes by memory ({len(processes)} total):[/bold]\n"
        )
        console.print(
            f"  {'PID':>6s}  {'USER':>6s}  {'RSS':>8s}  "
            f"{'STATE':8s}  {'NAME':25s}  COMMAND"
        )

        limit = 25
        for proc in sorted_procs[:limit]:
            _print_process(proc)

        if len(sorted_procs) > limit:
            console.print(
                f"  [dim]... and {len(sorted_procs) - limit} more[/dim]"
            )
        console.print()


def _print_process(proc: dict) -> None:
    """Приказује један процес."""
    pid = proc["pid"]
    uid = proc.get("uid", "?")
    vm_rss = proc.get("vm_rss_kb") or 0
    state = proc.get("state", "?")
    name = proc["name"]
    cmdline = proc.get("cmdline", "")

    # Форматирамо RSS у MB ако је велики.
    if vm_rss > 1024:
        rss_str = f"{vm_rss / 1024:.1f}M"
    else:
        rss_str = f"{vm_rss}K"

    # Скраћујемо команду.
    if len(cmdline) > 50:
        cmdline = cmdline[:47] + "..."

    # Скраћујемо име.
    if len(name) > 23:
        name = name[:20] + "..."

    # Боја за стање.
    if state == "R":
        state_color = "green"
    elif state == "Z":
        state_color = "red"
    else:
        state_color = "dim"

    console.print(
        f"  {pid:>6d}  {uid:>6}  {rss_str:>8s}  "
        f"[{state_color}]{state:8s}[/{state_color}]  "
        f"[bold]{name:25s}[/bold]  "
        f"[dim]{cmdline}[/dim]"
    )