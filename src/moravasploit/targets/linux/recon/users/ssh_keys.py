# Модул за приказ SSH кључева на систему.
# Проналази authorized_keys и known_hosts фајлове свих корисника
# и приказује шта садрже. Ово је важно за безбедност јер
# неовлашћени кључеви у authorized_keys значе неовлашћен приступ.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import base64
import hashlib
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми где тражимо .ssh фолдере.
HOME_DIRS = [
    Path("/root"),
    Path("/home"),
]


def run() -> dict:
    """Приказује SSH кључеве на систему.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]SSH keys[/bold cyan]\n")

    # Проналазимо све .ssh фолдере и евидентирамо прескочене.
    ssh_dirs, skipped = _find_ssh_dirs()

    if not ssh_dirs and not skipped:
        console.print("  [dim]No .ssh directories found.[/dim]\n")
        return {
            "ssh_dirs": [],
            "skipped": [],
            "summary": {
                "total_dirs": 0,
                "total_skipped": 0,
                "total_authorized_keys": 0,
                "total_known_hosts": 0,
            },
        }

    # Анализирамо сваки .ssh фолдер.
    results = []

    for ssh_dir in ssh_dirs:
        result = _analyze_ssh_dir(ssh_dir)
        results.append(result)

    # Правимо резиме.
    summary = _make_summary(results, skipped)

    data = {
        "ssh_dirs": results,
        "skipped": skipped,
        "summary": summary,
    }

    _print_data(data)

    return data


def _find_ssh_dirs() -> tuple[list[Path], list[dict]]:
    """Проналази све .ssh фолдере у системима корисника.

    Враћа:
        Tuple (list_of_ssh_dirs, list_of_skipped)
        Где је skipped листа речника са разлогом прескакања.
    """
    found = []
    skipped = []

    for home_base in HOME_DIRS:
        # Проверавамо да ли уопште можемо да приступимо.
        try:
            if not home_base.exists():
                continue
        except (PermissionError, OSError):
            skipped.append({
                "path": str(home_base),
                "reason": "permission denied",
            })
            continue

        # /root је сам по себи home.
        if home_base == Path("/root"):
            ssh_dir = home_base / ".ssh"
            try:
                if ssh_dir.exists() and ssh_dir.is_dir():
                    found.append(ssh_dir)
            except (PermissionError, OSError):
                skipped.append({
                    "path": str(ssh_dir),
                    "reason": "permission denied",
                })
            continue

        # /home садржи више корисника.
        try:
            user_homes = list(home_base.iterdir())
        except (PermissionError, OSError):
            skipped.append({
                "path": str(home_base),
                "reason": "permission denied",
            })
            continue

        for user_home in user_homes:
            try:
                if not user_home.is_dir():
                    continue

                ssh_dir = user_home / ".ssh"
                if ssh_dir.exists() and ssh_dir.is_dir():
                    found.append(ssh_dir)
            except (PermissionError, OSError):
                skipped.append({
                    "path": str(user_home / ".ssh"),
                    "reason": "permission denied",
                })
                continue

    return found, skipped


def _analyze_ssh_dir(ssh_dir: Path) -> dict:
    """Анализира један .ssh фолдер."""
    # Име корисника из путање.
    user = ssh_dir.parent.name

    result = {
        "user": user,
        "path": str(ssh_dir),
        "authorized_keys": [],
        "known_hosts": [],
        "other_files": [],
    }

    # Проверавамо приступ фолдеру.
    try:
        files = list(ssh_dir.iterdir())
    except PermissionError:
        result["error"] = "permission denied"
        return result
    except Exception as error:
        result["error"] = str(error)
        return result

    for file_path in files:
        try:
            if not file_path.is_file():
                continue
        except (PermissionError, OSError):
            continue

        name = file_path.name

        if name == "authorized_keys":
            result["authorized_keys"] = _parse_authorized_keys(file_path)
        elif name == "known_hosts":
            result["known_hosts"] = _parse_known_hosts(file_path)
        else:
            # Остали фајлови (id_rsa, config, ...).
            try:
                size = file_path.stat().st_size
                result["other_files"].append({
                    "name": name,
                    "size_bytes": size,
                })
            except Exception:
                continue

    return result


def _parse_authorized_keys(path: Path) -> list[dict]:
    """Парсира authorized_keys фајл.

    Свака линија може имати формат:
        [options] ssh-rsa AAAA... comment
        [options] ssh-ed25519 AAAA... comment
    """
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return []
    except Exception:
        return []

    keys = []

    for line in content.splitlines():
        line = line.strip()

        # Прескачемо празне линије и коментаре.
        if not line or line.startswith("#"):
            continue

        parsed = _parse_key_line(line)
        if parsed:
            keys.append(parsed)

    return keys


def _parse_key_line(line: str) -> dict | None:
    """Парсира једну линију из authorized_keys."""
    # Типови кључева које препознајемо.
    key_types = (
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    )

    parts = line.split()

    # Проналазимо индекс типа кључа.
    type_index = None
    for i, part in enumerate(parts):
        if part in key_types:
            type_index = i
            break

    if type_index is None:
        return None

    key_type = parts[type_index]

    # Опције су све пре типа (ако их има).
    options = " ".join(parts[:type_index]) if type_index > 0 else ""

    # Кључ је после типа.
    if type_index + 1 >= len(parts):
        return None

    key_data = parts[type_index + 1]

    # Коментар је све остало (може бити празно).
    comment = " ".join(parts[type_index + 2:]) if type_index + 2 < len(parts) else ""

    # Рачунамо fingerprint.
    fingerprint = _calculate_fingerprint(key_data)

    return {
        "type": key_type,
        "comment": comment,
        "options": options,
        "fingerprint": fingerprint,
    }


def _calculate_fingerprint(key_data: str) -> str | None:
    """Рачуна SHA256 fingerprint SSH кључа.

    OpenSSH користи SHA256 base64 формат.
    """
    try:
        # Декодирамо base64 кључ.
        key_bytes = base64.b64decode(key_data)
    except Exception:
        return None

    # Рачунамо SHA256.
    digest = hashlib.sha256(key_bytes).digest()

    # Кодирамо у base64 (OpenSSH формат, без padding-а).
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")

    return f"SHA256:{encoded}"


def _parse_known_hosts(path: Path) -> list[dict]:
    """Парсира known_hosts фајл.

    Свака линија има формат:
        hostname[,hostname] keytype key
    """
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return []
    except Exception:
        return []

    hosts = []

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        hosts.append({
            "host": parts[0],
            "key_type": parts[1],
        })

    return hosts


def _make_summary(results: list[dict], skipped: list[dict]) -> dict:
    """Прави резиме."""
    total_auth = sum(len(r.get("authorized_keys", [])) for r in results)
    total_hosts = sum(len(r.get("known_hosts", [])) for r in results)

    return {
        "total_dirs": len(results),
        "total_skipped": len(skipped),
        "total_authorized_keys": total_auth,
        "total_known_hosts": total_hosts,
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    ssh_dirs = data.get("ssh_dirs", [])
    skipped = data.get("skipped", [])

    console.print(
        f"[bold]Total .ssh dirs:[/bold]          {summary.get('total_dirs', 0)}"
    )
    console.print(
        f"[bold]Total authorized_keys:[/bold]   "
        f"{summary.get('total_authorized_keys', 0)}"
    )
    console.print(
        f"[bold]Total known_hosts:[/bold]       "
        f"{summary.get('total_known_hosts', 0)}"
    )

    if skipped:
        console.print(
            f"[bold]Skipped:[/bold]                "
            f"[yellow]{summary.get('total_skipped', 0)}[/yellow]"
        )

    console.print()

    # Приказујемо прескочене фолдере.
    if skipped:
        console.print("[bold yellow]Skipped directories:[/bold yellow]\n")
        for item in skipped:
            console.print(
                f"  [yellow]{item['path']}[/yellow]  "
                f"[dim]({item['reason']})[/dim]"
            )
        console.print()

    # Приказујемо детаље за сваки фолдер.
    for result in ssh_dirs:
        _print_ssh_dir(result)


def _print_ssh_dir(result: dict) -> None:
    """Приказује један .ssh фолдер."""
    user = result.get("user", "unknown")

    console.print(f"[bold cyan]User: {user}[/bold cyan]")
    console.print(f"  [dim]{result.get('path', '')}[/dim]")

    # Грешка при приступу.
    if result.get("error"):
        console.print(
            f"  [red]Error: {result['error']}[/red]\n"
        )
        return

    # authorized_keys.
    keys = result.get("authorized_keys", [])
    if keys:
        console.print(
            f"\n  [bold]authorized_keys:[/bold] {len(keys)} key(s)\n"
        )
        for key in keys:
            _print_key(key)

    # known_hosts.
    hosts = result.get("known_hosts", [])
    if hosts:
        console.print(
            f"  [bold]known_hosts:[/bold] {len(hosts)} host(s)"
        )
        # Приказујемо само првих 5.
        for host in hosts[:5]:
            console.print(f"    [dim]{host['host']}[/dim]")
        if len(hosts) > 5:
            console.print(
                f"    [dim]... and {len(hosts) - 5} more[/dim]"
            )

    # Остали фајлови.
    others = result.get("other_files", [])
    if others:
        console.print("  [bold]Other files:[/bold]")
        for other in others:
            size_str = _format_size(other["size_bytes"])
            console.print(
                f"    {other['name']}  [dim]({size_str})[/dim]"
            )

    console.print()


def _print_key(key: dict) -> None:
    """Приказује један SSH кључ."""
    # Опције су важне — показују ограничења.
    if key.get("options"):
        console.print(
            f"    [yellow][options][/yellow]  {key['options']}"
        )

    console.print(f"    Type:        {key['type']}")
    console.print(f"    Comment:     {key.get('comment') or '(none)'}")
    console.print(f"    Fingerprint: {key.get('fingerprint') or '(unknown)'}")
    console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"