# Модул за детаљну анализу sudo конфигурације.
# Чита /etc/sudoers и /etc/sudoers.d/ и парсира правила.
# Препознаје опасне конфигурације као што су NOPASSWD,
# ALL=(ALL), и дозволе за извршавање било које команде.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до sudo конфигурације.
SUDOERS_FILE = Path("/etc/sudoers")
SUDOERS_DIR = Path("/etc/sudoers.d")

# Патерни који указују на опасне конфигурације.
DANGEROUS_PATTERNS = [
    (r"NOPASSWD", "Password not required", "yellow"),
    (r"ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL",
     "Full root access without password", "bold red"),
    (r"ALL\s*=\s*\(ALL\)\s*ALL",
     "Full root access (any command)", "red"),
    (r"ALL\s*=\s*\(ALL\)",
     "Can run as any user", "yellow"),
    (r"/bin/(ba)?sh", "Shell access allowed", "yellow"),
    (r"/usr/bin/(ba)?sh", "Shell access allowed", "yellow"),
    (r"/usr/bin/su\b", "su allowed (privilege escalation)", "yellow"),
    (r"/usr/bin/vi\b|/usr/bin/vim\b",
     "Editor allowed (can escape to shell)", "yellow"),
    (r"/usr/bin/find\b",
     "find allowed (can execute commands)", "yellow"),
    (r"/usr/bin/less\b|/usr/bin/more\b",
     "Pager allowed (can escape to shell)", "yellow"),
]


def run() -> dict:
    """Анализира sudo конфигурацију.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Sudo configuration[/bold cyan]\n")

    # Читамо главни sudoers фајл.
    main_entries = _read_sudoers_file(SUDOERS_FILE, "/etc/sudoers")

    # Читамо све фајлове у /etc/sudoers.d/.
    drop_in_entries = _read_sudoers_dir()

    # Спајамо све уносе.
    all_entries = main_entries + drop_in_entries

    # Анализирамо опасне патерне.
    dangerous = _find_dangerous(all_entries)

    data = {
        "main_file": {
            "path": str(SUDOERS_FILE),
            "readable": _is_readable(SUDOERS_FILE),
            "entries": main_entries,
        },
        "drop_in_files": drop_in_entries,
        "dangerous_findings": dangerous,
        "summary": {
            "total_entries": len(all_entries),
            "total_dangerous": len(dangerous),
        },
    }

    _print_data(data)

    return data


def _is_readable(path: Path) -> bool:
    """Проверава да ли можемо да читамо фајл."""
    if not path.exists():
        return False

    try:
        path.read_text(encoding="utf-8", errors="replace")
        return True
    except (PermissionError, Exception):
        return False


def _read_sudoers_file(path: Path, source: str) -> list[dict]:
    """Чита sudoers фајл и враћа листу правила."""
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return []
    except Exception:
        return []

    entries = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_stripped = line.strip()

        # Прескачемо празне линије.
        if not line_stripped:
            continue

        # Прескачемо коментаре.
        if line_stripped.startswith("#"):
            # Али задржавамо #include и #includedir.
            if line_stripped.startswith("#include"):
                entries.append({
                    "type": "include",
                    "source": source,
                    "line_number": line_number,
                    "raw": line_stripped,
                })
            continue

        # Defaults линије.
        if line_stripped.startswith("Defaults"):
            entries.append({
                "type": "defaults",
                "source": source,
                "line_number": line_number,
                "raw": line_stripped,
            })
            continue

        # Alias линије (User_Alias, Host_Alias, Cmnd_Alias, Runas_Alias).
        if "_Alias" in line_stripped:
            entries.append({
                "type": "alias",
                "source": source,
                "line_number": line_number,
                "raw": line_stripped,
            })
            continue

        # Остало су правила.
        parsed = _parse_rule(line_stripped)
        if parsed:
            parsed["source"] = source
            parsed["line_number"] = line_number
            parsed["raw"] = line_stripped
            entries.append(parsed)

    return entries


def _parse_rule(line: str) -> dict | None:
    """Парсира sudo правило.

    Формат:
        user host=(runas) commands
        user host=(runas) NOPASSWD: commands
        %group host=(runas) commands
    """
    # Основни патерн: sweb host=(runas) commands
    match = re.match(
        r"^(\S+)\s+(\S+)\s*=\s*(?:\(([^)]+)\))?\s*(.*)$",
        line,
    )

    if not match:
        return None

    subject = match.group(1)
    host = match.group(2)
    runas = match.group(3) or ""
    commands = match.group(4).strip()

    # Тип субјекта — корисник или група.
    subject_type = "group" if subject.startswith("%") else "user"

    # Проверавамо NOPASSWD.
    nopasswd = "NOPASSWD" in commands

    return {
        "type": "rule",
        "subject": subject,
        "subject_type": subject_type,
        "host": host,
        "runas": runas,
        "commands": commands,
        "nopasswd": nopasswd,
    }


def _read_sudoers_dir() -> list[dict]:
    """Чита све фајлове у /etc/sudoers.d/."""
    entries = []

    if not SUDOERS_DIR.exists() or not SUDOERS_DIR.is_dir():
        return entries

    try:
        files = sorted(SUDOERS_DIR.iterdir())
    except PermissionError:
        return entries
    except Exception:
        return entries

    for file_path in files:
        if not file_path.is_file():
            continue

        # У sudoers.d могу бити и backup фајлови (нпр. .dpkg-old).
        # Прескачемо оне који садрже тачку на почетку.
        name = file_path.name
        if name.startswith(".") or name.endswith("~"):
            continue

        source = f"/etc/sudoers.d/{name}"
        file_entries = _read_sudoers_file(file_path, source)
        entries.extend(file_entries)

    return entries


def _find_dangerous(entries: list[dict]) -> list[dict]:
    """Проналази опасне конфигурације у правилима."""
    findings = []

    for entry in entries:
        if entry.get("type") != "rule":
            continue

        raw = entry.get("raw", "")
        commands = entry.get("commands", "")

        # Проверавамо сваки опасан патерн.
        for pattern, description, severity in DANGEROUS_PATTERNS:
            if re.search(pattern, raw, re.IGNORECASE):
                findings.append({
                    "subject": entry.get("subject"),
                    "subject_type": entry.get("subject_type"),
                    "source": entry.get("source"),
                    "line_number": entry.get("line_number"),
                    "pattern": pattern,
                    "description": description,
                    "severity": severity,
                    "raw": raw,
                })
                # Не додајемо вишеструке налазе за исти унос.
                break

    return findings


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    main = data.get("main_file", {})
    drop_in = data.get("drop_in_files", [])
    dangerous = data.get("dangerous_findings", [])
    summary = data.get("summary", {})

    # Главни фајл.
    console.print("[bold]Main file:[/bold]  /etc/sudoers")

    if main.get("readable"):
        main_entries = main.get("entries", [])
        console.print(
            f"  [green]Readable[/green] ({len(main_entries)} entries)"
        )
    else:
        console.print(
            "  [yellow]Not readable[/yellow] "
            "[dim](requires root)[/dim]"
        )

    # Drop-in фајлови.
    drop_in_count = len(set(e.get("source") for e in drop_in))
    console.print(
        f"[bold]Drop-in files:[/bold]  {drop_in_count} "
        f"({len(drop_in)} entries)"
    )

    console.print(
        f"[bold]Total entries:[/bold]  {summary.get('total_entries', 0)}"
    )
    console.print()

    # Ако нема података, објашњавамо зашто.
    if not main.get("readable") and not drop_in:
        console.print(
            "[yellow]/etc/sudoers is not readable by the current user.[/yellow]\n"
        )
        console.print(
            "[dim]Run 'sudo moravasploit' to see sudo configuration.[/dim]\n"
        )
        return

    # Приказујемо опасне налазе прво.
    if dangerous:
        console.print(
            f"[bold red]Dangerous findings ({len(dangerous)}):[/bold red]\n"
        )
        for finding in dangerous:
            _print_dangerous(finding)
        console.print()
    else:
        console.print(
            "[bold green]No dangerous patterns detected.[/bold green]\n"
        )

    # Приказујемо сва правила (првих 20).
    all_entries = main.get("entries", []) + drop_in
    rules = [e for e in all_entries if e.get("type") == "rule"]

    if rules:
        console.print(f"[bold]Rules ({len(rules)}):[/bold]\n")
        for rule in rules[:20]:
            _print_rule(rule)

        if len(rules) > 20:
            console.print(
                f"  [dim]... and {len(rules) - 20} more[/dim]\n"
            )


def _print_dangerous(finding: dict) -> None:
    """Приказује један опасан налаз."""
    severity = finding.get("severity", "yellow")
    subject = finding.get("subject", "?")
    description = finding.get("description", "")
    source = finding.get("source", "")
    line_number = finding.get("line_number", "?")

    console.print(
        f"  [{severity}]● {subject}[/{severity}]  "
        f"[dim]{description}[/dim]"
    )
    console.print(
        f"    [dim]Source: {source}:{line_number}[/dim]"
    )


def _print_rule(rule: dict) -> None:
    """Приказује једно sudo правило."""
    subject = rule.get("subject", "?")
    subject_type = rule.get("subject_type", "user")
    host = rule.get("host", "?")
    runas = rule.get("runas", "")
    commands = rule.get("commands", "")
    nopasswd = rule.get("nopasswd", False)

    # Ознака за тип субјекта.
    type_marker = "group" if subject_type == "group" else "user"

    # NOPASSWD је важно — означавамо црвено.
    if nopasswd:
        nopasswd_marker = " [bold red](NOPASSWD)[/bold red]"
    else:
        nopasswd_marker = ""

    console.print(
        f"  [bold]{subject}[/bold] [dim]({type_marker})[/dim]"
        f"{nopasswd_marker}"
    )

    # Скролујемо линију.
    runas_str = f"=({runas})" if runas else ""
    line = f"    {host}{runas_str} {commands}"

    if len(line) > 100:
        line = line[:97] + "..."

    console.print(f"  [dim]{line}[/dim]")
    console.print()