# Модул за анализу историје команди корисника.
# Историја команди открива шта је корисник радио — може
# садржати лозинке, токене, URL-ове са креденцијалима.
# Класичан пример: "mysql -u root -pSecretPass123".
#
# Чита .bash_history, .zsh_history и друге history фајлове.
# Препознаје осетљиве команде.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

# History фајлови које тражимо.
HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".ksh_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
    ".sqlite_history",
    ".lesshst",
    ".viminfo",
    ".node_repl_history",
    ".irb_history",
    ".pry_history",
    ".rediscli_history",
]

# Директоријуми где тражимо кориснике.
USER_HOME_DIRS = [
    Path("/root"),
    Path("/home"),
]

# Патерни за осетљиве команде.
SENSITIVE_PATTERNS = [
    # Лозинке — само у специфичним командама.
    # mysql/mariadb са -p (без размака или са размаком).
    (r"\bmysql\s+.*\s-p\S+", "MySQL password in command"),
    (r"\bmysql\s+.*\s-p\s+\S+", "MySQL password in command"),
    (r"\bmariadb\s+.*\s-p\S+", "MariaDB password in command"),

    # sshpass
    (r"\bsshpass\s+-p\s*\S+", "sshpass with password"),

    # PostgreSQL са PGPASSWORD
    (r"\bPGPASSWORD=\S+", "PostgreSQL password in env"),

    # curl/wget са лозинком
    (r"\bcurl\s+.*-u\s+\S+:\S+", "curl with credentials"),
    (r"\bwget\s+.*--user=\S+.*--password=\S+", "wget with credentials"),

    # --password= (али не у именима фајлова).
    (r"--password[=\s]+\S+", "password in command"),

    # PASSWORD= (окружење).
    (r"\b(?:PASSWORD|PASSWD)=(?!\s)(\S+)", "password in env variable"),

    # Токени у curl/wget URL-овима.
    (r"curl.*[?&](token|key|api_key|apikey|access_token)=", "token in URL"),
    (r"wget.*[?&](token|key|api_key|apikey|access_token)=", "token in URL"),

    # Authorization header.
    (r"-H\s+['\"]Authorization:\s*(?:Bearer|Basic)\s+\S+", "auth header"),

    # API кључеви (специфични формати).
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    (r"\bsk-[a-zA-Z0-9]{32,}\b", "OpenAI key"),
    (r"\bgh[ps]_[a-zA-Z0-9]{36,}\b", "GitHub token"),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key"),
    (r"\bsk_live_[0-9a-zA-Z]{24,}\b", "Stripe live key"),

    # AWS
    (r"\bAWS_SECRET_ACCESS_KEY\b", "AWS secret key reference"),

    # Docker
    (r"docker\s+login\s+.*-p\s+\S+", "docker login with password"),

    # Git URL са credentials.
    (r"git\s+(?:clone|remote\s+add)\s+https?://[^@\s]+:[^@\s]+@", "git URL with credentials"),

    # SSH са кључем (мање озбиљно, али вреди знати).
    (r"\bssh\s+.*-i\s+\S+", "SSH with key"),
]
# Компајлирамо патерне.
SENSITIVE_RE = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in SENSITIVE_PATTERNS
]

# Максималан број команди за приказ.
MAX_DISPLAY = 30

# Максимална дужина команде.
MAX_CMD_LEN = 200


def run() -> dict:
    """Анализира history фајлове корисника.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Command history[/bold cyan]\n")

    # Проналазимо све history фајлове.
    all_histories = []

    for home_base in USER_HOME_DIRS:
        if not home_base.exists():
            continue

        if home_base == Path("/root"):
            histories = _read_user_histories(home_base, "root")
            all_histories.extend(histories)
        else:
            try:
                user_homes = sorted(home_base.iterdir())
            except (PermissionError, Exception):
                continue

            for user_home in user_homes:
                if not user_home.is_dir():
                    continue

                username = user_home.name
                histories = _read_user_histories(user_home, username)
                all_histories.extend(histories)

    # Проналазимо осетљиве команде.
    findings = _find_sensitive(all_histories)

    # Правимо резиме.
    summary = {
        "total_users": len(set(h["user"] for h in all_histories)),
        "total_histories": len(all_histories),
        "total_commands": sum(h["command_count"] for h in all_histories),
        "sensitive_count": len(findings),
    }

    data = {
        "histories": all_histories,
        "sensitive_findings": findings,
        "summary": summary,
    }

    _print_data(data)

    return data


def _read_user_histories(home: Path, username: str) -> list[dict]:
    """Чита све history фајлове за једног корисника."""
    histories = []

    for history_name in HISTORY_FILES:
        file_path = home / history_name

        if not file_path.exists() or not file_path.is_file():
            continue

        # Проверавамо приступ.
        if not os.access(file_path, os.R_OK):
            continue

        history = _read_history_file(file_path, username, history_name)
        if history:
            histories.append(history)

    return histories


def _read_history_file(
    path: Path, username: str, history_name: str
) -> dict | None:
    """Чита један history фајл."""
    try:
        # Читамо са errors="replace" јер могу бити бинарни садржаји.
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return None

    # Парсирамо команде.
    commands = _parse_history(content, history_name)

    if not commands:
        return {
            "user": username,
            "file": str(path),
            "name": history_name,
            "command_count": 0,
            "commands": [],
        }

    # Узимамо само последњих N команди за приказ,
    # али све за JSON (може бити корисно).
    return {
        "user": username,
        "file": str(path),
        "name": history_name,
        "command_count": len(commands),
        "commands": commands[-500:],  # лимитирамо на 500 за JSON
    }


def _parse_history(content: str, history_name: str) -> list[str]:
    """Парсира линије из history фајла."""
    commands = []

    # Zsh има посебан формат са timestamps.
    if history_name == ".zsh_history":
        return _parse_zsh_history(content)

    # За .viminfo — само команде (линије које почињу са ":" или "!").
    if history_name == ".viminfo":
        return _parse_viminfo(content)

    # Стандардни формат — свака линија је команда.
    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        # Прескачемо "#<timestamp>" линије (bash са timestamps).
        if line.startswith("#") and line[1:].isdigit():
            continue

        # Скраћујемо превише дугачке команде.
        if len(line) > MAX_CMD_LEN:
            line = line[:MAX_CMD_LEN - 3] + "..."

        commands.append(line)

    return commands


def _parse_zsh_history(content: str) -> list[str]:
    """Парсира zsh history.

    Zsh може имати формат: ": <timestamp>:<duration>;command"
    или обичан формат ако је EXTENDED_HISTORY искључен.
    """
    commands = []

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        # Проверавамо zsh формат са timestamp-ом.
        # ": 1234567890:0;command"
        match = re.match(r"^:\s+\d+:\d+;(.+)$", line)

        if match:
            cmd = match.group(1).strip()
        else:
            cmd = line

        if len(cmd) > MAX_CMD_LEN:
            cmd = cmd[:MAX_CMD_LEN - 3] + "..."

        commands.append(cmd)

    return commands


def _parse_viminfo(content: str) -> list[str]:
    """Парсира viminfo.

    Тражимо линије које почињу са ":" (ex команде) или "/" (search).
    """
    commands = []

    for line in content.splitlines():
        line = line.strip()

        # Ex команде почињу са ":".
        if line.startswith(":"):
            cmd = line[1:].strip()
            if cmd and len(cmd) < MAX_CMD_LEN:
                commands.append(f"[vim] {cmd}")

    return commands


def _find_sensitive(histories: list[dict]) -> list[dict]:
    """Проналази осетљиве команде у history-има."""
    findings = []

    for history in histories:
        user = history.get("user", "?")
        file_path = history.get("file", "?")
        commands = history.get("commands", [])

        for line_number, command in enumerate(commands, start=1):
            # Проверавамо сваки патерн.
            for pattern, description in SENSITIVE_RE:
                if pattern.search(command):
                    # Скраћујемо и маскирамо команду за приказ.
                    display = _mask_command(command)

                    findings.append({
                        "user": user,
                        "file": file_path,
                        "line_number": line_number,
                        "command": command,
                        "display": display,
                        "reason": description,
                        "severity": _severity_for(description),
                    })
                    break  # само један разлог по команди

    return findings


def _severity_for(reason: str) -> str:
    """Одређује озбиљност на основу разлога."""
    # Црвено за праве креденцијале.
    high_risk = (
        "password",
        "token",
        "AWS",
        "key",
        "Bearer",
    )

    for marker in high_risk:
        if marker.lower() in reason.lower():
            return "red"

    return "yellow"


def _mask_command(command: str) -> str:
    """Маскира осетљиве делове команде за приказ.

    Замењује вредности после -p, --password, token= са ***.
    """
    masked = command

    # Маскирамо -pXXX и -p XXX.
    masked = re.sub(
        r"(-p)(\S+)",
        lambda m: m.group(1) + "***",
        masked,
    )
    masked = re.sub(
        r"(-p\s+)(\S+)",
        lambda m: m.group(1) + "***",
        masked,
    )

    # Маскирамо --password=XXX и --password XXX.
    masked = re.sub(
        r"(--password[=\s]+)(\S+)",
        lambda m: m.group(1) + "***",
        masked,
    )

    # Маскирамо PASSWORD=XXX и сличне.
    masked = re.sub(
        r"((?:PASSWORD|PASSWD|PGPASSWORD|TOKEN|API_KEY|SECRET)[=:]\s*)(\S+)",
        lambda m: m.group(1) + "***",
        masked,
        flags=re.IGNORECASE,
    )

    # Маскирамо token= у URL-овима.
    masked = re.sub(
        r"([?&](?:token|key|api_key|apikey|access_token)=)([^&\s]+)",
        lambda m: m.group(1) + "***",
        masked,
        flags=re.IGNORECASE,
    )

    # Маскирамо Bearer токене.
    masked = re.sub(
        r"(Bearer\s+)(\S+)",
        lambda m: m.group(1) + "***",
        masked,
    )

    # Скраћујемо.
    if len(masked) > 120:
        masked = masked[:117] + "..."

    return masked


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    histories = data.get("histories", [])
    findings = data.get("sensitive_findings", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Users with history:[/bold]    {summary.get('total_users', 0)}"
    )
    console.print(
        f"[bold]History files:[/bold]        {summary.get('total_histories', 0)}"
    )
    console.print(
        f"[bold]Total commands:[/bold]       {summary.get('total_commands', 0)}"
    )

    if findings:
        console.print(
            f"[bold red]Sensitive commands:[/bold red]   "
            f"{summary.get('sensitive_count', 0)}"
        )

    console.print()

    # Осетљиви налази прво.
    if findings:
        console.print(
            f"[bold red]Sensitive findings "
            f"({len(findings)}):[/bold red]\n"
        )

        for finding in findings[:MAX_DISPLAY]:
            _print_finding(finding)

        if len(findings) > MAX_DISPLAY:
            console.print(
                f"  [dim]... and {len(findings) - MAX_DISPLAY} more[/dim]"
            )
        console.print()

    # Преглед history фајлова.
    if histories:
        console.print(
            f"[bold]History files ({len(histories)}):[/bold]\n"
        )

        for history in histories:
            user = history.get("user", "?")
            name = history.get("name", "?")
            count = history.get("command_count", 0)

            console.print(
                f"  [bold]{user:15s}[/bold]  "
                f"{name:25s}  "
                f"[dim]{count} commands[/dim]"
            )

        console.print()


def _print_finding(finding: dict) -> None:
    """Приказује један осетљив налаз."""
    user = finding.get("user", "?")
    reason = finding.get("reason", "")
    severity = finding.get("severity", "yellow")
    display = finding.get("display", "")
    file_path = finding.get("file", "")

    console.print(
        f"  [{severity}]●[/{severity}] "
        f"[bold]{user}[/bold]  "
        f"[dim]({reason})[/dim]"
    )
    console.print(f"    [dim]{file_path}[/dim]")
    console.print(f"    [white]{display}[/white]")
    console.print()