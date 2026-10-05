# Модул за претрагу тајни у конфигурационим фајловима.
# Многи фајлови као .env, .aws/credentials, .netrc садрже
# праве креденцијале за продукционе сервисе. Ово је злато
# за нападаче.
#
# ВАЖНО: Модул НЕ претражује цео систем. Чита само познате
# локације где се тајне обично налазе. Вредности се маскирају
# у приказу, али се чувају у JSON за анализу.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Познати конфиг фајлови који могу садржати тајне.
# Свака ставка: (релативна_путања_од_home_или_апсолутна, опис)
CONFIG_FILES = [
    # Environment фајлови
    (".env", "Environment variables"),
    (".env.local", "Environment variables (local)"),
    (".env.production", "Environment variables (production)"),
    (".env.prod", "Environment variables (production)"),
    (".env.dev", "Environment variables (development)"),
    (".env.development", "Environment variables (development)"),
    (".env.backup", "Environment variables (backup)"),

    # Cloud креденцијали
    (".aws/credentials", "AWS credentials"),
    (".aws/config", "AWS config"),
    (".config/gcloud/credentials.db", "Google Cloud credentials"),
    (".config/gcloud/application_default_credentials.json", "GCP ADC"),
    (".azure/azureProfile.json", "Azure profile"),
    (".azure/accessTokens.json", "Azure tokens"),

    # Git и package manager
    (".git-credentials", "Git credentials"),
    (".netrc", "FTP/HTTP credentials"),
    (".npmrc", "npm config"),
    (".pypirc", "Python package config"),
    (".gem/credentials", "Ruby gems credentials"),
    (".docker/config.json", "Docker config"),

    # Database
    (".pgpass", "PostgreSQL password file"),
    (".my.cnf", "MySQL config"),
    (".dbsqliterc", "SQLite config"),

    # Email и messaging
    (".msmtprc", "SMTP config"),
    (".muttrc", "Mutt email config"),
    (".msmtp/config", "SMTP config"),

    # SSH и security
    (".ssh/config", "SSH client config"),

    # Cloud CLI
    (".config/rclone/rclone.conf", "Rclone config"),
    (".config/heroku/config.json", "Heroku config"),
    (".config/gh/hosts.yml", "GitHub CLI config"),

    # Kubernetes
    (".kube/config", "Kubernetes config"),

    # App configs (често у home директоријуму пројеката)
    (".config/git/credentials", "Git credentials (XDG)"),

    # Апсолутне путање
    ("/etc/environment", "System environment"),
    ("/etc/mysql/debian.cnf", "MySQL Debian config"),
]

# Кључеви који указују на тајне.
# Ако име кључа садржи неки од ових, сматрамо да је вредност тајна.
SECRET_KEY_PATTERNS = [
    r"password",
    r"passwd",
    r"pass$",
    r"pwd",
    r"secret",
    r"token",
    r"api[_-]?key",
    r"apikey",
    r"access[_-]?key",
    r"private[_-]?key",
    r"auth",
    r"credential",
    r"aws_",
    r"azure_",
    r"gcp_",
    r"google_",
    r"stripe_",
    r"sendgrid_",
    r"mailgun_",
    r"twilio_",
    r"slack_",
    r"discord_",
    r"database_url",
    r"db_",
    r"redis_",
    r"mysql_",
    r"postgres_",
    r"jwt",
    r"bearer",
    r"session",
    r"cookie",
]

# Компајлирамо патерне.
SECRET_KEY_RE = re.compile(
    "|".join(SECRET_KEY_PATTERNS),
    re.IGNORECASE,
)

# Максимална величина фајла који читамо.
MAX_FILE_SIZE = 100 * 1024  # 100 KB

# Максималан број налаза по фајлу.
MAX_FINDINGS_PER_FILE = 50


def run() -> dict:
    """Претражује конфиг фајлове за тајнама.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Config secrets[/bold cyan]\n")

    # Проналазимо све конфиг фајлове.
    files = _find_config_files()

    # Читамо сваки фајл.
    results = []

    for file_info in files:
        result = _read_config_file(file_info)
        if result:
            results.append(result)

    # Правимо резиме.
    total_findings = sum(len(r.get("findings", [])) for r in results)

    summary = {
        "total_files": len(results),
        "total_findings": total_findings,
        "files_with_secrets": len(
            [r for r in results if r.get("findings")]
        ),
    }

    data = {
        "files": results,
        "summary": summary,
    }

    _print_data(data)

    return data


def _find_config_files() -> list[dict]:
    """Проналази конфиг фајлове на познатим локацијама.

    Претражује:
        1. Директно у home директоријуму (најчешће).
        2. До 3 нивоа дубине у home директоријуму (пројекти).
        3. Системске локације.
    """
    found = []
    seen_paths = set()

    # Директоријуми које прескачемо при дубљој претрази.
    # Ово су велики фолдери где нема смисла тражити .env.
    skip_dirs = {
        ".cache",
        ".local",
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        "vendor",
        "target",
        "build",
        "dist",
        "__pycache__",
        ".venv",
        "venv",
        ".npm",
        ".yarn",
        ".gradle",
        ".m2",
        "go",
        "snap",
        ".mozilla",
        ".thunderbird",
        ".steam",
        ".wine",
    }

    # Home директоријуми (root и сви корисници).
    home_dirs = []

    root_home = Path("/root")
    if root_home.exists():
        home_dirs.append(("root", root_home))

    home_base = Path("/home")
    if home_base.exists():
        try:
            for user_home in sorted(home_base.iterdir()):
                if user_home.is_dir():
                    home_dirs.append((user_home.name, user_home))
        except (PermissionError, Exception):
            pass

    for username, home in home_dirs:
        # Прво директно у home директоријуму (највећи приоритет).
        for rel_path, description in CONFIG_FILES:
            if rel_path.startswith("/"):
                continue

            file_path = home / rel_path

            if file_path.exists() and file_path.is_file():
                if str(file_path) not in seen_paths:
                    seen_paths.add(str(file_path))
                    found.append({
                        "path": file_path,
                        "user": username,
                        "description": description,
                    })

        # Онда дубља претрага (до 3 нивоа) за .env и сличне фајлове.
        deeper = _walk_for_configs(
            home, username, skip_dirs, seen_paths, max_depth=3
        )
        found.extend(deeper)

    # Апсолутне путање (системски конфиг).
    for abs_path, description in CONFIG_FILES:
        if not abs_path.startswith("/"):
            continue

        file_path = Path(abs_path)
        if file_path.exists() and file_path.is_file():
            if str(file_path) not in seen_paths:
                seen_paths.add(str(file_path))
                found.append({
                    "path": file_path,
                    "user": "system",
                    "description": description,
                })

    return found


def _walk_for_configs(
    base: Path,
    username: str,
    skip_dirs: set,
    seen_paths: set,
    max_depth: int = 3,
    current_depth: int = 0,
) -> list[dict]:
    """Претражује директоријум рекурзивно за конфиг фајловима.

    Иде до max_depth нивоа дубине и прескаче skip_dirs.
    """
    found = []

    if current_depth >= max_depth:
        return found

    try:
        entries = sorted(base.iterdir())
    except (PermissionError, Exception):
        return found

    for entry in entries:
        try:
            # Прескачемо скривене директоријуме на дубљим нивоима.
            if entry.is_dir():
                name = entry.name

                # Прескачемо директоријуме из листе.
                if name in skip_dirs:
                    continue

                # Прескачемо дубоке скривене директоријуме.
                if name.startswith(".") and current_depth > 0:
                    continue

                # Рекурзивно.
                sub_found = _walk_for_configs(
                    entry, username, skip_dirs, seen_paths,
                    max_depth, current_depth + 1,
                )
                found.extend(sub_found)

            elif entry.is_file():
                name = entry.name

                # Тражимо само .env фајлове и сличне.
                if not _is_env_like_file(name):
                    continue

                path_str = str(entry)

                if path_str in seen_paths:
                    continue
                seen_paths.add(path_str)

                # Препознајемо опис.
                description = _describe_env_file(name)

                found.append({
                    "path": entry,
                    "user": username,
                    "description": description,
                })

        except (PermissionError, OSError):
            continue

    return found


def _is_env_like_file(name: str) -> bool:
    """Проверава да ли је фајл .env или сличан."""
    # Прескачемо .env.example и .env.template — то су примери.
    if name.endswith((".example", ".template", ".sample", ".dist")):
        return False

    # .env фајлови.
    if name == ".env":
        return True

    if name.startswith(".env."):
        return True

    # Други конфиг фајлови који могу имати тајне.
    if name in (
        "settings.py", "config.py", "config.json", "config.yml",
        "config.yaml", "secrets.yml", "secrets.yaml", "secrets.json",
        "wp-config.php", "local.settings.json", "appsettings.json",
        "database.yml", "credentials.json", "service-account.json",
    ):
        return True

    # .envrc (direnv).
    if name == ".envrc":
        return True

    return False


def _describe_env_file(name: str) -> str:
    """Враћа опис за .env фајл."""
    if name == ".env":
        return "Environment variables"

    if name.startswith(".env."):
        suffix = name[5:]
        return f"Environment variables ({suffix})"

    descriptions = {
        "settings.py": "Django settings",
        "config.py": "Python config",
        "config.json": "JSON config",
        "config.yml": "YAML config",
        "config.yaml": "YAML config",
        "secrets.yml": "Secrets file",
        "secrets.yaml": "Secrets file",
        "secrets.json": "Secrets file",
        "wp-config.php": "WordPress config",
        "local.settings.json": "Azure Functions local config",
        "appsettings.json": ".NET config",
        "database.yml": "Rails database config",
        "credentials.json": "Credentials file",
        "service-account.json": "GCP service account",
        ".envrc": "Direnv config",
    }

    return descriptions.get(name, "Config file")


def _read_config_file(file_info: dict) -> dict | None:
    """Чита један конфиг фајл."""
    path = file_info["path"]
    username = file_info["user"]
    description = file_info["description"]

    # Проверавамо величину.
    try:
        st = path.stat()
        if st.st_size > MAX_FILE_SIZE:
            return None
        if st.st_size == 0:
            return None
    except Exception:
        return None

    # Проверавамо приступ.
    if not os.access(path, os.R_OK):
        return {
            "path": str(path),
            "user": username,
            "description": description,
            "readable": False,
            "findings": [],
        }

    # Читамо садржај.
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return None

    # Проналазимо тајне.
    findings = _extract_secrets(content)

    return {
        "path": str(path),
        "user": username,
        "description": description,
        "readable": True,
        "size_bytes": len(content),
        "line_count": content.count("\n") + 1,
        "findings": findings,
    }


def _extract_secrets(content: str) -> list[dict]:
    """Извлачи тајне из садржаја фајла.

    Парсира различите формате:
        KEY=value
        key: value
        key = value
        "key": "value"
    """
    findings = []
    seen_keys = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_stripped = line.strip()

        if not line_stripped:
            continue

        # Прескачемо коментаре.
        if line_stripped.startswith("#") or line_stripped.startswith(";"):
            continue

        # Парсирамо key-value.
        parsed = _parse_config_line(line_stripped)

        if not parsed:
            continue

        key, value = parsed

        # Проверавамо да ли кључ указује на тајну.
        if not SECRET_KEY_RE.search(key):
            continue

        # Прескачемо празне вредности.
        if not value or value in ("", "''", '""', "null", "None"):
            continue

        # Избегавамо дупликате.
        key_lower = key.lower()
        if key_lower in seen_keys:
            continue
        seen_keys.add(key_lower)

        # Маскирамо вредност за приказ.
        masked = _mask_value(value)

        findings.append({
            "key": key,
            "value": value,
            "display": masked,
            "line_number": line_number,
            "size": len(value),
        })

        if len(findings) >= MAX_FINDINGS_PER_FILE:
            break

    return findings


def _parse_config_line(line: str) -> tuple[str, str] | None:
    """Парсира линију у key-value пар.

    Подржава:
        KEY=value
        key: value
        key = value
        "key": "value"
        export KEY=value
    """
    # Уклањамо "export " префикс.
    if line.startswith("export "):
        line = line[7:].strip()

    # Формат JSON или ENV.
    json_match = re.match(
        r'^["\']?([a-zA-Z_][a-zA-Z0-9_\-.]*)["\']?\s*[:=]\s*["\']?(.+?)["\']?,?$',
        line,
    )

    if json_match:
        key = json_match.group(1).strip()
        value = json_match.group(2).strip()

        # Уклањамо завршне зарезе и наводнике.
        value = value.rstrip(",").strip()
        value = value.strip("'\"")

        return key, value

    return None


def _mask_value(value: str) -> str:
    """Маскира вредност тајне за приказ."""
    if not value:
        return "(empty)"

    # Ако је кратка, маскирамо целину.
    if len(value) <= 8:
        return "*" * len(value)

    # Иначе приказујемо првих 4 знака и остало маскирано.
    return value[:4] + "*" * min(len(value) - 4, 20)


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    files = data.get("files", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Config files found:[/bold]    "
        f"{summary.get('total_files', 0)}"
    )
    console.print(
        f"[bold]Files with secrets:[/bold]    "
        f"[bold red]{summary.get('files_with_secrets', 0)}[/bold red]"
    )
    console.print(
        f"[bold]Total secrets found:[/bold]   "
        f"[bold red]{summary.get('total_findings', 0)}[/bold red]"
    )
    console.print()

    if not files:
        console.print(
            "  [dim]No known config files found.[/dim]\n"
        )
        return

    # Фајлови са тајнама прво.
    files_with_secrets = [f for f in files if f.get("findings")]

    if files_with_secrets:
        console.print(
            f"[bold red]Files with secrets "
            f"({len(files_with_secrets)}):[/bold red]\n"
        )

        # Приказујемо првих 15 фајлова.
        limit = 15
        for file_info in files_with_secrets[:limit]:
            _print_file_with_secrets(file_info)

        if len(files_with_secrets) > limit:
            console.print(
                f"  [dim]... and "
                f"{len(files_with_secrets) - limit} more files[/dim]\n"
            )

    # Фајлови без тајни.
    files_no_secrets = [f for f in files if not f.get("findings")]

    if files_no_secrets:
        console.print(
            f"[bold]Files without secrets "
            f"({len(files_no_secrets)}):[/bold]\n"
        )

        # Приказујемо само првих 10.
        limit = 10
        for file_info in files_no_secrets[:limit]:
            path = file_info.get("path", "?")
            description = file_info.get("description", "")
            readable = file_info.get("readable", False)

            if not readable:
                console.print(
                    f"  [dim]{path}[/dim]  "
                    f"[yellow](not readable)[/yellow]"
                )
            else:
                console.print(
                    f"  [dim]{path}[/dim]  "
                    f"[dim]({description})[/dim]"
                )

        if len(files_no_secrets) > limit:
            console.print(
                f"  [dim]... and "
                f"{len(files_no_secrets) - limit} more[/dim]"
            )

        console.print()


def _print_file_with_secrets(file_info: dict) -> None:
    """Приказује фајл са тајнама."""
    path = file_info.get("path", "?")
    user = file_info.get("user", "?")
    description = file_info.get("description", "")
    findings = file_info.get("findings", [])

    console.print(
        f"  [bold]{path}[/bold]"
    )
    console.print(
        f"    [dim]User: {user}  |  {description}  |  "
        f"{len(findings)} secret(s)[/dim]"
    )
    console.print()

    for finding in findings:
        key = finding.get("key", "?")
        display = finding.get("display", "?")
        line_number = finding.get("line_number", "?")

        console.print(
            f"    [yellow]{key}[/yellow] = "
            f"[red]{display}[/red]  "
            f"[dim](line {line_number})[/dim]"
        )

    console.print()