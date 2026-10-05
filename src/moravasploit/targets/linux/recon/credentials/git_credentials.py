# Модул за проналажење git креденцијала и конфигурација.
# Git конфигурација може садржати credential helper са токеном,
# remote URL-ове са уграђеним credentials, и корисничке
# податке који откривају идентитет.
#
# ВАЖНО: Модул маскира вредности у приказу, али их чува у JSON.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import re
from configparser import ConfigParser
from pathlib import Path

from rich.console import Console

console = Console()

# Релативне путање до git конфигурације (од home).
GIT_CONFIGS = [
    ".gitconfig",
    ".config/git/config",
]

# Путања до git-credentials.
GIT_CREDENTIALS = ".git-credentials"

# CLI конфигурације за GitHub и GitLab.
CLI_CONFIGS = [
    (".config/gh/hosts.yml", "GitHub CLI"),
    (".config/glab-cli/config.yml", "GitLab CLI"),
    (".config/hub", "Hub CLI (legacy)"),
]

# Директоријуми где тражимо .git/config фајлове.
GIT_PROJECT_DIRS = [
    "Projects",
    "projects",
    "razvoj",
    "www",
    "my-projects",
    "Documents",
    "Public",
    "Templates",
    "Downloads",
]

# Директоријуми које прескачемо.
SKIP_DIRS = {
    ".cache",
    ".local",
    "node_modules",
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
}

# Кључеви у gitconfig који могу садржати осетљиве податке.
SENSITIVE_CONFIG_KEYS = {
    "helper",
    "token",
    "password",
    "username",
    "credential",
    "oauth",
    "url",
    "insteadof",
}

# Максимална дубина претраге .git фолдера.
MAX_DEPTH = 4


def run() -> dict:
    """Проналази git креденцијале и конфигурације.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Git credentials[/bold cyan]\n")

    # Проналазимо home директоријуме.
    homes = _get_home_dirs()

    # Читамо глобалну git конфигурацију.
    configs = []

    for username, home in homes:
        user_configs = _read_user_git_configs(home, username)
        configs.extend(user_configs)

    # Читамо .git-credentials.
    credentials = []

    for username, home in homes:
        creds = _read_git_credentials(home, username)
        credentials.extend(creds)

    # Читамо CLI конфигурације (gh, glab).
    cli_configs = []

    for username, home in homes:
        user_cli = _read_cli_configs(home, username)
        cli_configs.extend(user_cli)

    # Читамо .git/config у пројектима (remote URL-ови).
    project_remotes = []

    for username, home in homes:
        remotes = _find_project_remotes(home, username)
        project_remotes.extend(remotes)

    # Правимо резиме.
    summary = {
        "configs": len(configs),
        "credentials": len(credentials),
        "cli_configs": len(cli_configs),
        "project_remotes": len(project_remotes),
        "total_findings": (
            len(configs) + len(credentials) + len(cli_configs) + len(project_remotes)
        ),
    }

    data = {
        "configs": configs,
        "credentials": credentials,
        "cli_configs": cli_configs,
        "project_remotes": project_remotes,
        "summary": summary,
    }

    _print_data(data)

    return data


def _get_home_dirs() -> list[tuple[str, Path]]:
    """Враћа листу (корисник, home) туплова."""
    homes = []

    root_home = Path("/root")
    if root_home.exists():
        homes.append(("root", root_home))

    home_base = Path("/home")
    if home_base.exists():
        try:
            for user_home in sorted(home_base.iterdir()):
                if user_home.is_dir():
                    homes.append((user_home.name, user_home))
        except (PermissionError, Exception):
            pass

    return homes


def _read_user_git_configs(home: Path, username: str) -> list[dict]:
    """Чита глобалну git конфигурацију за корисника."""
    configs = []

    for rel_path in GIT_CONFIGS:
        config_path = home / rel_path

        if not config_path.exists() or not config_path.is_file():
            continue

        config = _parse_git_config(config_path, username)
        if config:
            configs.append(config)

    return configs


def _parse_git_config(path: Path, username: str) -> dict | None:
    """Парсира git конфигурациони фајл."""
    parser = ConfigParser(strict=False)

    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return None

    result = {
        "username": username,
        "path": str(path),
        "user": {},
        "credential": {},
        "aliases": {},
        "url_rewrites": [],
        "other_sensitive": [],
    }

    # User секција — име и мејл.
    if parser.has_section("user"):
        for key in ("name", "email", "signingkey"):
            if parser.has_option("user", key):
                result["user"][key] = parser.get("user", key)

    # Credential секција — helper.
    if parser.has_section("credential"):
        for key, value in parser.items("credential"):
            # Маскирамо ако је осетљиво.
            if key.lower() in SENSITIVE_CONFIG_KEYS:
                result["credential"][key] = _mask_value(value, 6, 0)
            else:
                result["credential"][key] = value

    # Aliases — могу бити злоупотребљени.
    if parser.has_section("alias"):
        for key, value in parser.items("alias"):
            result["aliases"][key] = value

    # URL rewrites (insteadOf) — могу сакрити праве URL-ове.
    if parser.has_section("url"):
        for key, value in parser.items("url"):
            # На пример: "git@github.com:" = "https://token@github.com/"
            if "insteadof" in key.lower():
                result["url_rewrites"].append({
                    "url": key.replace("insteadof", "").strip(),
                    "instead_of": value,
                    "masked_url": _mask_url(key),
                })

    # Тражимо осетљиве кључеве у осталим секцијама.
    for section in parser.sections():
        if section in ("user", "credential", "alias", "url"):
            continue

        for key, value in parser.items(section):
            key_lower = key.lower()
            if any(
                sensitive in key_lower
                for sensitive in ("token", "password", "secret", "key")
            ):
                result["other_sensitive"].append({
                    "section": section,
                    "key": key,
                    "value": _mask_value(value, 6, 0),
                })

    return result


def _read_git_credentials(home: Path, username: str) -> list[dict]:
    """Чита .git-credentials фајл."""
    result = []

    creds_path = home / GIT_CREDENTIALS

    if not creds_path.exists() or not creds_path.is_file():
        return result

    try:
        content = creds_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return result

    # Формат: https://username:password@host
    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        # Парсирамо URL са credentials.
        match = re.match(
            r"^(https?|ftp)://([^:]+):([^@]+)@(.+)$",
            line,
        )

        if match:
            protocol = match.group(1)
            cred_user = match.group(2)
            password = match.group(3)
            host = match.group(4)

            result.append({
                "username": username,
                "path": str(creds_path),
                "line_number": line_number,
                "protocol": protocol,
                "cred_username": cred_user,
                "password": _mask_value(password, 4, 0),
                "host": host,
                "has_password": bool(password),
            })
        else:
            # Непрепознат формат — маскирамо целу линију.
            result.append({
                "username": username,
                "path": str(creds_path),
                "line_number": line_number,
                "raw": _mask_url(line),
                "unparsed": True,
            })

    return result


def _read_cli_configs(home: Path, username: str) -> list[dict]:
    """Чита gh, glab и hub CLI конфигурације."""
    result = []

    for rel_path, description in CLI_CONFIGS:
        config_path = home / rel_path

        if not config_path.exists() or not config_path.is_file():
            continue

        try:
            content = config_path.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, Exception):
            continue

        # Тражимо токене у садржају.
        tokens = _extract_tokens(content)

        result.append({
            "username": username,
            "path": str(config_path),
            "cli": description,
            "size_bytes": len(content),
            "tokens_found": tokens,
            "has_oauth_token": "oauth_token" in content.lower(),
        })

    return result


def _extract_tokens(content: str) -> list[dict]:
    """Извлачи токене из конфигурације."""
    tokens = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_stripped = line.strip()

        # Тражимо кључеве са token/secret/password.
        match = re.match(
            r"^([a-zA-Z_][a-zA-Z0-9_\-]*)\s*:\s*(.+)$",
            line_stripped,
        )

        if not match:
            continue

        key = match.group(1)
        value = match.group(2).strip().strip("'\"")

        key_lower = key.lower()

        if any(
            marker in key_lower
            for marker in ("token", "secret", "password", "key")
        ):
            tokens.append({
                "key": key,
                "value": value,
                "display": _mask_value(value, 6, 0),
                "line_number": line_number,
            })

    return tokens


def _find_project_remotes(home: Path, username: str) -> list[dict]:
    """Проналази .git/config фајлове у пројектима."""
    remotes = []
    seen_paths = set()

    for project_dir_name in GIT_PROJECT_DIRS:
        project_dir = home / project_dir_name

        if not project_dir.exists() or not project_dir.is_dir():
            continue

        found = _walk_for_git_configs(
            project_dir, username, seen_paths, max_depth=MAX_DEPTH
        )
        remotes.extend(found)

    return remotes


def _walk_for_git_configs(
    base: Path,
    username: str,
    seen_paths: set,
    max_depth: int = 4,
    current_depth: int = 0,
) -> list[dict]:
    """Рекурзивно тражи .git/config фајлове."""
    found = []

    if current_depth >= max_depth:
        return found

    try:
        entries = sorted(base.iterdir())
    except (PermissionError, Exception):
        return found

    for entry in entries:
        try:
            if entry.is_dir():
                name = entry.name

                if name in SKIP_DIRS:
                    continue

                # Ако је .git фолдер, читамо config.
                if name == ".git":
                    config_path = entry / "config"

                    if config_path.exists() and config_path.is_file():
                        path_str = str(config_path)

                        if path_str not in seen_paths:
                            seen_paths.add(path_str)
                            remotes = _parse_git_config_remotes(
                                config_path, username
                            )
                            found.extend(remotes)

                    continue

                # Рекурзивно у подфолдере (али не дубоко у .git).
                sub_found = _walk_for_git_configs(
                    entry, username, seen_paths,
                    max_depth, current_depth + 1,
                )
                found.extend(sub_found)

        except (PermissionError, OSError):
            continue

    return found


def _parse_git_config_remotes(path: Path, username: str) -> list[dict]:
    """Парсира .git/config за remote URL-ове."""
    parser = ConfigParser(strict=False)

    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return []

    remotes = []

    for section in parser.sections():
        # Секција типа 'remote "origin"'.
        if not section.startswith('remote '):
            continue

        # Извлачимо име remote-а.
        match = re.match(r'remote\s+"([^"]+)"', section)
        if not match:
            continue

        remote_name = match.group(1)

        if not parser.has_option(section, "url"):
            continue

        url = parser.get(section, "url")

        # Проверавамо да ли URL има уграђене credentials.
        has_credentials = False
        masked_url = url

        # Формат: https://user:pass@host/path
        url_match = re.match(
            r"^(https?://)([^@]+)@(.+)$",
            url,
        )

        if url_match:
            has_credentials = True
            masked_url = url_match.group(1) + "***@" + url_match.group(3)

        remotes.append({
            "username": username,
            "config_path": str(path),
            "remote_name": remote_name,
            "url": url,
            "display": masked_url,
            "has_credentials": has_credentials,
        })

    return remotes


def _mask_value(value: str, show_first: int = 4, show_last: int = 0) -> str:
    """Маскира вредност за приказ."""
    if not value:
        return "(empty)"

    if len(value) <= show_first + show_last:
        return "*" * len(value)

    if show_last > 0:
        return (
            value[:show_first]
            + "*" * min(len(value) - show_first - show_last, 20)
            + value[-show_last:]
        )

    return value[:show_first] + "*" * min(len(value) - show_first, 20)


def _mask_url(url: str) -> str:
    """Маскира credentials у URL-у."""
    # Замењујемо део између :// и @.
    match = re.match(r"^([a-z]+://)([^@]+)@(.+)$", url)

    if match:
        return match.group(1) + "***@" + match.group(3)

    return url


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    configs = data.get("configs", [])
    credentials = data.get("credentials", [])
    cli_configs = data.get("cli_configs", [])
    project_remotes = data.get("project_remotes", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Git configs:[/bold]         {summary.get('configs', 0)}"
    )
    console.print(
        f"[bold]Stored credentials:[/bold]  "
        f"[bold red]{summary.get('credentials', 0)}[/bold red]"
    )
    console.print(
        f"[bold]CLI configs:[/bold]         {summary.get('cli_configs', 0)}"
    )
    console.print(
        f"[bold]Project remotes:[/bold]     "
        f"{summary.get('project_remotes', 0)}"
    )

    if summary.get("total_findings", 0) == 0:
        console.print()
        console.print("  [dim]No git credentials found.[/dim]\n")
        return

    console.print()

    # Git конфигурације.
    if configs:
        console.print("[bold cyan]Git configuration[/bold cyan]\n")
        for config in configs:
            _print_git_config(config)

    # Credentials.
    if credentials:
        console.print(
            f"[bold red]Stored credentials "
            f"({len(credentials)}):[/bold red]\n"
        )
        for cred in credentials:
            _print_credential(cred)

    # CLI конфигурације.
    if cli_configs:
        console.print("[bold cyan]CLI configurations[/bold cyan]\n")
        for cli in cli_configs:
            _print_cli_config(cli)

    # Project remotes.
    if project_remotes:
        # Филтрирамо само оне са credentials.
        with_creds = [r for r in project_remotes if r.get("has_credentials")]

        if with_creds:
            console.print(
                f"[bold red]Project remotes with credentials "
                f"({len(with_creds)}):[/bold red]\n"
            )
            for remote in with_creds:
                _print_remote(remote)
        else:
            console.print(
                f"[bold]Project remotes "
                f"({len(project_remotes)}) — no embedded credentials[/bold]\n"
            )


def _print_git_config(config: dict) -> None:
    """Приказује git конфигурацију."""
    path = config.get("path", "?")
    user = config.get("user", {})
    credential = config.get("credential", {})
    aliases = config.get("aliases", {})
    url_rewrites = config.get("url_rewrites", [])
    other = config.get("other_sensitive", [])

    console.print(f"  [dim]{path}[/dim]")

    if user:
        console.print("    [bold]User:[/bold]")
        for key, value in user.items():
            console.print(f"      {key}: {value}")

    if credential:
        console.print("    [bold]Credential:[/bold]")
        for key, value in credential.items():
            console.print(f"      {key}: [yellow]{value}[/yellow]")

    if url_rewrites:
        console.print("    [bold]URL rewrites:[/bold]")
        for rewrite in url_rewrites:
            console.print(
                f"      [yellow]{rewrite['instead_of']}[/yellow] → "
                f"{rewrite['masked_url']}"
            )

    if aliases:
        console.print(f"    [bold]Aliases:[/bold] {len(aliases)}")
        for name, cmd in list(aliases.items())[:5]:
            console.print(f"      {name}: [dim]{cmd}[/dim]")

    if other:
        console.print("    [bold red]Other sensitive keys:[/bold red]")
        for item in other:
            console.print(
                f"      [{item['section']}] {item['key']} = "
                f"[red]{item['value']}[/red]"
            )

    console.print()


def _print_credential(cred: dict) -> None:
    """Приказује један credential унос."""
    username = cred.get("username", "?")
    host = cred.get("host", "?")
    cred_user = cred.get("cred_username", "?")
    password = cred.get("password", "?")

    console.print(
        f"  [bold]{host}[/bold]  [dim](user: {username})[/dim]"
    )
    console.print(f"    Credential user: {cred_user}")
    console.print(f"    Password:        [red]{password}[/red]")
    console.print()


def _print_cli_config(cli: dict) -> None:
    """Приказује CLI конфигурацију."""
    path = cli.get("path", "?")
    name = cli.get("cli", "?")
    tokens = cli.get("tokens_found", [])

    console.print(f"  [bold]{name}[/bold]  [dim]{path}[/dim]")

    if tokens:
        for token in tokens:
            key = token.get("key", "?")
            display = token.get("display", "?")
            console.print(
                f"    [yellow]{key}[/yellow] = [red]{display}[/red]"
            )
    else:
        console.print("    [dim]No tokens found[/dim]")

    console.print()


def _print_remote(remote: dict) -> None:
    """Приказује git remote са credentials."""
    config_path = remote.get("config_path", "?")
    remote_name = remote.get("remote_name", "?")
    display = remote.get("display", "?")

    console.print(f"  [bold]{remote_name}[/bold]")
    console.print(f"    URL: [red]{display}[/red]")
    console.print(f"    [dim]{config_path}[/dim]")
    console.print()