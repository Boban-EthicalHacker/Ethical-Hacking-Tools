# Модул за проналажење cloud креденцијала.
# AWS, GCP и Azure креденцијали су највредније што нападач
# може да нађе — дају приступ целом cloud окружењу.
#
# ВАЖНО: Модул маскира вредности у приказу, али их чува у JSON.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import json
import os
import re
from configparser import ConfigParser
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до cloud креденцијала.
AWS_CREDS = Path(".aws/credentials")
AWS_CONFIG = Path(".aws/config")
GCP_CONFIG_DIR = Path(".config/gcloud")
AZURE_DIR = Path(".azure")
KUBE_CONFIG = Path(".kube/config")

# Service account фајлови (обично у пројектима).
SERVICE_ACCOUNT_PATTERNS = [
    "service-account*.json",
    "service_account*.json",
    "gcp-credentials.json",
    "google-credentials.json",
    "*gcp*key*.json",
]

# Environment варијабле за cloud.
CLOUD_ENV_VARS = {
    "aws": [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
        "AWS_PROFILE",
    ],
    "gcp": [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GCLOUD_PROJECT",
        "CLOUDSDK_CONFIG",
    ],
    "azure": [
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID",
    ],
}

# Директоријуми за претрагу service account фајлова.
SERVICE_ACCOUNT_SEARCH_DIRS = [
    ".config",
    "Projects",
    "projects",
    "razvoj",
    "www",
    "my-projects",
    "Documents",
]

# Директоријуми које прескачемо.
SKIP_DIRS = {
    ".cache",
    ".local",
    "node_modules",
    ".git",
    "vendor",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".venv",
    "venv",
}


def run() -> dict:
    """Проналази cloud креденцијале.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Cloud credentials[/bold cyan]\n")

    # Проналазимо home директоријуме.
    homes = _get_home_dirs()

    # Читамо AWS.
    aws = _read_aws(homes)

    # Читамо GCP.
    gcp = _read_gcp(homes)

    # Читамо Azure.
    azure = _read_azure(homes)

    # Читамо Kubernetes.
    kube = _read_kubernetes(homes)

    # Читамо environment варијабле.
    env_vars = _read_env_vars()

    # Правимо резиме.
    summary = {
        "aws_profiles": len(aws.get("profiles", [])),
        "gcp_accounts": len(gcp.get("accounts", [])),
        "gcp_service_accounts": len(gcp.get("service_accounts", [])),
        "azure_profiles": len(azure.get("profiles", [])),
        "kube_contexts": len(kube.get("contexts", [])),
        "env_vars_found": sum(
            len(v) for v in env_vars.values()
        ),
        "total_findings": (
            len(aws.get("profiles", []))
            + len(gcp.get("accounts", []))
            + len(gcp.get("service_accounts", []))
            + len(azure.get("profiles", []))
            + len(kube.get("contexts", []))
            + sum(len(v) for v in env_vars.values())
        ),
    }

    data = {
        "aws": aws,
        "gcp": gcp,
        "azure": azure,
        "kubernetes": kube,
        "environment": env_vars,
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


def _read_aws(homes: list[tuple[str, Path]]) -> dict:
    """Чита AWS креденцијале."""
    result = {
        "credentials_file": None,
        "config_file": None,
        "profiles": [],
    }

    for username, home in homes:
        # .aws/credentials
        creds_path = home / AWS_CREDS

        if creds_path.exists() and creds_path.is_file():
            if result["credentials_file"] is None:
                result["credentials_file"] = str(creds_path)

            profiles = _parse_aws_credentials(creds_path, username)
            result["profiles"].extend(profiles)

        # .aws/config
        config_path = home / AWS_CONFIG

        if config_path.exists() and config_path.is_file():
            if result["config_file"] is None:
                result["config_file"] = str(config_path)

            profiles = _parse_aws_config(config_path, username)
            result["profiles"].extend(profiles)

    return result


def _parse_aws_credentials(path: Path, username: str) -> list[dict]:
    """Парсира ~/.aws/credentials."""
    result = []

    parser = ConfigParser(strict=False)

    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return result

    for section in parser.sections():
        profile = {
            "username": username,
            "profile": section,
            "source": str(path),
            "access_key": None,
            "secret_key": None,
            "session_token": None,
            "has_keys": False,
        }

        if parser.has_option(section, "aws_access_key_id"):
            access_key = parser.get(section, "aws_access_key_id")
            profile["access_key"] = _mask_value(access_key, 4, 4)
            profile["has_keys"] = True

        if parser.has_option(section, "aws_secret_access_key"):
            secret = parser.get(section, "aws_secret_access_key")
            profile["secret_key"] = _mask_value(secret, 4, 4)

        if parser.has_option(section, "aws_session_token"):
            profile["session_token"] = "(present)"

        result.append(profile)

    return result


def _parse_aws_config(path: Path, username: str) -> list[dict]:
    """Парсира ~/.aws/config."""
    result = []

    parser = ConfigParser(strict=False)

    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return result

    for section in parser.sections():
        # У config фајлу, профили су типа "profile name" (осим default).
        name = section
        if name.startswith("profile "):
            name = name[8:]

        profile = {
            "username": username,
            "profile": name,
            "source": str(path),
            "region": None,
            "output": None,
        }

        if parser.has_option(section, "region"):
            profile["region"] = parser.get(section, "region")

        if parser.has_option(section, "output"):
            profile["output"] = parser.get(section, "output")

        result.append(profile)

    return result


def _read_gcp(homes: list[tuple[str, Path]]) -> dict:
    """Чита GCP креденцијале."""
    result = {
        "config_dir": None,
        "accounts": [],
        "service_accounts": [],
    }

    for username, home in homes:
        gcp_dir = home / GCP_CONFIG_DIR

        if gcp_dir.exists() and gcp_dir.is_dir():
            if result["config_dir"] is None:
                result["config_dir"] = str(gcp_dir)

            # application_default_credentials.json
            adc = gcp_dir / "application_default_credentials.json"
            if adc.exists() and adc.is_file():
                account = _parse_gcp_adc(adc, username)
                if account:
                    result["accounts"].append(account)

            # configurations/config_default
            config_default = gcp_dir / "configurations" / "config_default"
            if config_default.exists() and config_default.is_file():
                config_data = _parse_gcp_config(config_default, username)
                if config_data:
                    result["accounts"].extend(config_data)

        # Тражимо service account фајлове.
        sa_files = _find_service_accounts(home, username)
        result["service_accounts"].extend(sa_files)

    return result


def _parse_gcp_adc(path: Path, username: str) -> dict | None:
    """Парсира GCP application default credentials."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except Exception:
        return None

    account = {
        "username": username,
        "source": str(path),
        "type": data.get("type", "unknown"),
        "client_id": None,
        "project_id": data.get("project_id"),
        "refresh_token": None,
    }

    if data.get("client_id"):
        account["client_id"] = _mask_value(data["client_id"], 8, 4)

    if data.get("refresh_token"):
        account["refresh_token"] = "(present)"

    return account


def _parse_gcp_config(path: Path, username: str) -> list[dict]:
    """Парсира GCP config_default."""
    result = []

    parser = ConfigParser(strict=False)

    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return result

    for section in parser.sections():
        entry = {
            "username": username,
            "source": str(path),
            "section": section,
            "account": None,
            "project": None,
        }

        if parser.has_option(section, "account"):
            entry["account"] = parser.get(section, "account")

        if parser.has_option(section, "project"):
            entry["project"] = parser.get(section, "project")

        result.append(entry)

    return result


def _find_service_accounts(home: Path, username: str) -> list[dict]:
    """Проналази GCP service account JSON фајлове."""
    found = []
    seen = set()

    for search_dir_name in SERVICE_ACCOUNT_SEARCH_DIRS:
        search_dir = home / search_dir_name

        if not search_dir.exists() or not search_dir.is_dir():
            continue

        # Рекурзивна претрага (до 4 нивоа).
        files = _walk_for_service_accounts(
            search_dir, username, seen, max_depth=4
        )
        found.extend(files)

    return found


def _walk_for_service_accounts(
    base: Path,
    username: str,
    seen: set,
    max_depth: int = 4,
    current_depth: int = 0,
) -> list[dict]:
    """Рекурзивно тражи service account фајлове."""
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
                if name.startswith(".") and current_depth > 0:
                    continue

                sub_found = _walk_for_service_accounts(
                    entry, username, seen, max_depth, current_depth + 1
                )
                found.extend(sub_found)

            elif entry.is_file():
                name = entry.name.lower()

                # Проверавамо да ли име одговара service account шаблону.
                if not any(
                    _match_pattern(name, pattern)
                    for pattern in SERVICE_ACCOUNT_PATTERNS
                ):
                    continue

                path_str = str(entry)
                if path_str in seen:
                    continue
                seen.add(path_str)

                sa = _parse_service_account(entry, username)
                if sa:
                    found.append(sa)

        except (PermissionError, OSError):
            continue

    return found


def _match_pattern(name: str, pattern: str) -> bool:
    """Једноставно подударање имена са шаблоном (без fnmatch)."""
    # Претварамо * у .* regex.
    regex = re.escape(pattern).replace(r"\*", ".*")
    return bool(re.match(f"^{regex}$", name))


def _parse_service_account(path: Path, username: str) -> dict | None:
    """Парсира GCP service account JSON фајл."""
    try:
        # Проверавамо величину.
        if path.stat().st_size > 100 * 1024:
            return None

        content = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except Exception:
        return None

    # Service account фајл мора да има "type": "service_account".
    if data.get("type") != "service_account":
        return None

    return {
        "username": username,
        "path": str(path),
        "type": "service_account",
        "project_id": data.get("project_id"),
        "client_email": data.get("client_email"),
        "client_id": data.get("client_id"),
        "private_key_id": _mask_value(
            data.get("private_key_id", ""), 8, 4
        ) if data.get("private_key_id") else None,
        "has_private_key": bool(data.get("private_key")),
    }


def _read_azure(homes: list[tuple[str, Path]]) -> dict:
    """Чита Azure креденцијале."""
    result = {
        "config_dir": None,
        "profiles": [],
    }

    for username, home in homes:
        azure_dir = home / AZURE_DIR

        if not azure_dir.exists() or not azure_dir.is_dir():
            continue

        if result["config_dir"] is None:
            result["config_dir"] = str(azure_dir)

        # azureProfile.json
        profile_file = azure_dir / "azureProfile.json"

        if profile_file.exists() and profile_file.is_file():
            profiles = _parse_azure_profile(profile_file, username)
            result["profiles"].extend(profiles)

        # accessTokens.json
        tokens_file = azure_dir / "accessTokens.json"

        if tokens_file.exists() and tokens_file.is_file():
            token_entry = {
                "username": username,
                "path": str(tokens_file),
                "type": "access_tokens",
                "has_tokens": True,
            }
            result["profiles"].append(token_entry)

        # msal_token_cache.json (новији формат)
        msal_file = azure_dir / "msal_token_cache.json"

        if msal_file.exists() and msal_file.is_file():
            result["profiles"].append({
                "username": username,
                "path": str(msal_file),
                "type": "msal_token_cache",
                "has_tokens": True,
            })

    return result


def _parse_azure_profile(path: Path, username: str) -> list[dict]:
    """Парсира Azure профил."""
    result = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except Exception:
        return result

    # Azure формат има BOM на почетку понекад — уклањамо га.
    if not isinstance(data, dict):
        return result

    subscriptions = data.get("subscriptions", [])

    for sub in subscriptions:
        if not isinstance(sub, dict):
            continue

        result.append({
            "username": username,
            "path": str(path),
            "type": "subscription",
            "subscription_id": _mask_value(
                sub.get("id", ""), 8, 4
            ) if sub.get("id") else None,
            "name": sub.get("name"),
            "tenant_id": _mask_value(
                sub.get("tenantId", ""), 8, 4
            ) if sub.get("tenantId") else None,
            "user": sub.get("user", {}).get("name") if isinstance(
                sub.get("user"), dict
            ) else None,
        })

    return result


def _read_kubernetes(homes: list[tuple[str, Path]]) -> dict:
    """Чита Kubernetes конфигурацију."""
    result = {
        "config_file": None,
        "contexts": [],
        "clusters": [],
    }

    for username, home in homes:
        kube_path = home / KUBE_CONFIG

        if not kube_path.exists() or not kube_path.is_file():
            continue

        if result["config_file"] is None:
            result["config_file"] = str(kube_path)

        try:
            content = kube_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except Exception:
            # YAML формат — користимо прост парсер.
            contexts = _parse_kube_yaml(content if 'content' in dir() else "")
            result["contexts"].extend(contexts)
            continue

        # JSON формат.
        for ctx in data.get("contexts", []):
            result["contexts"].append({
                "username": username,
                "name": ctx.get("name"),
                "cluster": ctx.get("context", {}).get("cluster"),
                "user": ctx.get("context", {}).get("user"),
            })

        for cluster in data.get("clusters", []):
            result["clusters"].append({
                "username": username,
                "name": cluster.get("name"),
                "server": cluster.get("cluster", {}).get("server"),
            })

    return result


def _parse_kube_yaml(content: str) -> list[dict]:
    """Прост парсер kubeconfig YAML-а.

    Тражимо само "current-context" и имена контекста.
    """
    contexts = []

    if not content:
        return contexts

    # Проста regex претрага за "name:" линије у contexts делу.
    # YAML парсирање није доступно без додатне библиотеке.
    in_contexts = False

    for line in content.splitlines():
        stripped = line.strip()

        if stripped == "contexts:":
            in_contexts = True
            continue

        if in_contexts:
            # Излазимо кад наиђемо на нови топ-левел кључ.
            if stripped and not stripped.startswith("-") and not stripped.startswith(" ") and ":" in stripped:
                if not line.startswith(" "):
                    in_contexts = False
                    continue

            if stripped.startswith("- name:"):
                name = stripped[7:].strip().strip("'\"")
                contexts.append({"name": name})

    return contexts


def _read_env_vars() -> dict:
    """Чита environment варијабле за cloud креденцијале."""
    result = {
        "aws": [],
        "gcp": [],
        "azure": [],
    }

    for cloud, var_names in CLOUD_ENV_VARS.items():
        for var_name in var_names:
            value = os.environ.get(var_name)
            if value:
                # Маскирамо вредности које су креденцијали.
                if "SECRET" in var_name or "TOKEN" in var_name or "KEY" in var_name:
                    if "ID" in var_name or var_name.endswith("_ID"):
                        display = _mask_value(value, 4, 4)
                    else:
                        display = _mask_value(value, 4, 4)
                else:
                    display = value

                result[cloud].append({
                    "name": var_name,
                    "value": value,
                    "display": display,
                })

    return result


def _mask_value(value: str, show_first: int = 4, show_last: int = 0) -> str:
    """Маскира вредност за приказ.

    show_first: колико првих знакова приказати.
    show_last: колико последњих знакова приказати.
    """
    if not value:
        return "(empty)"

    # Ако је кратка, маскирамо целину.
    if len(value) <= show_first + show_last:
        return "*" * len(value)

    if show_last > 0:
        return (
            value[:show_first]
            + "*" * min(len(value) - show_first - show_last, 20)
            + value[-show_last:]
        )

    return value[:show_first] + "*" * min(len(value) - show_first, 20)


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    aws = data.get("aws", {})
    gcp = data.get("gcp", {})
    azure = data.get("azure", {})
    kube = data.get("kubernetes", {})
    env_vars = data.get("environment", {})
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total findings:[/bold]  "
        f"[bold red]{summary.get('total_findings', 0)}[/bold red]\n"
    )

    # AWS.
    _print_aws(aws)

    # GCP.
    _print_gcp(gcp)

    # Azure.
    _print_azure(azure)

    # Kubernetes.
    _print_kubernetes(kube)

    # Environment.
    _print_env_vars(env_vars)


def _print_aws(aws: dict) -> None:
    """Приказује AWS креденцијале."""
    profiles = aws.get("profiles", [])

    if not profiles and not aws.get("credentials_file"):
        return

    console.print(f"[bold cyan]AWS ({len(profiles)} profile(s))[/bold cyan]\n")

    if aws.get("credentials_file"):
        console.print(
            f"  [dim]Credentials: {aws['credentials_file']}[/dim]"
        )

    if aws.get("config_file"):
        console.print(
            f"  [dim]Config: {aws['config_file']}[/dim]"
        )

    console.print()

    for profile in profiles:
        name = profile.get("profile", "?")
        source = profile.get("source", "")

        console.print(f"  [bold]{name}[/bold]")

        if profile.get("access_key"):
            console.print(
                f"    Access Key: [red]{profile['access_key']}[/red]"
            )
        if profile.get("secret_key"):
            console.print(
                f"    Secret Key: [red]{profile['secret_key']}[/red]"
            )
        if profile.get("session_token"):
            console.print(
                f"    Session Token: [red]{profile['session_token']}[/red]"
            )
        if profile.get("region"):
            console.print(f"    Region:     {profile['region']}")

        console.print(f"    [dim]Source: {source}[/dim]")
        console.print()


def _print_gcp(gcp: dict) -> None:
    """Приказује GCP креденцијале."""
    accounts = gcp.get("accounts", [])
    sa = gcp.get("service_accounts", [])

    if not accounts and not sa and not gcp.get("config_dir"):
        return

    console.print(
        f"[bold cyan]GCP ({len(accounts)} account(s), "
        f"{len(sa)} service account(s))[/bold cyan]\n"
    )

    if gcp.get("config_dir"):
        console.print(f"  [dim]Config: {gcp['config_dir']}[/dim]\n")

    for account in accounts:
        console.print(
            f"  [bold]{account.get('type', 'unknown')}[/bold]"
        )

        if account.get("project_id"):
            console.print(
                f"    Project:   {account['project_id']}"
            )
        if account.get("account"):
            console.print(
                f"    Account:   {account['account']}"
            )
        if account.get("client_id"):
            console.print(
                f"    Client ID: [red]{account['client_id']}[/red]"
            )
        if account.get("refresh_token"):
            console.print(
                f"    Refresh Token: [red]{account['refresh_token']}[/red]"
            )

        console.print(
            f"    [dim]Source: {account.get('source', '?')}[/dim]"
        )
        console.print()

    for sa_entry in sa:
        console.print("  [bold]Service Account[/bold]")
        console.print(
            f"    Project:      {sa_entry.get('project_id')}"
        )
        console.print(
            f"    Client email: {sa_entry.get('client_email')}"
        )
        if sa_entry.get("private_key_id"):
            console.print(
                f"    Key ID:       [red]{sa_entry['private_key_id']}[/red]"
            )
        if sa_entry.get("has_private_key"):
            console.print(
                "    Private key:  [red]present[/red]"
            )
        console.print(
            f"    [dim]Path: {sa_entry.get('path')}[/dim]"
        )
        console.print()


def _print_azure(azure: dict) -> None:
    """Приказује Azure креденцијале."""
    profiles = azure.get("profiles", [])

    if not profiles and not azure.get("config_dir"):
        return

    console.print(
        f"[bold cyan]Azure ({len(profiles)} entry/entries)[/bold cyan]\n"
    )

    if azure.get("config_dir"):
        console.print(f"  [dim]Config: {azure['config_dir']}[/dim]\n")

    for profile in profiles:
        entry_type = profile.get("type", "?")

        if entry_type == "subscription":
            console.print(f"  [bold]Subscription[/bold]")
            console.print(
                f"    ID:     [red]{profile.get('subscription_id')}[/red]"
            )
            console.print(f"    Name:   {profile.get('name')}")
            console.print(f"    Tenant: {profile.get('tenant_id')}")
            console.print(f"    User:   {profile.get('user')}")
        else:
            console.print(
                f"  [bold]{entry_type}[/bold]  "
                f"[red](contains tokens)[/red]"
            )

        console.print(f"    [dim]{profile.get('path', '')}[/dim]")
        console.print()


def _print_kubernetes(kube: dict) -> None:
    """Приказује Kubernetes конфигурацију."""
    contexts = kube.get("contexts", [])
    clusters = kube.get("clusters", [])

    if not contexts and not clusters and not kube.get("config_file"):
        return

    console.print(
        f"[bold cyan]Kubernetes "
        f"({len(contexts)} context(s), "
        f"{len(clusters)} cluster(s))[/bold cyan]\n"
    )

    if kube.get("config_file"):
        console.print(f"  [dim]Config: {kube['config_file']}[/dim]\n")

    for cluster in clusters[:10]:
        console.print(f"  [bold]Cluster:[/bold] {cluster.get('name')}")
        if cluster.get("server"):
            console.print(f"    Server: {cluster['server']}")

    if clusters:
        console.print()

    for ctx in contexts[:10]:
        console.print(f"  [bold]Context:[/bold] {ctx.get('name')}")
        if ctx.get("cluster"):
            console.print(f"    Cluster: {ctx['cluster']}")
        if ctx.get("user"):
            console.print(f"    User:    {ctx['user']}")

    if contexts:
        console.print()


def _print_env_vars(env_vars: dict) -> None:
    """Приказује environment варијабле."""
    total = sum(len(v) for v in env_vars.values())

    if total == 0:
        return

    console.print(
        f"[bold cyan]Environment variables "
        f"({total})[/bold cyan]\n"
    )

    for cloud, vars_list in env_vars.items():
        if not vars_list:
            continue

        console.print(f"  [bold]{cloud.upper()}:[/bold]")

        for var in vars_list:
            name = var.get("name")
            display = var.get("display", "")
            console.print(
                f"    [yellow]{name}[/yellow] = "
                f"[red]{display}[/red]"
            )

        console.print()