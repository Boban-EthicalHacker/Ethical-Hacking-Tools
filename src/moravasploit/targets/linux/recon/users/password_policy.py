# Модул за анализу политике лозинки.
# Чита /etc/login.defs и PAM конфигурацију за лозинке.
# Слаба политика лозинки значи да је brute force лакши.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import re
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до конфигурационих фајлова.
LOGIN_DEFS = Path("/etc/login.defs")
COMMON_PASSWORD = Path("/etc/pam.d/common-password")
PWQUALITY_CONF = Path("/etc/security/pwquality.conf")

# Кључни параметри из /etc/login.defs који нас занимају.
LOGIN_DEFS_KEYS = {
    "PASS_MAX_DAYS": ("Maximum password age (days)", "int"),
    "PASS_MIN_DAYS": ("Minimum password age (days)", "int"),
    "PASS_WARN_AGE": ("Warning days before expiration", "int"),
    "PASS_MIN_LEN": ("Minimum password length", "int"),
    "LOGIN_RETRIES": ("Login retry attempts", "int"),
    "LOGIN_TIMEOUT": ("Login timeout (seconds)", "int"),
    "ENCRYPT_METHOD": ("Password hashing algorithm", "str"),
    "SHA_CRYPT_MIN_ROUNDS": ("Minimum SHA crypt rounds", "int"),
    "SHA_CRYPT_MAX_ROUNDS": ("Maximum SHA crypt rounds", "int"),
    "UMASK": ("Default umask", "str"),
}

# Безбедносне препоруке за вредности.
RECOMMENDATIONS = {
    "PASS_MAX_DAYS": (90, "Should be 90 days or less"),
    "PASS_MIN_DAYS": (1, "Should be 1 or more"),
    "PASS_MIN_LEN": (12, "Should be at least 12"),
    "LOGIN_RETRIES": (5, "Should be 5 or less"),
}


def run() -> dict:
    """Анализира политику лозинки.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Password policy[/bold cyan]\n")

    # Читамо /etc/login.defs.
    login_defs = _read_login_defs()

    # Читамо PAM конфигурацију.
    pam_password = _read_pam_password()

    # Читамо pwquality конфигурацију.
    pwquality = _read_pwquality()

    # Правимо препоруке.
    recommendations = _make_recommendations(login_defs)

    data = {
        "login_defs": login_defs,
        "pam_password": pam_password,
        "pwquality": pwquality,
        "recommendations": recommendations,
        "summary": {
            "login_defs_readable": LOGIN_DEFS.exists() and _can_read(LOGIN_DEFS),
            "pam_readable": COMMON_PASSWORD.exists() and _can_read(COMMON_PASSWORD),
            "total_recommendations": len(recommendations),
        },
    }

    _print_data(data)

    return data


def _can_read(path: Path) -> bool:
    """Проверава да ли можемо да читамо фајл."""
    try:
        path.read_text(encoding="utf-8", errors="replace")
        return True
    except Exception:
        return False


def _read_login_defs() -> dict:
    """Чита кључне параметре из /etc/login.defs."""
    result = {}

    if not LOGIN_DEFS.exists():
        return result

    try:
        content = LOGIN_DEFS.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return result
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        key = parts[0]
        value = parts[1]

        if key in LOGIN_DEFS_KEYS:
            _, value_type = LOGIN_DEFS_KEYS[key]

            if value_type == "int":
                try:
                    result[key] = int(value)
                except ValueError:
                    result[key] = value
            else:
                result[key] = value

    return result


def _read_pam_password() -> dict:
    """Чита PAM конфигурацију за лозинке."""
    result = {
        "path": str(COMMON_PASSWORD),
        "readable": False,
        "modules": [],
        "pwquality_options": {},
    }

    if not COMMON_PASSWORD.exists():
        return result

    try:
        content = COMMON_PASSWORD.read_text(encoding="utf-8", errors="replace")
        result["readable"] = True
    except PermissionError:
        return result
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # PAM линија има формат:
        #   type control module [options]
        # Control може бити:
        #   - обична реч: required, requisite, optional, sufficient
        #   - у угластим заградама: [success=1 default=ignore]

        # Прво узимамо прву реч (type).
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue

        module_type = parts[0]
        rest = parts[1] + " " + parts[2]  # остатак након type

        # Сада парсирамо control и module из остатка.
        control, module, options = _parse_pam_rest(rest)

        if module is None:
            continue

        module_entry = {
            "type": module_type,
            "control": control,
            "module": module.split("/")[-1],
            "options": options,
        }

        # Ако је pam_pwquality или pam_cracklib, парсирамо опције.
        if "pwquality" in module or "cracklib" in module:
            for option in options:
                if "=" in option:
                    opt_key, opt_value = option.split("=", 1)
                    result["pwquality_options"][opt_key] = opt_value

        result["modules"].append(module_entry)

    return result


def _parse_pam_rest(rest: str) -> tuple[str, str | None, list[str]]:
    """Парсира control, module и options из PAM линије.

    Враћа: (control, module, options)
    """
    rest = rest.strip()

    control = ""
    remaining = ""

    # Ако почиње са "[" — контрол је у угластим заградама.
    if rest.startswith("["):
        end = rest.find("]")
        if end == -1:
            # Нема затварајуће заграде — неисправна линија.
            return "", None, []

        control = rest[: end + 1]
        remaining = rest[end + 1 :].strip()
    else:
        # Control је једна реч.
        parts = rest.split(None, 1)
        if len(parts) < 2:
            return "", None, []

        control = parts[0]
        remaining = parts[1].strip()

    # remaining сада почиње са module.
    parts = remaining.split(None, 1)
    if not parts:
        return control, None, []

    module = parts[0]
    options = parts[1].split() if len(parts) > 1 else []

    return control, module, options


def _read_pwquality() -> dict:
    """Чита /etc/security/pwquality.conf."""
    result = {}

    if not PWQUALITY_CONF.exists():
        return result

    try:
        content = PWQUALITY_CONF.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return result
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Формат: key = value или key=value
        match = re.match(r"^(\w+)\s*=\s*(.+)$", line)
        if not match:
            continue

        key = match.group(1)
        value = match.group(2).strip()

        result[key] = value

    return result


def _make_recommendations(login_defs: dict) -> list[dict]:
    """Прави препоруке на основу прочитаних вредности."""
    recommendations = []

    for key, (threshold, message) in RECOMMENDATIONS.items():
        if key not in login_defs:
            continue

        value = login_defs[key]

        if not isinstance(value, int):
            continue

        # За PASS_MAX_DAYS: ако је веће од препоруке — лоше.
        # За остале: ако је мање од препоруке — лоше.
        if key == "PASS_MAX_DAYS":
            if value > threshold or value == 99999:
                recommendations.append({
                    "key": key,
                    "value": value,
                    "threshold": threshold,
                    "severity": "yellow",
                    "message": f"{key}={value} — {message}",
                })
        else:
            if value < threshold:
                recommendations.append({
                    "key": key,
                    "value": value,
                    "threshold": threshold,
                    "severity": "yellow",
                    "message": f"{key}={value} — {message}",
                })

    return recommendations


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    login_defs = data.get("login_defs", {})
    pam = data.get("pam_password", {})
    pwquality = data.get("pwquality", {})
    recommendations = data.get("recommendations", [])

    # login.defs.
    console.print("[bold]From /etc/login.defs[/bold]\n")

    if not login_defs:
        console.print("  [yellow]Not readable or empty.[/yellow]\n")
    else:
        for key, (label, _) in LOGIN_DEFS_KEYS.items():
            if key in login_defs:
                value = login_defs[key]
                console.print(f"  {label:35s} [cyan]{value}[/cyan]")
        console.print()

    # PAM.
    console.print("[bold]From PAM configuration[/bold]\n")

    if not pam.get("readable"):
        console.print(
            "  [dim]/etc/pam.d/common-password not readable.[/dim]\n"
        )
    else:
        modules = pam.get("modules", [])
        console.print(f"  Modules: {len(modules)}\n")

        for module in modules:
            module_type = module.get("type", "?")
            control = module.get("control", "?")
            module_name = module.get("module", "?")
            options = module.get("options", [])

            line = f"  {module_type:10s} {control:30s} {module_name}"

            if options:
                line += f"  [dim]{' '.join(options)}[/dim]"

            console.print(line)

        console.print()

        # Приказујемо pwquality опције ако постоје.
        pwq_options = pam.get("pwquality_options", {})
        if pwq_options:
            console.print(
                "  [bold]pwquality options from PAM:[/bold]\n"
            )
            for key, value in sorted(pwq_options.items()):
                console.print(f"    {key:30s} [cyan]{value}[/cyan]")
            console.print()

    # pwquality.conf.
    if pwquality:
        console.print("[bold]From /etc/security/pwquality.conf[/bold]\n")
        for key, value in sorted(pwquality.items()):
            console.print(f"  {key:30s} [cyan]{value}[/cyan]")
        console.print()

    # Препоруке.
    if recommendations:
        console.print(
            f"[bold yellow]Recommendations ({len(recommendations)}):[/bold yellow]\n"
        )
        for rec in recommendations:
            severity = rec.get("severity", "yellow")
            console.print(
                f"  [{severity}]●[/{severity}] {rec['message']}"
            )
        console.print()
    else:
        console.print(
            "[bold green]No security recommendations.[/bold green]\n"
        )