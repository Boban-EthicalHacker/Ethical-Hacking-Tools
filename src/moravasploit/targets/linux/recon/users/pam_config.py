# Модул за анализу PAM (Pluggable Authentication Modules) конфигурације.
# PAM је систем за аутентикацију на Linux-у. Конфигурација је
# у /etc/pam.d/ и садржи правила за различите сервисе (login,
# sshd, sudo, su, итд.).
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријум са PAM конфигурацијом.
PAM_DIR = Path("/etc/pam.d")

# Кључни сервиси које увек приказујемо.
KEY_SERVICES = [
    "common-auth",
    "common-account",
    "common-session",
    "common-password",
    "sshd",
    "sudo",
    "su",
    "login",
]

# Безбедносно важни модули.
NOTABLE_MODULES = {
    "pam_unix.so": "Standard Unix authentication",
    "pam_pwquality.so": "Password quality checking",
    "pam_cracklib.so": "Password strength (legacy)",
    "pam_deny.so": "Explicit deny",
    "pam_permit.so": "Explicit permit (allow)",
    "pam_rootok.so": "Allow root without password",
    "pam_wheel.so": "Restrict su to wheel group",
    "pam_tally2.so": "Login attempt counting (legacy)",
    "pam_faillock.so": "Login attempt counting",
    "pam_faildelay.so": "Delay on failed login",
    "pam_pwhistory.so": "Password history",
    "pam_limits.so": "Resource limits",
    "pam_systemd.so": "systemd integration",
    "pam_gnome_keyring.so": "GNOME keyring integration",
    "pam_winbind.so": "Windows domain auth",
    "pam_sss.so": "SSSD integration",
    "pam_krb5.so": "Kerberos auth",
    "pam_ldap.so": "LDAP auth",
    "pam_google_authenticator.so": "Google 2FA",
    "pam_oath.so": "OATH 2FA",
    "pam_u2f.so": "U2F hardware keys",
}


def run() -> dict:
    """Анализира PAM конфигурацију.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]PAM configuration[/bold cyan]\n")

    # Проверавамо да ли PAM директоријум постоји.
    if not PAM_DIR.exists():
        console.print("  [red]/etc/pam.d/ not found.[/red]\n")
        return _empty_result()

    # Читамо све PAM фајлове.
    services = _read_all_services()

    # Анализирамо кључне сервисе.
    key_services = {}
    for name in KEY_SERVICES:
        if name in services:
            key_services[name] = services[name]

    data = {
        "pam_dir": str(PAM_DIR),
        "total_services": len(services),
        "key_services": key_services,
        "notable_modules": _collect_notable_modules(services),
        "summary": _make_summary(services),
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат кад нема PAM директоријума."""
    return {
        "pam_dir": str(PAM_DIR),
        "total_services": 0,
        "key_services": {},
        "notable_modules": [],
        "summary": {
            "total_services": 0,
            "total_rules": 0,
            "notable_modules_found": 0,
        },
    }


def _read_all_services() -> dict:
    """Чита све PAM фајлове у /etc/pam.d/."""
    services = {}

    try:
        files = sorted(PAM_DIR.iterdir())
    except PermissionError:
        return services
    except Exception:
        return services

    for file_path in files:
        if not file_path.is_file():
            continue

        # Прескачемо backup фајлове.
        name = file_path.name
        if name.endswith("~") or name.startswith("."):
            continue

        rules = _parse_pam_file(file_path)
        if rules:
            services[name] = rules

    return services


def _parse_pam_file(path: Path) -> list[dict]:
    """Парсира један PAM фајл."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, Exception):
        return []

    rules = []

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Формат: type control module [options]
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue

        module_type = parts[0]
        rest = parts[1] + " " + parts[2]

        control, module, options = _parse_pam_rest(rest)
        if module is None:
            continue

        rules.append({
            "type": module_type,
            "control": control,
            "module": module.split("/")[-1],
            "options": options,
        })

    return rules


def _parse_pam_rest(rest: str) -> tuple[str, str | None, list[str]]:
    """Парсира control, module и options из PAM линије."""
    rest = rest.strip()

    control = ""
    remaining = ""

    if rest.startswith("["):
        end = rest.find("]")
        if end == -1:
            return "", None, []
        control = rest[: end + 1]
        remaining = rest[end + 1 :].strip()
    else:
        parts = rest.split(None, 1)
        if len(parts) < 2:
            return "", None, []
        control = parts[0]
        remaining = parts[1].strip()

    parts = remaining.split(None, 1)
    if not parts:
        return control, None, []

    module = parts[0]
    options = parts[1].split() if len(parts) > 1 else []

    return control, module, options


def _collect_notable_modules(services: dict) -> list[dict]:
    """Проналази безбедносно занимљиве PAM модуле."""
    found = {}

    for service_name, rules in services.items():
        for rule in rules:
            module = rule.get("module", "")
            if module in NOTABLE_MODULES:
                if module not in found:
                    found[module] = {
                        "module": module,
                        "description": NOTABLE_MODULES[module],
                        "used_in": [],
                    }
                if service_name not in found[module]["used_in"]:
                    found[module]["used_in"].append(service_name)

    return sorted(found.values(), key=lambda x: x["module"])


def _make_summary(services: dict) -> dict:
    """Прави резиме."""
    total_rules = sum(len(rules) for rules in services.values())

    return {
        "total_services": len(services),
        "total_rules": total_rules,
        "notable_modules_found": len(_collect_notable_modules(services)),
    }


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    summary = data.get("summary", {})
    key_services = data.get("key_services", {})
    notable = data.get("notable_modules", [])

    console.print(
        f"[bold]Total services:[/bold]      {summary.get('total_services', 0)}"
    )
    console.print(
        f"[bold]Total rules:[/bold]         {summary.get('total_rules', 0)}"
    )
    console.print(
        f"[bold]Notable modules:[/bold]     {summary.get('notable_modules_found', 0)}"
    )
    console.print()

    # Приказујемо кључне сервисе.
    for service_name, rules in key_services.items():
        _print_service(service_name, rules)

    # Приказујемо занимљиве модуле.
    if notable:
        console.print("[bold cyan]Notable modules[/bold cyan]\n")
        for module in notable:
            console.print(
                f"  [bold]{module['module']}[/bold]  "
                f"[dim]{module['description']}[/dim]"
            )
            console.print(
                f"    [dim]Used in: {', '.join(module['used_in'])}[/dim]"
            )
        console.print()


def _print_service(name: str, rules: list[dict]) -> None:
    """Приказује правила једног сервиса."""
    console.print(f"[bold cyan]{name}[/bold cyan] ({len(rules)} rules)\n")

    for rule in rules:
        rule_type = rule.get("type", "?")
        control = rule.get("control", "?")
        module = rule.get("module", "?")
        options = rule.get("options", [])

        # Скраћујемо control ако је дугачак.
        control_display = control
        if len(control) > 25:
            control_display = control[:22] + "..."

        line = f"  {rule_type:10s} {control_display:25s} {module}"

        if options:
            opts = " ".join(options)
            if len(opts) > 30:
                opts = opts[:27] + "..."
            line += f"  [dim]{opts}[/dim]"

        console.print(line)

    console.print()