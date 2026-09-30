# Модул за приказ DNS конфигурације.
# Чита /etc/resolv.conf, /etc/hosts, /etc/nsswitch.conf и
# systemd-resolved конфигурацију ако постоји.
# DNS је важан јер ако иде на непоуздан сервер, саобраћај
# може бити пресретнут или преусмерен.
#
# Модул враћа речник са подацима, који мени чува у JSON.
from pathlib import Path

from rich.console import Console

console = Console()

# Путање до конфигурационих фајлова.
RESOLV_CONF = Path("/etc/resolv.conf")
HOSTS_FILE = Path("/etc/hosts")
NSSWITCH_CONF = Path("/etc/nsswitch.conf")
RESOLVED_CONF = Path("/etc/systemd/resolved.conf")
RESOLVED_DIR = Path("/etc/systemd/resolved.conf.d")

# Познати "сумњиви" DNS сервери (јавни DNS-ови).
# Ово не мора да буде лоше — само вреди знати.
PUBLIC_DNS = {
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "64.6.64.6": "Verisign",
    "64.6.65.6": "Verisign",
}


def run() -> dict:
    """Приказује DNS конфигурацију.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]DNS configuration[/bold cyan]\n")

    data = {
        "resolv_conf": _read_resolv_conf(),
        "hosts": _read_hosts(),
        "nsswitch": _read_nsswitch(),
        "systemd_resolved": _read_resolved_conf(),
    }

    _print_data(data)

    return data


def _read_resolv_conf() -> dict:
    """Чита /etc/resolv.conf."""
    result = {
        "path": str(RESOLV_CONF),
        "readable": False,
        "is_symlink": False,
        "symlink_target": None,
        "nameservers": [],
        "search": [],
        "options": [],
    }

    if not RESOLV_CONF.exists():
        return result

    # Проверавамо да ли је симлинк (systemd-resolved често прави симлинк).
    if RESOLV_CONF.is_symlink():
        result["is_symlink"] = True
        try:
            result["symlink_target"] = str(RESOLV_CONF.resolve())
        except Exception:
            pass

    try:
        content = RESOLV_CONF.read_text(encoding="utf-8", errors="replace")
        result["readable"] = True
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", ";")):
            continue

        parts = line.split()
        if not parts:
            continue

        key = parts[0]

        if key == "nameserver" and len(parts) > 1:
            ns = parts[1]
            entry = {
                "address": ns,
                "known": PUBLIC_DNS.get(ns, ""),
            }
            result["nameservers"].append(entry)
        elif key == "search":
            result["search"].extend(parts[1:])
        elif key == "domain" and len(parts) > 1:
            result["search"].append(parts[1])
        elif key == "options":
            result["options"].extend(parts[1:])

    return result


def _read_hosts() -> list[dict]:
    """Чита /etc/hosts."""
    if not HOSTS_FILE.exists():
        return []

    try:
        content = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    entries = []

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Уклањамо inline коментаре.
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        parts = line.split()
        if len(parts) < 2:
            continue

        ip = parts[0]
        hostnames = parts[1:]

        entries.append({
            "ip": ip,
            "hostnames": hostnames,
        })

    return entries


def _read_nsswitch() -> dict:
    """Чита /etc/nsswitch.conf."""
    result = {
        "path": str(NSSWITCH_CONF),
        "readable": False,
        "hosts": [],
        "passwd": [],
        "group": [],
    }

    if not NSSWITCH_CONF.exists():
        return result

    try:
        content = NSSWITCH_CONF.read_text(encoding="utf-8", errors="replace")
        result["readable"] = True
    except Exception:
        return result

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Формат: database: service1 service2 ...
        if ":" not in line:
            continue

        db, services_str = line.split(":", 1)
        db = db.strip()
        services = services_str.strip().split()

        if db == "hosts":
            result["hosts"] = services
        elif db == "passwd":
            result["passwd"] = services
        elif db == "group":
            result["group"] = services

    return result


def _read_resolved_conf() -> dict:
    """Чита systemd-resolved конфигурацију."""
    result = {
        "main_conf": None,
        "main_conf_readable": False,
        "drop_in_files": [],
        "dns_servers": [],
        "dns_over_tls": None,
        "dnssec": None,
    }

    # Главни фајл.
    if RESOLVED_CONF.exists():
        try:
            content = RESOLVED_CONF.read_text(
                encoding="utf-8", errors="replace"
            )
            result["main_conf_readable"] = True
            result["main_conf"] = _parse_resolved_conf(content)
        except Exception:
            pass

    # Drop-in фајлови у /etc/systemd/resolved.conf.d/.
    if RESOLVED_DIR.exists() and RESOLVED_DIR.is_dir():
        try:
            files = sorted(RESOLVED_DIR.iterdir())
        except (PermissionError, Exception):
            files = []

        for file_path in files:
            if not file_path.is_file():
                continue
            if not file_path.name.endswith(".conf"):
                continue

            try:
                content = file_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                parsed = _parse_resolved_conf(content)
                result["drop_in_files"].append({
                    "path": str(file_path),
                    "config": parsed,
                })
            except Exception:
                continue

    # Извлачимо DNS сервере и DoT/DoH из главног фајла.
    main = result.get("main_conf") or {}
    if main.get("DNS"):
        result["dns_servers"] = main["DNS"]
    if main.get("DNSOverTLS"):
        result["dns_over_tls"] = main["DNSOverTLS"]
    if main.get("DNSSEC"):
        result["dnssec"] = main["DNSSEC"]

    return result


def _parse_resolved_conf(content: str) -> dict:
    """Парсира systemd-resolved конфигурацију."""
    result = {}

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Вредност може бити листа раздвојена размацима.
        parts = value.split()

        if len(parts) == 1:
            result[key] = parts[0]
        else:
            result[key] = parts

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    resolv = data.get("resolv_conf", {})
    hosts = data.get("hosts", [])
    nsswitch = data.get("nsswitch", {})
    resolved = data.get("systemd_resolved", {})

    # /etc/resolv.conf
    console.print("[bold]/etc/resolv.conf[/bold]\n")

    if not resolv.get("readable"):
        console.print("  [dim]Not readable.[/dim]\n")
    else:
        if resolv.get("is_symlink"):
            console.print(
                f"  [dim]Symlink to: {resolv.get('symlink_target')}[/dim]"
            )

        nameservers = resolv.get("nameservers", [])
        if nameservers:
            console.print(f"  [bold]Nameservers ({len(nameservers)}):[/bold]")
            for ns in nameservers:
                addr = ns.get("address", "?")
                known = ns.get("known", "")

                # Ако је јавни DNS, означавамо жуто.
                if known:
                    console.print(
                        f"    [yellow]{addr}[/yellow]  "
                        f"[dim]({known})[/dim]"
                    )
                else:
                    console.print(f"    [cyan]{addr}[/cyan]")
        else:
            console.print("  [dim]No nameservers configured.[/dim]")

        if resolv.get("search"):
            console.print(
                f"\n  [bold]Search domains:[/bold] "
                f"{', '.join(resolv['search'])}"
            )

        if resolv.get("options"):
            console.print(
                f"  [bold]Options:[/bold] "
                f"{' '.join(resolv['options'])}"
            )

        console.print()

    # /etc/hosts
    console.print(f"[bold]/etc/hosts ({len(hosts)} entries)[/bold]\n")

    if hosts:
        # Приказујемо само првих 15.
        for entry in hosts[:15]:
            ip = entry.get("ip", "?")
            hostnames = entry.get("hostnames", [])

            # Означавамо сумњиве IP-ове.
            is_suspicious = _is_suspicious_hosts_entry(ip, hostnames)

            if is_suspicious:
                console.print(
                    f"  [yellow]{ip:15s}[/yellow]  "
                    f"{' '.join(hostnames)}"
                )
            else:
                console.print(
                    f"  [dim]{ip:15s}  {' '.join(hostnames)}[/dim]"
                )

        if len(hosts) > 15:
            console.print(
                f"  [dim]... and {len(hosts) - 15} more[/dim]"
            )
    else:
        console.print("  [dim]No entries.[/dim]")

    console.print()

    # nsswitch.conf
    if nsswitch.get("readable"):
        console.print("[bold]/etc/nsswitch.conf[/bold]\n")

        if nsswitch.get("hosts"):
            console.print(
                f"  [bold]hosts:[/bold]  "
                f"{' '.join(nsswitch['hosts'])}"
            )

        console.print()

    # systemd-resolved
    resolved_main = resolved.get("main_conf")
    if resolved_main:
        console.print("[bold]systemd-resolved[/bold]\n")

        if resolved.get("dns_servers"):
            console.print(
                f"  [bold]DNS servers:[/bold]  "
                f"{', '.join(resolved['dns_servers'])}"
            )

        if resolved.get("dns_over_tls"):
            dot = resolved["dns_over_tls"]

            if dot in ("yes", "true"):
                color = "green"
            elif dot in ("no", "false"):
                color = "red"
            else:
                color = "yellow"

            console.print(
                f"  [bold]DNS over TLS:[/bold]  "
                f"[{color}]{dot}[/{color}]"
            )

        if resolved.get("dnssec"):
            console.print(
                f"  [bold]DNSSEC:[/bold]       "
                f"{resolved['dnssec']}"
            )

        if resolved.get("drop_in_files"):
            console.print(
                f"\n  [bold]Drop-in files:[/bold]  "
                f"{len(resolved['drop_in_files'])}"
            )

        console.print()


def _is_suspicious_hosts_entry(ip: str, hostnames: list[str]) -> bool:
    """Проверава да ли је /etc/hosts унос сумњив."""
    # Сумњиво ако мапира познат домен на локалну адресу.
    suspicious_domains = (
        "google.com", "facebook.com", "twitter.com",
        "youtube.com", "amazon.com", "microsoft.com",
        "apple.com", "github.com", "cloudflare.com",
    )

    for hostname in hostnames:
        hostname_lower = hostname.lower()
        for domain in suspicious_domains:
            if domain in hostname_lower:
                # Ако мапира на приватну адресу, сумњиво.
                if ip.startswith(("127.", "10.", "192.168.", "172.")):
                    return True

    return False