# Модул за приказ правила фајервола.
# Препознаје који систем се користи (iptables, nftables, ufw,
# firewalld) и чита правила из одговарајућег извора.
# Ако нема фајервола, сви отворени портови су доступни споља.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess

from rich.console import Console

console = Console()


def run() -> dict:
    """Приказује правила фајервола.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Firewall rules[/bold cyan]\n")

    # Препознајемо који систем је активан.
    system = _detect_firewall()

    # Читамо правила.
    rules = _read_rules(system)

    data = {
        "system": system,
        "rules": rules,
        "summary": _make_summary(system, rules),
    }

    _print_data(data)

    return data


def _detect_firewall() -> str:
    """Препознаје који систем фајервола је активан.

    Редослед провере:
        1. ufw (најчешћи на Ubuntu/Debian/Kali)
        2. firewalld (најчешћи на RHEL/Fedora)
        3. nftables (новији)
        4. iptables (класични)
    """
    # Проверавамо да ли су команде доступне.
    if shutil.which("ufw"):
        # Проверавамо да ли је ufw активан.
        if _ufw_is_active():
            return "ufw"

    if shutil.which("firewall-cmd"):
        if _firewalld_is_active():
            return "firewalld"

    if shutil.which("nft"):
        # Ако nftables има правила, користимо га.
        if _nftables_has_rules():
            return "nftables"

    if shutil.which("iptables"):
        if _iptables_has_rules():
            return "iptables"

    # Ниједан није активан или нема правила.
    # Ипак приказујемо шта је доступно.
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    if shutil.which("nft"):
        return "nftables"
    if shutil.which("iptables"):
        return "iptables"

    return "none"


def _ufw_is_active() -> bool:
    """Проверава да ли је ufw активан."""
    try:
        result = subprocess.run(
            ["ufw", "status"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "Status: active" in result.stdout
    except Exception:
        return False


def _firewalld_is_active() -> bool:
    """Проверава да ли је firewalld активан."""
    try:
        result = subprocess.run(
            ["firewall-cmd", "--state"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "running" in result.stdout.lower()
    except Exception:
        return False


def _nftables_has_rules() -> bool:
    """Проверава да ли nftables има правила."""
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Ако има више од 1 линије, има правила.
        lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
        return len(lines) > 1
    except Exception:
        return False


def _iptables_has_rules() -> bool:
    """Проверава да ли iptables има правила."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Прескачемо заглавља. Ако има нешто друго — има правила.
        lines = [
            ln for ln in result.stdout.splitlines()
            if ln.strip() and not ln.startswith(("Chain", "target", "pkts"))
        ]
        return len(lines) > 0
    except Exception:
        return False


def _read_rules(system: str) -> dict:
    """Чита правила за дати систем."""
    if system == "ufw":
        return _read_ufw()
    if system == "firewalld":
        return _read_firewalld()
    if system == "nftables":
        return _read_nftables()
    if system == "iptables":
        return _read_iptables()
    return {}


def _read_ufw() -> dict:
    """Чита ufw правила."""
    result = {
        "active": False,
        "raw_output": "",
        "rules": [],
    }

    try:
        proc = subprocess.run(
            ["ufw", "status", "verbose"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return result

    output = proc.stdout
    result["raw_output"] = output
    result["active"] = "Status: active" in output

    # Парсирамо правила.
    for line in output.splitlines():
        line = line.strip()

        # Правила почињу са "ALLOW" или "DENY".
        if line.startswith(("ALLOW", "DENY", "REJECT", "LIMIT")):
            result["rules"].append(line)

    return result


def _read_firewalld() -> dict:
    """Чита firewalld правила."""
    result = {
        "active": False,
        "default_zone": None,
        "zones": [],
        "raw_output": "",
    }

    try:
        # Основне информације.
        state = subprocess.run(
            ["firewall-cmd", "--state"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["active"] = "running" in state.stdout.lower()

        # Default zone.
        default_zone = subprocess.run(
            ["firewall-cmd", "--get-default-zone"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["default_zone"] = default_zone.stdout.strip()

        # Листа зона.
        zones = subprocess.run(
            ["firewall-cmd", "--list-all-zones"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result["raw_output"] = zones.stdout

        # Парсирамо зоне.
        for zone in _parse_firewalld_zones(zones.stdout):
            result["zones"].append(zone)

    except Exception:
        pass

    return result


def _parse_firewalld_zones(output: str) -> list[dict]:
    """Парсира firewalld зоне."""
    zones = []
    current_zone = None

    for line in output.splitlines():
        line = line.rstrip()

        # Зона почиње на почетку линије без размака.
        if line and not line.startswith(" "):
            if current_zone:
                zones.append(current_zone)
            current_zone = {
                "name": line.strip(),
                "ports": [],
                "services": [],
                "interfaces": [],
                "sources": [],
            }
            continue

        # Атрибути зоне.
        if current_zone is None:
            continue

        stripped = line.strip()

        if stripped.startswith("ports:"):
            ports_str = stripped.replace("ports:", "").strip()
            if ports_str:
                current_zone["ports"] = ports_str.split()

        elif stripped.startswith("services:"):
            services_str = stripped.replace("services:", "").strip()
            if services_str:
                current_zone["services"] = services_str.split()

        elif stripped.startswith("interfaces:"):
            interfaces_str = stripped.replace("interfaces:", "").strip()
            if interfaces_str:
                current_zone["interfaces"] = interfaces_str.split()

        elif stripped.startswith("sources:"):
            sources_str = stripped.replace("sources:", "").strip()
            if sources_str:
                current_zone["sources"] = sources_str.split()

    if current_zone:
        zones.append(current_zone)

    return zones


def _read_nftables() -> dict:
    """Чита nftables правила."""
    result = {
        "raw_output": "",
        "tables": [],
    }

    try:
        proc = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result["raw_output"] = proc.stdout

        # Групишемо по табелама.
        current_table = None
        current_chain = None

        for line in proc.stdout.splitlines():
            stripped = line.strip()

            if stripped.startswith("table "):
                # Нова табела: "table ip filter {"
                parts = stripped.split()
                if len(parts) >= 3:
                    table_name = f"{parts[1]} {parts[2]}"
                    current_table = {
                        "name": table_name,
                        "chains": [],
                    }
                    result["tables"].append(current_table)

            elif stripped.startswith("chain ") and current_table is not None:
                # Нови chain: "chain INPUT {"
                parts = stripped.split()
                if len(parts) >= 2:
                    current_chain = {
                        "name": parts[1],
                        "rules": [],
                    }
                    current_table["chains"].append(current_chain)

            elif current_chain is not None and stripped and not stripped.startswith("}"):
                # Правило.
                if not stripped.startswith(("type ", "policy ", "hook ", "priority ")):
                    current_chain["rules"].append(stripped)

    except Exception:
        pass

    return result


def _read_iptables() -> dict:
    """Чита iptables правила."""
    result = {
        "ipv4": _read_iptables_family("iptables"),
        "ipv6": _read_iptables_family("ip6tables"),
    }
    return result


def _read_iptables_family(cmd: str) -> dict:
    """Чита iptables за једну фамилију (IPv4 или IPv6)."""
    family_result = {
        "available": shutil.which(cmd) is not None,
        "raw_output": "",
        "chains": {},
    }

    if not family_result["available"]:
        return family_result

    try:
        proc = subprocess.run(
            [cmd, "-L", "-n", "-v"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        family_result["raw_output"] = proc.stdout

        # Парсирамо chains.
        current_chain = None

        for line in proc.stdout.splitlines():
            stripped = line.strip()

            if stripped.startswith("Chain "):
                # "Chain INPUT (policy ACCEPT 1234 packets, 5678 bytes)"
                parts = stripped.split()
                if len(parts) >= 2:
                    chain_name = parts[1]
                    policy = ""
                    if "policy" in parts:
                        idx = parts.index("policy")
                        if idx + 1 < len(parts):
                            policy = parts[idx + 1]

                    current_chain = {
                        "name": chain_name,
                        "policy": policy,
                        "rules": [],
                    }
                    family_result["chains"][chain_name] = current_chain

            elif current_chain is not None and stripped:
                # Правило (прескачемо заглавље).
                if stripped.startswith(("target", "pkts")):
                    continue
                current_chain["rules"].append(stripped)

    except Exception:
        pass

    return family_result


def _make_summary(system: str, rules: dict) -> dict:
    """Прави резиме."""
    summary = {
        "system": system,
        "active": False,
        "total_rules": 0,
    }

    if system == "ufw":
        summary["active"] = rules.get("active", False)
        summary["total_rules"] = len(rules.get("rules", []))

    elif system == "firewalld":
        summary["active"] = rules.get("active", False)
        total = 0
        for zone in rules.get("zones", []):
            total += len(zone.get("ports", []))
            total += len(zone.get("services", []))
        summary["total_rules"] = total

    elif system == "nftables":
        total = 0
        for table in rules.get("tables", []):
            for chain in table.get("chains", []):
                total += len(chain.get("rules", []))
        summary["total_rules"] = total
        summary["active"] = total > 0

    elif system == "iptables":
        total = 0
        for family in ("ipv4", "ipv6"):
            fam = rules.get(family, {})
            for chain in fam.get("chains", {}).values():
                total += len(chain.get("rules", []))
        summary["total_rules"] = total
        summary["active"] = total > 0

    return summary


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    system = data.get("system", "none")
    rules = data.get("rules", {})
    summary = data.get("summary", {})

    console.print(f"[bold]Firewall system:[/bold]  {system}")

    if system == "none":
        console.print()
        console.print(
            "[bold red]No firewall detected on this system![/bold red]\n"
        )
        console.print(
            "[dim]All open ports may be accessible from the network.[/dim]\n"
        )
        return

    # Стање.
    if summary.get("active"):
        console.print(
            f"[bold]Active:[/bold]           [green]yes[/green]"
        )
    else:
        console.print(
            f"[bold]Active:[/bold]           [red]no[/red]"
        )

    console.print(
        f"[bold]Total rules:[/bold]      {summary.get('total_rules', 0)}"
    )
    console.print()

    if not summary.get("active"):
        console.print(
            "[bold yellow]Firewall is not active![/bold yellow]\n"
        )
        console.print(
            "[dim]All open ports may be accessible from the network.[/dim]\n"
        )
        return

    # Приказујемо правила по систему.
    if system == "ufw":
        _print_ufw(rules)
    elif system == "firewalld":
        _print_firewalld(rules)
    elif system == "nftables":
        _print_nftables(rules)
    elif system == "iptables":
        _print_iptables(rules)


def _print_ufw(rules: dict) -> None:
    """Приказује ufw правила."""
    ufw_rules = rules.get("rules", [])

    if not ufw_rules:
        console.print("[dim]No rules defined.[/dim]\n")
        return

    console.print(f"[bold]Rules ({len(ufw_rules)}):[/bold]\n")

    for rule in ufw_rules:
        # Боја — зелено за ALLOW, црвено за DENY.
        if rule.startswith("ALLOW"):
            color = "green"
        elif rule.startswith(("DENY", "REJECT")):
            color = "red"
        else:
            color = "yellow"

        console.print(f"  [{color}]{rule}[/{color}]")

    console.print()


def _print_firewalld(rules: dict) -> None:
    """Приказује firewalld зоне."""
    zones = rules.get("zones", [])
    default_zone = rules.get("default_zone")

    if not zones:
        console.print("[dim]No zones defined.[/dim]\n")
        return

    console.print(
        f"[bold]Zones ({len(zones)}):[/bold]  "
        f"[dim]default: {default_zone}[/dim]\n"
    )

    for zone in zones:
        name = zone.get("name", "?")
        ports = zone.get("ports", [])
        services = zone.get("services", [])
        interfaces = zone.get("interfaces", [])

        # Прескачемо празне зоне.
        if not ports and not services and not interfaces:
            continue

        console.print(f"  [bold cyan]{name}[/bold cyan]")

        if interfaces:
            console.print(
                f"    Interfaces: {', '.join(interfaces)}"
            )
        if ports:
            console.print(f"    Ports:      {', '.join(ports)}")
        if services:
            console.print(f"    Services:   {', '.join(services)}")

        console.print()


def _print_nftables(rules: dict) -> None:
    """Приказује nftables табеле и chains."""
    tables = rules.get("tables", [])

    if not tables:
        console.print("[dim]No tables defined.[/dim]\n")
        return

    for table in tables:
        name = table.get("name", "?")
        chains = table.get("chains", [])

        console.print(f"[bold cyan]Table: {name}[/bold cyan]")

        if not chains:
            console.print("  [dim]No chains.[/dim]\n")
            continue

        for chain in chains:
            chain_name = chain.get("name", "?")
            chain_rules = chain.get("rules", [])

            console.print(
                f"  [bold]{chain_name}[/bold]  "
                f"({len(chain_rules)} rules)"
            )

            for rule in chain_rules[:5]:
                console.print(f"    [dim]{rule}[/dim]")

            if len(chain_rules) > 5:
                console.print(
                    f"    [dim]... and {len(chain_rules) - 5} more[/dim]"
                )

        console.print()


def _print_iptables(rules: dict) -> None:
    """Приказује iptables chains."""
    for family in ("ipv4", "ipv6"):
        fam_data = rules.get(family, {})

        if not fam_data.get("available"):
            continue

        chains = fam_data.get("chains", {})

        if not chains:
            continue

        family_label = "IPv4" if family == "ipv4" else "IPv6"
        console.print(f"[bold cyan]{family_label}[/bold cyan]\n")

        for chain_name, chain in chains.items():
            policy = chain.get("policy", "")
            chain_rules = chain.get("rules", [])

            policy_display = f" (policy: {policy})" if policy else ""

            console.print(
                f"  [bold]{chain_name}[/bold]{policy_display}  "
                f"({len(chain_rules)} rules)"
            )

            for rule in chain_rules[:5]:
                console.print(f"    [dim]{rule}[/dim]")

            if len(chain_rules) > 5:
                console.print(
                    f"    [dim]... and {len(chain_rules) - 5} more[/dim]"
                )

        console.print()