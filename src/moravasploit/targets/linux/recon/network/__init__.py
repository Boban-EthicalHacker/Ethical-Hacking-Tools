# Модул за Linux / recon / network категорију.
# Приказује модуле за мрежну конфигурацију.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.network import (
    arp_table,
    dns_config,
    firewall_rules,
    listening_services,
    network_info,
    open_ports,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "network_info": ("Network information", network_info.run),
    "open_ports": ("Open ports", open_ports.run),
    "listening_services": ("Listening services", listening_services.run),
    "firewall_rules": ("Firewall rules", firewall_rules.run),
    "dns_config": ("DNS configuration", dns_config.run),
    "arp_table": ("ARP table", arp_table.run),
}


def menu() -> None:
    """Приказује мени модула за network категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / network - choose module:[/bold]\n"
        )

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]\n")
            choice = ask_select([])
            if choice is None:
                return
            continue

        options = [
            (key, description) for key, (description, _) in MODULES.items()
        ]
        choice = ask_select(options)

        if choice is None:
            return

        _, run_function = MODULES[choice]
        result = run_function()
        saved_path = save(choice, result)

        if saved_path is not None:
            console.print(f"[dim]Saved to: {saved_path}[/dim]")