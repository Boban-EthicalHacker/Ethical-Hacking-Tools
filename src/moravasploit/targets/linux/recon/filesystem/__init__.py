# Модул за Linux / recon / filesystem категорију.
# Приказује модуле за фајлове, дозволе и специјалне битове.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.filesystem import (
    capabilities,
    suid_sgid,
    world_writable,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "suid_sgid": ("SUID / SGID files", suid_sgid.run),
    "capabilities": ("Linux capabilities", capabilities.run),
    "world_writable": ("World-writable files", world_writable.run),
}


def menu() -> None:
    """Приказује мени модула за filesystem категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / filesystem - choose module:[/bold]\n"
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