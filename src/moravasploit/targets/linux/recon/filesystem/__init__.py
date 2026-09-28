# Модул за Linux / recon / filesystem категорију.
# Приказује модуле за фајлове, дозволе и специјалне битове.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.targets.linux.recon.filesystem import suid_sgid

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "suid_sgid": ("SUID / SGID files", suid_sgid.run),
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
        run_function()