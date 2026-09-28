# Модул за Linux / recon / system категорију.
# Приказује модуле за основне информације о систему.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.targets.linux.recon.system import kernel_info, system_info

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "system_info": ("System information", system_info.run),
    "kernel_info": ("Kernel information", kernel_info.run),
}


def menu() -> None:
    """Приказује мени модула за system категорију."""
    while True:
        console.print("\n[bold]Linux / recon / system - choose module:[/bold]\n")

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