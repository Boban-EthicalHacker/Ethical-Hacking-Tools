# Модул за Linux / recon / users категорију.
# Приказује модуле за кориснике, групе и привилегије.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.users import users_groups

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "users_groups": ("Users and groups", users_groups.run),
}


def menu() -> None:
    """Приказује мени модула за users категорију."""
    while True:
        console.print("\n[bold]Linux / recon / users - choose module:[/bold]\n")

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

        # Покрећемо модул.
        _, run_function = MODULES[choice]

        # Модул враћа речник са подацима.
        result = run_function()

        # Чувамо резултат у текућу сесију.
        saved_path = save(choice, result)

        if saved_path is not None:
            console.print(f"[dim]Saved to: {saved_path}[/dim]")