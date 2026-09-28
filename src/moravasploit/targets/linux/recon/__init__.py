# Модул за Linux / recon категорију.
# Приказује мени модула за извиђање Linux система.
from rich.console import Console

from moravasploit.core.menu import ask_select

# Увозимо модуле.
from moravasploit.targets.linux.recon import system_info

# Глобални објекат конзоле за испис у терминалу.
console = Console()

# Речник модула у recon грани.
# Кључ је интерно име, вредност је (опис, funkcija).
MODULES: dict[str, tuple[str, object]] = {
    "system_info": ("System information", system_info.run),
}


def menu() -> None:
    """Приказује мени модула за Linux / recon."""
    while True:
        console.print("\n[bold]Linux / recon - choose module:[/bold]\n")

        # Ако нема модула, приказујемо поруку.
        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]\n")

            choice = ask_select([])
            if choice is None:
                return
            continue

        # Припремамо листу (кључ, опис) за ask_select.
        options = [
            (key, description) for key, (description, _) in MODULES.items()
        ]

        # Питамо корисника.
        choice = ask_select(options)

        # Ако је изабрао 'back', враћамо се на категорије.
        if choice is None:
            return

        # Покрећемо изабрани модул.
        _, run_function = MODULES[choice]
        run_function()