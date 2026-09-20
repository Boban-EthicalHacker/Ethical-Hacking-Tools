# Модул за динамичку анализу Android уређаја преко ADB-а.
from rich.console import Console

from moravasploit.core.menu import ask_choice

console = Console()

# Речник модула у live грани. За сада празан.
MODULES: dict[str, tuple[str, object]] = {}


def menu() -> None:
    """Приказује мени модула за динамичку анализу уређаја."""
    while True:
        console.print("\n[bold]Android / recon / live - choose module:[/bold]\n")

        for key, (name, _) in MODULES.items():
            console.print(f"  [{key}] {name}")

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]")

        # Ако нема ниједан модул, не дозвољавамо избор,
        # само приказујемо мени и тражимо back/exit.
        if not MODULES:
            choice = ask_choice([])
            if choice is None:
                return
            continue

        choice = ask_choice(list(MODULES.keys()))

        if choice is None:
            return

        _, run_function = MODULES[choice]
        run_function()