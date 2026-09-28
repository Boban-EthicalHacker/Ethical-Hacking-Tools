# Модул за Linux / recon / credentials категорију.
# Тренутно празно, модули долазе касније.
from rich.console import Console

from moravasploit.core.menu import ask_select

console = Console()

MODULES: dict[str, tuple[str, object]] = {}


def menu() -> None:
    """Приказује мени модула за network категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / network - choose module:[/bold]\n"
        )
        console.print("  [dim]No modules yet.[/dim]\n")

        choice = ask_select([])
        if choice is None:
            return