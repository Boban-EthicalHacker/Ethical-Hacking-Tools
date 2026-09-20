# Модул за динамичку анализу Android уређаја преко ADB-а.
# За сада нема модула, само оквир менија.
from rich.console import Console
from rich.prompt import Prompt

console = Console()

# Речник модула у live грани.
# Касније ћемо овде додати праве модуле (adb_basic, ...).
MODULES: dict[str, str] = {}


def menu() -> None:
    """Приказује мени модула за динамичку анализу уређаја."""
    while True:
        console.print("\n[bold]Android / recon / live - choose module:[/bold]\n")

        # Приказујемо све доступне модуле.
        for key, name in MODULES.items():
            console.print(f"  [{key}] {name}")

        # Ако нема модула, приказујемо поруку.
        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]")

        console.print("  [0] Back\n")

        # Тражимо избор.
        choices = list(MODULES.keys()) + ["0"]
        choice = Prompt.ask(">", choices=choices, default="0")

        # Ако је изабрао повратак, излазимо.
        if choice == "0":
            return