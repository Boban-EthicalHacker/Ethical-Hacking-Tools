# Модул за статичку анализу IPA фајлова.
from rich.console import Console

from moravasploit.core.menu import ask_choice
from moravasploit.targets.ios.recon.static import ipa_info

console = Console()

# Речник модула у static грани.
MODULES: dict[str, tuple[str, object]] = {
    "1": ("ipa_info", ipa_info.run),
}


def menu() -> None:
    """Приказује мени модула за статичку анализу IPA фајлова."""
    while True:
        console.print("\n[bold]iOS / recon / static - choose module:[/bold]\n")

        for key, (name, _) in MODULES.items():
            console.print(f"  [{key}] {name}")

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]")

        choice = ask_choice(list(MODULES.keys()))

        if choice is None:
            return

        _, run_function = MODULES[choice]
        run_function()