# Модул за статичку анализу APK фајлова.
from rich.console import Console

from moravasploit.core.menu import ask_choice
from moravasploit.targets.android.recon.static import (
    apk_info,
    exported,
    permissions,
)

console = Console()

# Речник модула у static грани.
MODULES: dict[str, tuple[str, object]] = {
    "1": ("apk_info", apk_info.run),
    "2": ("permissions", permissions.run),
    "3": ("exported", exported.run),
}


def menu() -> None:
    """Приказује мени модула за статичку анализу APK фајлова."""
    while True:
        console.print("\n[bold]Android / recon / static - choose module:[/bold]\n")

        for key, (name, _) in MODULES.items():
            console.print(f"  [{key}] {name}")

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]")

        choice = ask_choice(list(MODULES.keys()))

        if choice is None:
            return

        _, run_function = MODULES[choice]
        run_function()