# Модул за статичку анализу APK фајлова.
# Приказује мени модула и позива изабрани модул.
from rich.console import Console
from rich.prompt import Prompt

# Увозимо модул apk_info.
# Овде ћемо касније додавати још модула.
from moravasploit.targets.android.recon.static import apk_info

console = Console()

# Речник модула у static грани.
# Кључ је редни број у менију, вредност је (име, функција).
MODULES: dict[str, tuple[str, object]] = {
    "1": ("apk_info", apk_info.run),
}


def menu() -> None:
    """Приказује мени модула за статичку анализу APK фајлова."""
    while True:
        console.print("\n[bold]Android / recon / static - choose module:[/bold]\n")

        # Приказујемо све доступне модуле.
        for key, (name, _) in MODULES.items():
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

        # Узимамо функцију изабраног модула и позивамо је.
        _, run_function = MODULES[choice]
        run_function()