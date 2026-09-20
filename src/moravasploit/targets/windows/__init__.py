# Модул за Windows систем.
# Садржи мени категорија за Windows.
from rich.console import Console
from rich.prompt import Prompt

# Глобални објекат конзоле за испис у терминалу.
console = Console()

# Речник категорија модула за Windows.
CATEGORIES = {
    "1": "recon",
    "2": "exploits",
    "3": "post",
    "4": "payloads",
}


def menu() -> str | None:
    """Приказује мени категорија за Windows и враћа избор."""
    # Исписујемо наслов менија.
    console.print("\n[bold]Windows - choose category:[/bold]\n")

    # Приказујемо све категорије.
    for key, name in CATEGORIES.items():
        console.print(f"  [{key}] {name}")

    # Опција за повратак.
    console.print("  [0] Back\n")

    # Тражимо избор.
    choice = Prompt.ask(
        ">",
        choices=list(CATEGORIES.keys()) + ["0"],
        default="0",
    )

    # Ако је изабрао повратак, враћамо None.
    if choice == "0":
        return None

    # Иначе враћамо име категорије.
    return CATEGORIES[choice]