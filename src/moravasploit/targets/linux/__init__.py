# Модул за Linux систем.
# Садржи мени категорија и, касније, логику за избор модула.
from rich.console import Console
from rich.prompt import Prompt

# Глобални објекат конзоле за испис у терминалу.
console = Console()

# Речник категорија модула за Linux.
# Свака категорија одговара подфолдеру у targets/linux/.
CATEGORIES = {
    "1": "recon",
    "2": "exploits",
    "3": "post",
    "4": "payloads",
}


def menu() -> str | None:
    """Приказује мени категорија за Linux и враћа избор.

    Враћа:
        Име изабране категорије или None ако је корисник изабрао повратак.
    """
    # Исписујемо наслов менија.
    console.print("\n[bold]Linux - choose category:[/bold]\n")

    # Пролазимо кроз све категорије и исписујемо их са редним бројем.
    for key, name in CATEGORIES.items():
        console.print(f"  [{key}] {name}")

    # Додајемо опцију за повратак на избор система.
    console.print("  [0] Back\n")

    # Тражимо избор од корисника.
    # Дозвољени уноси су 1-4 и 0.
    choice = Prompt.ask(
        ">",
        choices=list(CATEGORIES.keys()) + ["0"],
        default="0",
    )

    # Ако је изабрао 0, враћамо None.
    if choice == "0":
        return None

    # Иначе враћамо име категорије.
    return CATEGORIES[choice]