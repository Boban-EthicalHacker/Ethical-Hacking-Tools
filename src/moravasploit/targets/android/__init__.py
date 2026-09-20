# Модул за Android систем.
# Садржи мени категорија за Android.
from rich.console import Console
from rich.prompt import Prompt

# Увозимо подмени за recon категорију.
from moravasploit.targets.android.recon import menu as recon_menu

# Глобални објекат конзоле за испис у терминалу.
console = Console()

# Речник категорија модула за Android.
CATEGORIES = {
    "1": "recon",
    "2": "exploits",
    "3": "post",
    "4": "payloads",
}

# Речник који повезује категорију са њеном menu() функцијом.
# За сада само recon има подмени. Остале категорије су празне.
CATEGORY_MENUS = {
    "recon": recon_menu,
}


def menu() -> None:
    """Приказује мени категорија за Android."""
    # Петља која омогућава повратак на овај мени.
    while True:
        # Исписујемо наслов менија.
        console.print("\n[bold]Android - choose category:[/bold]\n")

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

        # Ако је изабрао повратак, излазимо из петље.
        if choice == "0":
            return

        # Узимамо име изабране категорије.
        category = CATEGORIES[choice]

        # Ако категорија има подмени, приказујемо га.
        submenu = CATEGORY_MENUS.get(category)

        if submenu is not None:
            submenu()
            # Након повратка из подменија, петља се наставља
            # и поново приказује овај мени.
        else:
            # За категорије без подменија, само исписујемо поруку.
            console.print(
                f"\n[bold green]You chose: {category}[/bold green]\n"
            )