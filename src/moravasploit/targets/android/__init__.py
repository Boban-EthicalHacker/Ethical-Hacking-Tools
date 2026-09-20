# Модул за Android систем.
# Садржи мени категорија за Android.
from rich.console import Console

# Увозимо помоћну функцију за избор.
from moravasploit.core.menu import ask_choice

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
CATEGORY_MENUS = {
    "recon": recon_menu,
}


def menu() -> None:
    """Приказује мени категорија за Android."""
    while True:
        console.print("\n[bold]Android - choose category:[/bold]\n")

        for key, name in CATEGORIES.items():
            console.print(f"  [{key}] {name}")

        # Питамо корисника. 'back' и 'exit' су аутоматски доступни.
        choice = ask_choice(list(CATEGORIES.keys()))

        # Ако је изабрао 'back', враћамо се на главни мени.
        if choice is None:
            return

        category = CATEGORIES[choice]
        submenu = CATEGORY_MENUS.get(category)

        if submenu is not None:
            submenu()
        else:
            console.print(
                f"\n[bold green]You chose: {category}[/bold green]\n"
            )