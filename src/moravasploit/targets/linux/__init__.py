# Модул за Linux систем.
# Садржи мени категорија за Linux.
from rich.console import Console

# Увозимо помоћну функцију за избор са стрелицама.
from moravasploit.core.menu import ask_select

# Увозимо подмени за recon категорију.
from moravasploit.targets.linux.recon import menu as recon_menu

# Глобални објекат конзоле за испис у терминалу.
console = Console()

# Речник категорија модула за Linux.
CATEGORIES = {
    "recon": "Reconnaissance",
    "exploits": "Exploits",
    "post": "Post-exploitation",
    "payloads": "Payloads",
}

# Речник који повезује категорију са њеном menu() функцијом.
CATEGORY_MENUS = {
    "recon": recon_menu,
}


def menu() -> None:
    """Приказује мени категорија за Linux."""
    while True:
        console.print("\n[bold]Linux - choose category:[/bold]\n")

        # Припремамо листу (кључ, опис) за ask_select.
        options = [
            (key, name) for key, name in CATEGORIES.items()
        ]

        # Питамо корисника. 'back' и 'exit' су аутоматски додати.
        choice = ask_select(options)

        # Ако је изабрао 'back', враћамо се на главни мени.
        if choice is None:
            return

        # Проналазимо подмени ако постоји.
        submenu = CATEGORY_MENUS.get(choice)

        if submenu is not None:
            submenu()
        else:
            console.print(
                f"\n[bold green]You chose: {choice}[/bold green]\n"
            )