# Модул за Linux систем.
# Садржи мени категорија за Linux.
from rich.console import Console

# Увозимо помоћну функцију за избор са стрелицама.
from moravasploit.core.menu import ask_select

# Увозимо функције за управљање сесијом.
from moravasploit.core.session import end_session, start_session

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
    # Покрећемо нову сесију чим уђемо у Linux.
    session_path = start_session("linux")

    # Приказујемо кориснику где се чувају резултати.
    console.print(
        f"\n[dim]Session started: {session_path}[/dim]"
    )

    try:
        # Главна петља Linux менија.
        while True:
            console.print("\n[bold]Linux - choose category:[/bold]\n")

            # Припремамо листу (кључ, опис) за ask_select.
            options = [
                (key, name) for key, name in CATEGORIES.items()
            ]

            # Питамо корисника.
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
    finally:
        # Кад корисник изађе из Linux менија, завршавамо сесију.
        # finally блок се извршава и ако дође до грешке или
        # ако корисник притисне Ctrl+C.
        end_session()