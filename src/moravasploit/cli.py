# Увоз потребних библиотека и модула.
from rich.console import Console
from rich.panel import Panel

# Увозимо број верзије из главног пакета.
from moravasploit import __version__

# Увозимо изузетак за потпуни излаз из апликације.
from moravasploit.exceptions import ExitApp

# Увозимо помоћну функцију за избор.
from moravasploit.core.menu import ask_choice

# Увозимо меније за све подржане системе.
from moravasploit.targets.linux import menu as linux_menu
from moravasploit.targets.android import menu as android_menu
from moravasploit.targets.macos import menu as macos_menu
from moravasploit.targets.windows import menu as windows_menu
from moravasploit.targets.ios import menu as ios_menu

# Правимо глобални објекат конзоле који ће се користити за испис.
console = Console()

# Речник који повезује редни број са именом система.
SYSTEMS = {
    "1": "Linux",
    "2": "macOS",
    "3": "Windows",
    "4": "Android",
    "5": "iOS",
}

# Речник који повезује име система са његовом menu() функцијом.
SYSTEM_MENUS = {
    "Linux": linux_menu,
    "macOS": macos_menu,
    "Windows": windows_menu,
    "Android": android_menu,
    "iOS": ios_menu,
}


def show_welcome() -> None:
    """Приказује уводну поруку о апликацији."""
    text = (
        f"[bold cyan]MoravaSploit[/bold cyan] v{__version__}\n\n"
        "Open-source tool for authorized security testing\n"
        "of systems and networks.\n\n"
        "[bold]License:[/bold] PolyForm Noncommercial 1.0.0\n"
        "[bold]Development started:[/bold] 2026\n\n"
        "[yellow]Use only on systems and networks you own\n"
        "or have explicit written permission to test.[/yellow]"
    )
    console.print(Panel(text, border_style="cyan", title="MoravaSploit"))


def choose_system() -> str:
    """Приказује главни мени и враћа име изабраног система.

    Подиже ExitApp ако корисник укуца 'exit'.
    """
    console.print("\n[bold]Choose target system:[/bold]\n")

    # Приказујемо све системе.
    for key, name in SYSTEMS.items():
        console.print(f"  [{key}] {name}")

    # Опција за излаз. Двострука обратна коса црта спречава
    # rich да interpreтира [exit] као markup таг.
    console.print("  \\[exit] Exit\n")

    # Питамо корисника за избор помоћу заједничке функције.
    choice = ask_choice(list(SYSTEMS.keys()))

    # Ако је враћено None, то значи 'back' — али у главном менију
    # 'back' нема смисла, па га третирамо као поновни приказ менија.
    if choice is None:
        return choose_system()

    return SYSTEMS[choice]


def main() -> None:
    """Главна улазна тачка програма."""
    # Прво приказујемо уводну поруку.
    show_welcome()

    try:
        # Главна петља програма. Врти се све док корисник не укуца 'exit'.
        while True:
            # Бирамо систем.
            system = choose_system()

            # Исписујемо поруку добродошлице за изабрани систем.
            console.print(
                f"\n[bold green]Welcome to security study of "
                f"{system} systems.[/bold green]"
            )

            # Проналазимо одговарајућу menu() функцију за изабрани систем.
            menu_function = SYSTEM_MENUS.get(system)

            # Приказујемо мени категорија за изабрани систем.
            menu_function()

    except ExitApp:
        # Хватамо сигнал за излаз и исписујемо поздрав.
        console.print("\n[dim]Goodbye.[/dim]")
        return