# Увоз потребних библиотека и модула.
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

# Увозимо број верзије из главног пакета.
from moravasploit import __version__

# Увозимо меније за све подржане системе.
# Главни програм тако остаје кратак и не зна детаље ниједног менија.
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
# Ово нам омогућава да избегнемо понављање истог кода за сваки систем.
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


def choose_system() -> str | None:
    """Приказује мени и враћа име изабраног система или None."""
    console.print("\n[bold]Choose target system:[/bold]\n")
    for key, name in SYSTEMS.items():
        console.print(f"  [{key}] {name}")
    console.print("  [0] Exit\n")

    choice = Prompt.ask(
        ">",
        choices=list(SYSTEMS.keys()) + ["0"],
        default="0",
    )

    if choice == "0":
        return None
    return SYSTEMS[choice]


def main() -> None:
    """Главна улазна тачка програма."""
    # Прво приказујемо уводну поруку.
    show_welcome()

    # Главна петља програма. Врти се све док корисник не изабере излаз.
    while True:
        # Тражимо од корисника да изабере систем.
        system = choose_system()

        # Ако је изабрао 0 на главном менију, излазимо из програма.
        if system is None:
            console.print("\n[dim]Goodbye.[/dim]")
            return

        # Исписујемо поруку добродошлице за изабрани систем.
        console.print(
            f"\n[bold green]Welcome to security study of "
            f"{system} systems.[/bold green]"
        )

        # Проналазимо одговарајућу menu() функцију за изабрани систем.
        menu_function = SYSTEM_MENUS.get(system)

        # Приказујемо мени категорија за изабрани систем.
        category = menu_function()

        # Ако је корисник изабрао назад, враћамо се на избор система.
        if category is None:
            continue

        # За сада само исписујемо шта је изабрано.
        # У следећем кораку ћемо ово повезати са правим модулима.
        console.print(f"\n[bold green]You chose: {category}[/bold green]\n")