# Модул за iOS / recon категорију.
# Приказује подмени за избор извора анализе.
from rich.console import Console

from moravasploit.core.menu import ask_choice
from moravasploit.targets.ios.recon.static import menu as static_menu
from moravasploit.targets.ios.recon.live import menu as live_menu

console = Console()

# Речник подкатегорија унутар recon-а.
SOURCES = {
    "1": "static",
    "2": "live",
}

# Речник који повезује извор са његовом menu() функцијом.
SOURCE_MENUS = {
    "static": static_menu,
    "live": live_menu,
}


def menu() -> None:
    """Приказује мени извора анализе за iOS / recon."""
    while True:
        console.print("\n[bold]iOS / recon - choose source:[/bold]\n")

        console.print("  [1] Static IPA analysis      (file only, no device)")
        console.print("  [2] Live device analysis     (via tools)")

        choice = ask_choice(list(SOURCES.keys()))

        if choice is None:
            return

        source = SOURCES[choice]
        SOURCE_MENUS[source]()