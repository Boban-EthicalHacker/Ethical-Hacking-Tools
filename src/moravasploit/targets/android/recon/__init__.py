# Модул за Android / recon категорију.
# Приказује подмени за избор извора анализе.
from rich.console import Console

from moravasploit.core.menu import ask_choice

from moravasploit.targets.android.recon.static import menu as static_menu
from moravasploit.targets.android.recon.live import menu as live_menu

console = Console()

SOURCES = {
    "1": "static",
    "2": "live",
}

SOURCE_MENUS = {
    "static": static_menu,
    "live": live_menu,
}


def menu() -> None:
    """Приказује мени извора анализе за Android / recon."""
    while True:
        console.print("\n[bold]Android / recon - choose source:[/bold]\n")

        console.print("  [1] Static APK analysis      (file only, no device)")
        console.print("  [2] Live device analysis     (via ADB)")

        choice = ask_choice(list(SOURCES.keys()))

        if choice is None:
            return

        source = SOURCES[choice]
        SOURCE_MENUS[source]()