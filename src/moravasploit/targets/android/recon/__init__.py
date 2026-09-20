# Модул за Android / recon категорију.
# Приказује подмени за избор извора анализе.
from rich.console import Console
from rich.prompt import Prompt

# Увозимо подменије за static и live гране.
from moravasploit.targets.android.recon.static import menu as static_menu
from moravasploit.targets.android.recon.live import menu as live_menu

# Глобални објекат конзоле за испис у терминалу.
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
    """Приказује мени извора анализе за Android / recon."""
    while True:
        console.print("\n[bold]Android / recon - choose source:[/bold]\n")

        console.print("  [1] Static APK analysis      (file only, no device)")
        console.print("  [2] Live device analysis     (via ADB)")

        console.print("  [0] Back\n")

        choice = Prompt.ask(
            ">",
            choices=list(SOURCES.keys()) + ["0"],
            default="0",
        )

        # Ако је изабрао повратак, излазимо из петље.
        if choice == "0":
            return

        # Узимамо име извора и позивамо његов мени.
        source = SOURCES[choice]
        SOURCE_MENUS[source]()