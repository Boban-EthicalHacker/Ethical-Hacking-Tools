# Модул за Linux / recon / software категорију.
# Приказује модуле за инсталирани софтвер.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.software import (
    compilers,
    docker,
    installed_packages,
    language_packages,
    outdated_packages,
    suid_interpreters,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "installed_packages": ("Installed packages", installed_packages.run),
    "outdated_packages": ("Outdated packages", outdated_packages.run),
    "docker": ("Docker resources", docker.run),
    "compilers": ("Compilers and interpreters", compilers.run),
    "suid_interpreters": ("SUID interpreters", suid_interpreters.run),
    "language_packages": ("Language packages", language_packages.run),
}


def menu() -> None:
    """Приказује мени модула за software категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / software - choose module:[/bold]\n"
        )

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]\n")
            choice = ask_select([])
            if choice is None:
                return
            continue

        options = [
            (key, description) for key, (description, _) in MODULES.items()
        ]
        choice = ask_select(options)

        if choice is None:
            return

        _, run_function = MODULES[choice]
        result = run_function()
        saved_path = save(choice, result)

        if saved_path is not None:
            console.print(f"[dim]Saved to: {saved_path}[/dim]")