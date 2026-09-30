# Модул за Linux / recon / services категорију.
# Приказује модуле за сервисе и процесе.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.services import (
    cron_jobs,
    processes,
    services,
    sockets,
    startup_scripts,
    timers,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "services": ("Systemd services", services.run),
    "processes": ("Running processes", processes.run),
    "cron_jobs": ("Cron jobs", cron_jobs.run),
    "timers": ("Systemd timers", timers.run),
    "startup_scripts": ("Startup scripts", startup_scripts.run),
    "sockets": ("Systemd sockets", sockets.run),
}


def menu() -> None:
    """Приказује мени модула за services категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / services - choose module:[/bold]\n"
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