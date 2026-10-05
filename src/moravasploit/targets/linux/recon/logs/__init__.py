# Модул за Linux / recon / logs категорију.
# Приказује модуле за анализу логова.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.logs import (
    app_logs,
    audit_logs,
    auth_logs,
    journal,
    kernel_logs,
    system_logs,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "auth_logs": ("Authentication logs", auth_logs.run),
    "system_logs": ("System logs", system_logs.run),
    "journal": ("Systemd journal", journal.run),
    "app_logs": ("Application logs", app_logs.run),
    "kernel_logs": ("Kernel logs", kernel_logs.run),
    "audit_logs": ("Audit logs", audit_logs.run),
}


def menu() -> None:
    """Приказује мени модула за logs категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / logs - choose module:[/bold]\n"
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