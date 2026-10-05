# Модул за Linux / recon / credentials категорију.
# Приказује модуле за проналажење креденцијала и тајни.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.credentials import (
    browser_data,
    cloud_creds,
    config_secrets,
    git_credentials,
    history_files,
    ssh_private_keys,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "ssh_private_keys": ("SSH private keys", ssh_private_keys.run),
    "history_files": ("Command history", history_files.run),
    "config_secrets": ("Config secrets", config_secrets.run),
    "cloud_creds": ("Cloud credentials", cloud_creds.run),
    "browser_data": ("Browser data", browser_data.run),
    "git_credentials": ("Git credentials", git_credentials.run),
}


def menu() -> None:
    """Приказује мени модула за credentials категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / credentials - choose module:[/bold]\n"
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