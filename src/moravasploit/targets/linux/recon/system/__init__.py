# Модул за Linux / recon / system категорију.
# Приказује модуле за основне информације о систему.
from rich.console import Console

from moravasploit.core.menu import ask_select

# Увозимо функцију за чување резултата у сесију.
from moravasploit.core.session import save

from moravasploit.targets.linux.recon.system import (
    boot_info,
    environment,
    hardware_info,
    kernel_info,
    system_info,
    time_info,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "system_info": ("System information", system_info.run),
    "kernel_info": ("Kernel information", kernel_info.run),
    "hardware_info": ("Hardware information", hardware_info.run),
    "boot_info": ("Boot information", boot_info.run),
    "environment": ("Environment variables", environment.run),
    "time_info": ("Time information", time_info.run),
}


def menu() -> None:
    """Приказује мени модула за system категорију."""
    while True:
        console.print("\n[bold]Linux / recon / system - choose module:[/bold]\n")

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

        # Покрећемо модул.
        _, run_function = MODULES[choice]

        # Модул враћа речник са подацима.
        result = run_function()

        # Чувамо резултат у текућу сесију.
        saved_path = save(choice, result)

        if saved_path is not None:
            console.print(f"[dim]Saved to: {saved_path}[/dim]")