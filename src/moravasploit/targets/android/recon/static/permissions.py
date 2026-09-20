# Модул за приказ дозвола које APK тражи.
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()


def run() -> None:
    """Приказује све дозволе које апликација тражи."""
    result = load_apk()
    if result is None:
        return

    _, apk = result

    # Узимамо листу дозвола из манифеста.
    permissions = apk.get_permissions()

    console.print("\n[bold cyan]Permissions[/bold cyan]\n")

    if not permissions:
        console.print("  [dim]No permissions requested.[/dim]\n")
        return

    console.print(f"Total: [bold]{len(permissions)}[/bold]\n")

    # Приказујемо дозволе сортиране по азбуци.
    for perm in sorted(permissions):
        console.print(f"  {perm}")

    console.print()