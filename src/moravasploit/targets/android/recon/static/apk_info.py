# Модул за приказ основних информација из APK фајла.
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()


def run() -> None:
    """Приказује основне информације из APK фајла."""
    result = load_apk()
    if result is None:
        return

    apk_path, apk = result

    console.print("\n[bold cyan]APK information[/bold cyan]\n")

    console.print(f"[bold]File:[/bold]          {apk_path.name}")
    console.print(f"[bold]Package name:[/bold]  {apk.package}")
    console.print(f"[bold]App name:[/bold]      {apk.application}")
    console.print(f"[bold]Version name:[/bold]  {apk.version_name}")
    console.print(f"[bold]Version code:[/bold]  {apk.version_code}")

    # Читамо debug статус. Ако није наведен, подразумевано је False.
    debug_value = apk.get_attribute_value("application", "debuggable")
    if debug_value is None:
        debug_value = False

    # Читамо allow backup. pyaxmlparser враћа стринг, претварамо у bool.
    backup_value = apk.get_attribute_value("application", "allowBackup")
    if backup_value is None:
        backup_value = True
    elif isinstance(backup_value, str):
        backup_value = backup_value.lower() == "true"

    console.print(f"[bold]Debuggable:[/bold]    {debug_value}")
    console.print(f"[bold]Allow backup:[/bold]  {backup_value}")

    console.print()