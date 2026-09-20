# Први модул у Android / recon / static грани.
# Чита APK фајл и приказује основне информације из манифеста.
# Не захтева уређај, ни root, ни ADB.
from pathlib import Path

from pyaxmlparser import APK
from rich.console import Console

# Глобални објекат конзоле за испис.
console = Console()


def run() -> None:
    """Покреће анализу APK фајла."""
    # Тражимо од корисника путању до APK фајла.
    console.print("\n[bold]Enter path to APK file:[/bold]")
    raw_path = console.input("> ").strip()

    # Уклањамо наводнике ако их је корисник ставио.
    raw_path = raw_path.strip("'\"")

    # Претварамо у Path објекат ради лакше провере.
    apk_path = Path(raw_path).expanduser()

    # Проверавамо да ли фајл постоји.
    if not apk_path.exists():
        console.print(f"\n[red]File not found:[/red] {apk_path}\n")
        return

    # Проверавамо да ли је фајл, не фолдер.
    if not apk_path.is_file():
        console.print(f"\n[red]Not a file:[/red] {apk_path}\n")
        return

    # Проверавамо да ли има .apk екстензију.
    if apk_path.suffix.lower() != ".apk":
        console.print(
            f"\n[yellow]Warning:[/yellow] file does not have .apk extension.\n"
        )

    # Учитавамо APK. Ако пукне, приказујемо грешку.
    try:
        apk = APK(str(apk_path))
    except Exception as error:
        console.print(f"\n[red]Failed to parse APK:[/red] {error}\n")
        return

    # Приказујемо основне информације.
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
        backup_value = True  # подразумевано у Android-у
    elif isinstance(backup_value, str):
        backup_value = backup_value.lower() == "true"

    console.print(f"[bold]Debuggable:[/bold]    {debug_value}")
    console.print(f"[bold]Allow backup:[/bold]  {backup_value}")

    console.print()