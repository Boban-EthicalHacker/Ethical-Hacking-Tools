# Помоћне функције за учитавање APK фајла.
# Користе их сви модули у static грани.
from pathlib import Path

from pyaxmlparser import APK
from rich.console import Console

console = Console()


def load_apk() -> tuple[Path, APK] | None:
    """Пита корисника за путању до APK фајла и учитава га.

    Ако је путања неисправна, пита поново. Петља се прекида
    само када је учитавање успело или када корисник укуца 'back'.

    Враћа:
        Tuple (path, apk) ако је учитавање успело, иначе None.
    """
    while True:
        console.print("\n[bold]Enter path to APK file (or 'back'):[/bold]")
        raw_path = console.input("> ").strip().strip("'\"")

        # Ако је корисник укуцао 'back', враћамо се на мени.
        if raw_path.lower() == "back":
            return None

        apk_path = Path(raw_path).expanduser()

        # Проверавамо да ли фајл постоји.
        if not apk_path.exists():
            console.print(f"\n[red]File not found:[/red] {apk_path}")
            continue

        # Проверавамо да ли је фајл, не фолдер.
        if not apk_path.is_file():
            console.print(f"\n[red]Not a file:[/red] {apk_path}")
            continue

        # Покушавамо да учитамо APK.
        try:
            apk = APK(str(apk_path))
        except Exception as error:
            console.print(f"\n[red]Failed to parse APK:[/red] {error}")
            continue

        # Ако смо стигли довде, све је у реду.
        return apk_path, apk