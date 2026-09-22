# Помоћне функције за учитавање IPA фајла.
# Користе их сви модули у iOS static грани.
import plistlib
import zipfile
from pathlib import Path

from rich.console import Console

console = Console()


def load_ipa() -> tuple[Path, dict, str] | None:
    """Пита корисника за путању до IPA фајла и учитава га.

    Враћа:
        Tuple (path, info_plist_dict, app_name) ако је учитавање
        успело, иначе None.
    """
    while True:
        console.print("\n[bold]Enter path to IPA file (or 'back'):[/bold]")
        raw_path = console.input("> ").strip().strip("'\"")

        # Ако је корисник укуцао 'back', враћамо се на мени.
        if raw_path.lower() == "back":
            return None

        ipa_path = Path(raw_path).expanduser()

        # Проверавамо да ли фајл постоји.
        if not ipa_path.exists():
            console.print(f"\n[red]File not found:[/red] {ipa_path}")
            continue

        # Проверавамо да ли је фајл, не фолдер.
        if not ipa_path.is_file():
            console.print(f"\n[red]Not a file:[/red] {ipa_path}")
            continue

        # Отварамо IPA као ZIP и учитавамо Info.plist.
        try:
            with zipfile.ZipFile(str(ipa_path), "r") as z:
                app_dir = _find_app_dir(z)

                if app_dir is None:
                    console.print(
                        "\n[red]No .app folder found in Payload/.[/red]"
                    )
                    continue

                # Име апликације без .app екстензије.
                app_name = app_dir.rstrip("/").split("/")[-1]
                if app_name.endswith(".app"):
                    app_name = app_name[:-4]

                # Читамо Info.plist.
                plist_path = f"{app_dir}Info.plist"

                try:
                    plist_data = z.read(plist_path)
                except KeyError:
                    console.print(
                        f"\n[red]Info.plist not found at {plist_path}.[/red]"
                    )
                    continue

                # plistlib уме да чита и бинарне и XML plist фајлове.
                info = plistlib.loads(plist_data)

        except zipfile.BadZipFile:
            console.print(
                f"\n[red]Not a valid IPA (ZIP) file:[/red] {ipa_path}"
            )
            continue
        except Exception as error:
            console.print(f"\n[red]Failed to read IPA:[/red] {error}")
            continue

        return ipa_path, info, app_name


def _find_app_dir(zip_file) -> str | None:
    """Проналази .app фолдер у Payload/ делу IPA фајла.

    Враћа путању до .app фолдера (са завршном косом цртом),
    или None ако није пронађен.
    """
    app_dirs = set()

    for name in zip_file.namelist():
        if not name.startswith("Payload/"):
            continue

        # Тражимо .app/ у путањи.
        if ".app/" not in name:
            continue

        # Извлачимо путању до .app фолдера.
        # На пример, од "Payload/CTFApp.app/Info.plist"
        # добијамо "Payload/CTFApp.app/".
        parts = name.split("/")
        if len(parts) >= 2:
            app_dirs.add(f"{parts[0]}/{parts[1]}/")

    if not app_dirs:
        return None

    # Узимамо први (обично постоји само један).
    return sorted(app_dirs)[0]