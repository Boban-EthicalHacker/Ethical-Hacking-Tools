# Модул за приказ извезених компоненти из APK манифеста.
# Извезене компоненте су оне које су доступне другим апликацијама.
# Ово је чест извор безбедносних проблема.
import zipfile

from lxml import etree
from pyaxmlparser.axmlprinter import AXMLPrinter
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Андроид namespace за атрибуте у манифесту.
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def run() -> None:
    """Приказује извезене компоненте из APK манифеста."""
    result = load_apk()
    if result is None:
        return

    apk_path, _ = result

    # Извлачимо AndroidManifest.xml из APK-а (APK је ZIP архива).
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            manifest_bytes = z.read("AndroidManifest.xml")
    except Exception as error:
        console.print(f"\n[red]Failed to read manifest:[/red] {error}\n")
        return

    # Претварамо бинарни манифест у читљив XML.
    try:
        printer = AXMLPrinter(manifest_bytes)
        xml_bytes = printer.get_xml()
        root = etree.fromstring(xml_bytes)
    except Exception as error:
        console.print(f"\n[red]Failed to parse manifest:[/red] {error}\n")
        return

    console.print("\n[bold cyan]Exported components[/bold cyan]\n")

    # Елемент application садржи све компоненте.
    application = root.find("application")
    if application is None:
        console.print("  [red]No application element in manifest.[/red]\n")
        return

    # Типови компоненти које нас занимају.
    tags = ("activity", "activity-alias", "service", "receiver", "provider")

    # Бројимо укупно приказаних компоненти.
    total = 0

    for tag in tags:
        total += _print_components(tag, application.findall(tag))

    if total == 0:
        console.print("  [dim]No exported components found.[/dim]\n")
    else:
        console.print(f"[bold]Total exported:[/bold] {total}\n")


def _print_components(tag: str, components: list) -> int:
    """Приказује извезене компоненте једног типа.

    Враћа број приказаних компоненти.
    """
    if not components:
        return 0

    # Филтрирамо само извезене компоненте.
    exported = []

    for comp in components:
        # Име компоненте.
        name = comp.get(f"{{{ANDROID_NS}}}name", "(no name)")

        # Експлицитни exported атрибут.
        exported_attr = comp.get(f"{{{ANDROID_NS}}}exported")

        # Да ли компонента има intent-filter.
        has_filter = comp.find("intent-filter") is not None

        # Компонента је извезена ако:
        # - експлицитно пише exported="true"
        # - или није наведено, али има intent-filter (старо понашање)
        is_exported = (
            exported_attr == "true"
            or (exported_attr is None and has_filter)
        )

        if is_exported:
            # Тип извезе: експлицитан или имплицитан.
            kind = "explicit" if exported_attr == "true" else "implicit"
            exported.append((name, kind))

    if not exported:
        return 0

    console.print(f"[bold]{tag}[/bold] ({len(exported)})")

    for name, kind in exported:
        # Експлицитно извезено је опасније, приказујемо црвено.
        # Двострука обратна коса црта спречава rich да interpreтира
        # [explicit] и [implicit] као markup тагове.
        if kind == "explicit":
            marker = "[bold red]\\[explicit][/bold red]"
        else:
            marker = "[yellow]\\[implicit][/yellow]"
        console.print(f"  {marker}  {name}")

    console.print()
    return len(exported)