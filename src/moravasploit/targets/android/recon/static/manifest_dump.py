# Модул за приказ целог AndroidManifest.xml у читљивом облику.
# Манифест је у APK-у у бинарном формату, овај модул га
# претвара у обичан XML и приказује га.
import zipfile

from lxml import etree
from pyaxmlparser.axmlprinter import AXMLPrinter
from rich.console import Console
from rich.syntax import Syntax

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()


def run() -> None:
    """Приказује цео AndroidManifest.xml."""
    result = load_apk()
    if result is None:
        return

    apk_path, _ = result

    console.print("\n[bold cyan]AndroidManifest.xml[/bold cyan]\n")

    # Извлачимо манифест из APK-а (APK је ZIP архива).
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            manifest_bytes = z.read("AndroidManifest.xml")
    except KeyError:
        console.print("[red]AndroidManifest.xml not found in APK.[/red]\n")
        return
    except Exception as error:
        console.print(f"[red]Failed to read manifest:[/red] {error}\n")
        return

    # Претварамо бинарни манифест у читљив XML.
    try:
        printer = AXMLPrinter(manifest_bytes)
        xml_bytes = printer.get_xml()
    except Exception as error:
        console.print(f"[red]Failed to parse manifest:[/red] {error}\n")
        return

    # Претварамо у дрво и поново у стринг, овога пута
    # лепо увучено (pretty-print).
    try:
        root = etree.fromstring(xml_bytes)
        pretty = etree.tostring(
            root, pretty_print=True, encoding="unicode"
        )
    except Exception as error:
        console.print(f"[red]Failed to format manifest:[/red] {error}\n")
        return

    # Приказујемо са синтаксним истицањем XML-а.
    syntax = Syntax(
        pretty,
        "xml",
        theme="monokai",
        line_numbers=True,
        word_wrap=True,
    )
    console.print(syntax)
    console.print()