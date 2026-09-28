# Модул за приказ целог Info.plist у читљивом облику.
# Info.plist је главни метаподаци iOS апликације — садржи
# све што систем треба да зна о апликацији.
import plistlib

from rich.console import Console
from rich.syntax import Syntax

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()


def run() -> None:
    """Приказује цео Info.plist."""
    result = load_ipa()
    if result is None:
        return

    _, info, _ = result

    console.print("\n[bold cyan]Info.plist[/bold cyan]\n")

    # Претварамо речник назад у XML plist формат.
    # Тако добијамо леп приказ као у оригиналном фајлу.
    try:
        xml_bytes = plistlib.dumps(info, fmt=plistlib.FMT_XML)
        xml_text = xml_bytes.decode("utf-8")
    except Exception as error:
        console.print(f"[red]Failed to format plist:[/red] {error}\n")
        return

    # Приказујемо са синтаксним истицањем XML-а.
    syntax = Syntax(
        xml_text,
        "xml",
        theme="monokai",
        line_numbers=True,
        word_wrap=True,
    )
    console.print(syntax)
    console.print()