# Модул за израчунавање хеш отисака IPA фајла.
# MD5, SHA-1 и SHA-256 су стандардни отисци који се користе
# за проверу интегритета и поређење са познатим фајловима.
import hashlib
from pathlib import Path

from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Величина блока за читање фајла (у бајтовима).
# 64 KB је оптимално — довољно велико да буде брзо,
# довољно мало да не заузима пуно меморије.
CHUNK_SIZE = 64 * 1024


def run() -> None:
    """Израчунава и приказује хеш отиске IPA фајла."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, _ = result

    console.print("\n[bold cyan]IPA hashes[/bold cyan]\n")

    # Израчунавамо хешове.
    try:
        hashes = _calculate_hashes(ipa_path)
    except Exception as error:
        console.print(f"[red]Failed to read file:[/red] {error}\n")
        return

    # Величина фајла.
    size = ipa_path.stat().st_size

    console.print(f"[bold]File:[/bold]         {ipa_path.name}")
    console.print(f"[bold]Path:[/bold]         {ipa_path}")
    console.print(f"[bold]Size:[/bold]         {_format_size(size)}\n")

    # Приказујемо отиске.
    console.print(f"[bold]MD5:[/bold]          {hashes['md5']}")
    console.print(f"[bold]SHA-1:[/bold]        {hashes['sha1']}")
    console.print(f"[bold]SHA-256:[/bold]      {hashes['sha256']}")

    console.print()


def _calculate_hashes(path: Path) -> dict[str, str]:
    """Израчунава MD5, SHA-1 и SHA-256 хешове фајла.

    Чита фајл у блоковима да не би учитао све у меморију
    (IPA фајлови могу бити велики, преко 100 MB).
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    # Отварамо фајл у бинарном режиму.
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            # Сва три хеша добијају исти блок.
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"