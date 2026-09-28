# Модул за проверу да ли је Mach-O бинар стварно шифрован.
# Ознака "encrypted" у заглављу може бити присутна иако је
# бинар заправо дешифрован (чест случај са CTF апликацијама
# и "кракнутим" App Store апликацијама).
import zipfile

import lief
from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()


def run() -> None:
    """Проверава да ли је бинар стварно шифрован."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Encryption check[/bold cyan]\n")

    # Проналазимо бинар.
    binary_path = _find_binary_path(ipa_path, app_name)
    if binary_path is None:
        console.print("[red]Binary not found in .app folder.[/red]\n")
        return

    # Читамо бинар као бајтове.
    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            binary_data = z.read(binary_path)
    except Exception as error:
        console.print(f"[red]Failed to read binary:[/red] {error}\n")
        return

    # Парсирамо Mach-O.
    try:
        fat = lief.MachO.parse(binary_data)
    except Exception as error:
        console.print(f"[red]Failed to parse Mach-O:[/red] {error}\n")
        return

    if fat is None:
        console.print("[red]Not a valid Mach-O binary.[/red]\n")
        return

    # Узимамо листу бинара (архитектура).
    try:
        binaries = list(fat)
    except TypeError:
        binaries = [fat]

    for i, binary in enumerate(binaries, start=1):
        _check_binary(i, binary)

    console.print()


def _find_binary_path(ipa_path, app_name: str) -> str | None:
    """Проналази путању до главног бинара у IPA фајлу."""
    expected = f"Payload/{app_name}.app/{app_name}"

    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            names = z.namelist()

            if expected in names:
                return expected

            # Резервна претрага.
            app_prefix = f"Payload/{app_name}.app/"
            for name in names:
                if not name.startswith(app_prefix):
                    continue

                rel = name[len(app_prefix):]
                if "/" in rel:
                    continue

                if rel.endswith((
                    ".png", ".jpg", ".jpeg", ".plist", ".json",
                    ".html", ".css", ".js", ".car",
                )):
                    continue

                if rel == "PkgInfo":
                    continue

                return name
    except Exception:
        return None

    return None


def _check_binary(index: int, binary) -> None:
    """Проверава шифровање једног бинара."""
    console.print(f"[bold]Architecture #{index}[/bold]\n")

    # Прво проверавамо шта заглавље каже.
    try:
        has_crypt_flag = binary.has_encryption_info
    except Exception:
        has_crypt_flag = False

    if has_crypt_flag:
        console.print(
            "  [bold]Encryption flag:[/bold]  "
            "[yellow]set in header[/yellow]"
        )
    else:
        console.print(
            "  [bold]Encryption flag:[/bold]  "
            "[green]not set[/green]"
        )

    # Тражимо __crypt секцију у __TEXT сегменту.
    crypt_info = _find_crypt_section(binary)

    if crypt_info is None:
        if has_crypt_flag:
            console.print(
                "  [bold]Crypt section:[/bold]   "
                "[yellow]flag set but no section found[/yellow]"
            )
        else:
            console.print(
                "  [bold]Crypt section:[/bold]   "
                "[dim]not present[/dim]"
            )
        console.print(
            "\n  [bold green]Conclusion:[/bold green] "
            "Binary is NOT encrypted. Ready for static analysis "
            "(disassemblers, decompilers).\n"
        )
        return

    section, crypt_offset, crypt_size = crypt_info

    # Читамо садржај crypt секције.
    try:
        content = bytes(section.content)
    except Exception:
        content = b""

    # Проверавамо да ли су сви бајтови нуле (дешифровано)
    # или има стварних података (шифровано).
    is_all_zeros = _is_all_zeros(content)

    console.print(
        f"  [bold]Crypt section:[/bold]   {section.name} "
        f"({_format_size(crypt_size)})"
    )
    console.print(f"  [bold]Crypt offset:[/bold]    {hex(crypt_offset)}")

    if is_all_zeros:
        console.print(
            "  [bold]Content:[/bold]         "
            "[dim]all zeros (decrypted)[/dim]"
        )
        console.print(
            "\n  [bold green]Conclusion:[/bold green] "
            "Binary is NOT encrypted. Ready for static analysis.\n"
        )
    else:
        console.print(
            "  [bold]Content:[/bold]         "
            "[red]contains data (encrypted)[/red]"
        )
        console.print(
            "\n  [bold red]Conclusion:[/bold red] "
            "Binary IS encrypted. You must decrypt it first "
            "(requires a jailbroken device).\n"
        )


def _find_crypt_section(binary) -> tuple | None:
    """Проналази __crypt секцију у бинару.

    Враћа tuple (section, crypt_offset, crypt_size) или None.
    """
    try:
        sections = binary.sections
    except Exception:
        return None

    for section in sections:
        if section.name == "__crypt":
            # Узимамо offset и size из заглавља секције.
            try:
                crypt_offset = section.offset
                crypt_size = section.size
            except Exception:
                crypt_offset = 0
                crypt_size = 0

            return section, crypt_offset, crypt_size

    return None


def _is_all_zeros(data: bytes) -> bool:
    """Проверава да ли су сви бајтови нуле.

    Ако је секција празна, сматрамо да је дешифрована.
    Узимамо узорак првих 4096 бајтова ради брзине.
    """
    if not data:
        return True

    # Узимамо узорак — не морамо целу секцију да проверавамо.
    sample = data[:4096]

    # Ако је бар један бајт различит од нуле, није празна.
    return all(b == 0 for b in sample)


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"