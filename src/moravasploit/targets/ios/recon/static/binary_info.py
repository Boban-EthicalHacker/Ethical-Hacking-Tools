# Модул за приказ информација о Mach-O бинару у IPA фајлу.
# Mach-O је извршни формат на iOS/macOS платформама.
import zipfile

import lief
from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Читљива имена типова процесора.
CPU_TYPES = {
    "ARM64": "ARM 64-bit (arm64)",
    "ARM64E": "ARM 64-bit (arm64e)",
    "ARM": "ARM 32-bit",
    "X86_64": "Intel x86 64-bit",
    "X86": "Intel x86 32-bit",
    "POWERPC": "PowerPC",
    "POWERPC_64": "PowerPC 64-bit",
}

# Читљива имена типова фајла.
FILE_TYPES = {
    "EXECUTE": "Executable",
    "DYLIB": "Dynamic library",
    "BUNDLE": "Bundle",
    "OBJECT": "Object file",
    "DSYM": "Debug symbols",
    "CORE": "Core dump",
    "PRELOAD": "Preload",
    "KEXT_BUNDLE": "Kernel extension",
}


def run() -> None:
    """Приказује информације о Mach-O бинару из IPA фајла."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Binary information[/bold cyan]\n")

    # Проналазимо име бинара у .app фолдеру.
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
        # Ако није итерирабилан, можда је обичан Binary.
        binaries = [fat]

    console.print(f"[bold]Binary:[/bold]         {binary_path.split('/')[-1]}")
    console.print(f"[bold]Architectures:[/bold]  {len(binaries)}\n")

    for i, binary in enumerate(binaries, start=1):
        _print_binary(i, binary)

    console.print()


def _find_binary_path(ipa_path, app_name: str) -> str | None:
    """Проналази путању до главног бинара у IPA фајлу.

    Бинар се обично зове исто као .app фолдер (без екстензије).
    Налази се директно у .app фолдеру, не у подфолдеру.
    """
    expected = f"Payload/{app_name}.app/{app_name}"

    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            names = z.namelist()

            # Тражимо тачан назив.
            if expected in names:
                return expected

            # Ако не нађемо, тражимо било који фајл у .app/ који
            # није очигледно ресурс.
            app_prefix = f"Payload/{app_name}.app/"
            for name in names:
                if not name.startswith(app_prefix):
                    continue

                # Само фајлови директно у .app/, не у подфолдерима.
                rel = name[len(app_prefix):]
                if "/" in rel:
                    continue

                # Прескачемо очигледне ресурсе.
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


def _print_binary(index: int, binary) -> None:
    """Приказује информације о једном бинару (једној архитектури)."""
    console.print(f"[bold]Architecture #{index}[/bold]\n")

    # Архитектура.
    cpu_type = str(binary.header.cpu_type).split(".")[-1]
    arch_name = CPU_TYPES.get(cpu_type, cpu_type)
    console.print(f"  [bold]CPU:[/bold]           {arch_name}")

    # Тип фајла.
    file_type = str(binary.header.file_type).split(".")[-1]
    type_name = FILE_TYPES.get(file_type, file_type)
    console.print(f"  [bold]Type:[/bold]          {type_name}")

    # Платформа (ако постоји).
    try:
        platform = str(binary.header.platform).split(".")[-1]
        console.print(f"  [bold]Platform:[/bold]      {platform}")
    except Exception:
        pass

    # Шифровање.
    try:
        has_crypt = binary.has_encryption_info
        if has_crypt:
            console.print("  [bold]Encrypted:[/bold]     [red]yes[/red]")
        else:
            console.print("  [bold]Encrypted:[/bold]     [green]no[/green]")
    except Exception:
        pass

    # Линковане библиотеке.
    try:
        libraries = list(binary.libraries)
        if libraries:
            console.print(
                f"\n  [bold]Linked libraries ({len(libraries)}):[/bold]"
            )
            for lib in libraries:
                console.print(f"    {lib.name}")
    except Exception:
        pass

    console.print()