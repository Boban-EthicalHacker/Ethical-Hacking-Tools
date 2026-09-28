# Модул за анализу Assets.car фајла у IPA фајлу.
# Assets.car је Apple-ов компајлирани каталог ресурса
# (Compiled Asset Catalog). Садржи слике, иконе, боје и
# друге ресурсе у бинарном формату.
#
# Овај модул не екстрактује саме слике (то би захтевало
# сложен парсер или спољне алате), али приказује основне
# информације: величину, отисак, верзију формата и
# основне информације из заглавља.
import hashlib
import struct
import zipfile

from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Магични бројеви за препознавање формата.
# CACA = старији CORE формат, CACHE = кеш,
# BOMS = новији BOM Store омотач (Bill of Materials).
CORE_MAGIC = b"CACA"
CACHE_MAGIC = b"CACHE"
BOMS_MAGIC = b"BOMS"

# Читљива имена верзија формата (BOM version).
BOM_VERSIONS = {
    1: "BOM 1 (legacy)",
    2: "BOM 2",
    3: "BOM 3",
    4: "BOM 4",
    5: "BOM 5",
    6: "BOM 6",
    7: "BOM 7",
    8: "BOM 8 (modern)",
    9: "BOM 9",
}


def run() -> None:
    """Анализира Assets.car фајл из IPA фајла."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Asset catalog[/bold cyan]\n")

    # Тражимо Assets.car у .app фолдеру.
    asset_path = f"Payload/{app_name}.app/Assets.car"

    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            names = z.namelist()

            if asset_path not in names:
                console.print(
                    "  [yellow]No Assets.car file found in the app.[/yellow]\n"
                )
                console.print(
                    "  [dim]This app may not use compiled asset catalogs, "
                    "or uses older resource format.[/dim]\n"
                )
                return

            car_data = z.read(asset_path)
    except Exception as error:
        console.print(f"[red]Failed to read IPA:[/red] {error}\n")
        return

    # Основни подаци.
    _print_basic_info(car_data)

    # Анализирамо заглавље.
    _analyze_header(car_data)

    # Додатна анализа — препознатљиви стрингови.
    _scan_rendition_types(car_data)


def _print_basic_info(car_data: bytes) -> None:
    """Приказује основне информације о фајлу."""
    size = len(car_data)

    # Хеш отисци.
    sha256 = hashlib.sha256(car_data).hexdigest()
    md5 = hashlib.md5(car_data).hexdigest()

    console.print(f"[bold]File size:[/bold]     {_format_size(size)}")
    console.print(f"[bold]MD5:[/bold]           {md5}")
    console.print(f"[bold]SHA-256:[/bold]       {sha256}")
    console.print()


def _analyze_header(car_data: bytes) -> None:
    """Анализира заглавље Assets.car фајла."""
    console.print("[bold]Format information[/bold]\n")

    if len(car_data) < 16:
        console.print("  [red]File too small to be a valid Assets.car.[/red]\n")
        return

    # Прва четири бајта су магични број.
    magic = car_data[:4]

    # Новији формат — BOM Store омотач.
    if magic == BOMS_MAGIC:
        _analyze_boms_format(car_data)
        return

    if magic not in (CORE_MAGIC, CACHE_MAGIC):
        console.print(
            f"  [red]Not a valid Assets.car format "
            f"(magic: {magic!r})[/red]\n"
        )
        return

    # Ако је CACHE формат (кеш), нема корисних података.
    if magic == CACHE_MAGIC:
        console.print("  [bold]Format:[/bold]       CACHE (runtime cache)")
        console.print(
            "  [dim]This is a runtime cache file, not the compiled "
            "asset catalog. Actual catalog is likely CACA.[/dim]\n"
        )
        return

    # CACA формат — читамо остатак заглавља.
    # Структура (big-endian):
    # 0-3:   magic "CACA"
    # 4-7:   core version (uint32)
    # 8-11:  storage version (uint32)
    # 12-15: storage timestamp (uint32)
    # 16-19: rendition count (uint32)
    try:
        core_version = struct.unpack(">I", car_data[4:8])[0]
        storage_version = struct.unpack(">I", car_data[8:12])[0]
        rendition_count = struct.unpack(">I", car_data[16:20])[0]
    except struct.error:
        console.print("  [red]Failed to read header fields.[/red]\n")
        return

    console.print(f"  [bold]Format:[/bold]       CACA (compiled asset catalog)")
    console.print(f"  [bold]Core version:[/bold] {core_version}")
    console.print(f"  [bold]Storage ver:[/bold]  {storage_version}")

    # Верзија BOM-а.
    bom_label = BOM_VERSIONS.get(storage_version, f"version {storage_version}")
    console.print(f"  [bold]BOM:[/bold]          {bom_label}")

    # Број рендиција.
    if rendition_count > 0:
        console.print(f"  [bold]Renditions:[/bold]   {rendition_count}")
    else:
        console.print(
            "  [bold]Renditions:[/bold]   [dim]unknown "
            "(not in header for this format)[/dim]"
        )

    console.print()


def _analyze_boms_format(car_data: bytes) -> None:
    """Анализира новији BOMS (BOM Store) формат.

    Овај формат је омотач који садржи више BOM фајлова унутра.
    Прави CACA каталог се налази негде унутра, али његова
    локација није на фиксном месту, па је не тражимо.

    Приказујемо само шта смо сигурни да знамо: формат је BOMS.
    """
    console.print(
        "  [bold]Format:[/bold]       BOMS (BOM Store, newer format)"
    )
    console.print(
        "  [dim]This is the newer Apple asset catalog format. "
        "Full parsing requires specialised tools.[/dim]\n"
    )

def _read_embedded_caca(car_data: bytes, offset: int) -> None:
    """Чита заглавље CACA каталога на датој позицији."""
    # Треба нам бар 20 бајтова од offset-а.
    if len(car_data) < offset + 20:
        return

    try:
        core_version = struct.unpack(">I", car_data[offset + 4 : offset + 8])[0]
        storage_version = struct.unpack(
            ">I", car_data[offset + 8 : offset + 12]
        )[0]
        rendition_count = struct.unpack(
            ">I", car_data[offset + 16 : offset + 20]
        )[0]
    except struct.error:
        return

    console.print(f"  [bold]Core version:[/bold] {core_version}")
    console.print(f"  [bold]Storage ver:[/bold]  {storage_version}")

    bom_label = BOM_VERSIONS.get(storage_version, f"version {storage_version}")
    console.print(f"  [bold]BOM:[/bold]          {bom_label}")

    if rendition_count > 0:
        console.print(f"  [bold]Renditions:[/bold]   {rendition_count}")


def _scan_rendition_types(car_data: bytes) -> None:
    """Претражује фајл за препознатљиве типове ресурса."""
    # Познати називи рендера који су чести у iOS апликацијама.
    known_names = [
        b"AppIcon",
        b"AccentColor",
        b"LaunchImage",
        b"Brand Assets",
    ]

    found = []
    for name in known_names:
        if name in car_data:
            found.append(name.decode("ascii", errors="replace"))

    console.print("[bold]Known rendition names[/bold]\n")

    if not found:
        console.print(
            "  [dim]No standard rendition names detected.[/dim]\n"
        )
    else:
        for name in found:
            console.print(f"  [green]{name}[/green]")
        console.print()

    # Напомена о ограничењима.
    console.print(
        "  [dim]Note: this is a basic analysis. For full extraction "
        "of images and colors, use tools like 'acextract' or "
        "'AssetCatalogTinkerer'.[/dim]\n"
    )


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"