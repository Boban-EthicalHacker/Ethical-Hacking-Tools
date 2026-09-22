# Модул за преглед assets/ фолдера у APK-у.
# У assets/ се често налазе конфигурациони фајлови, базе података,
# сертификати, кључеви, HTML/JS фајлови за WebView, модели
# машинског учења и друге корисне ствари за анализу.
import zipfile

from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Категорије фајлова по наставку (екстензији).
# Свака категорија има боју за приказ.
CATEGORIES = {
    "Configuration": {
        "ext": (".json", ".xml", ".yaml", ".yml", ".ini", ".conf",
                ".properties", ".toml", ".cfg"),
        "color": "cyan",
    },
    "Database": {
        "ext": (".db", ".sqlite", ".sqlite3", ".realm"),
        "color": "yellow",
    },
    "Certificate/Key": {
        "ext": (".pem", ".crt", ".cer", ".key", ".p12", ".pfx",
                ".jks", ".bks", ".der"),
        "color": "bold red",
    },
    "Web": {
        "ext": (".html", ".htm", ".css", ".js"),
        "color": "magenta",
    },
    "Text": {
        "ext": (".txt", ".md", ".log", ".csv"),
        "color": "white",
    },
    "ML Model": {
        "ext": (".tflite", ".onnx", ".pb", ".pt", ".h5"),
        "color": "bright_green",
    },
    "Media": {
        "ext": (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                ".mp3", ".mp4", ".wav", ".ogg", ".ttf", ".otf"),
        "color": "dim",
    },
}

# Категорија за све остало.
OTHER_COLOR = "dim"


def run() -> None:
    """Приказује фајлове у assets/ фолдеру APK-а."""
    result = load_apk()
    if result is None:
        return

    apk_path, _ = result

    console.print("\n[bold cyan]Assets scan[/bold cyan]\n")

    # Отварамо APK као ZIP и прикупљамо фајлове из assets/.
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            assets = _collect_assets(z)
    except Exception as error:
        console.print(f"[red]Failed to read APK:[/red] {error}\n")
        return

    if not assets:
        console.print("  [dim]No assets/ folder or it is empty.[/dim]\n")
        return

    # Групишемо фајлове по категоријама.
    grouped = _group_by_category(assets)

    # Укупно.
    total_size = sum(size for _, size in assets)
    console.print(
        f"[bold]Total:[/bold] {len(assets)} files, "
        f"{_format_size(total_size)}\n"
    )

    # Приказујемо категорије редом.
    for category in list(CATEGORIES.keys()) + ["Other"]:
        files = grouped.get(category, [])
        if not files:
            continue

        _print_category(category, files)


def _collect_assets(zip_file) -> list[tuple[str, int]]:
    """Прикупља све фајлове у assets/ фолдеру.

    Враћа листу (релативна_путања, величина_у_бајтовима).
    """
    assets: list[tuple[str, int]] = []

    for name in zip_file.namelist():
        if not name.startswith("assets/"):
            continue

        info = zip_file.getinfo(name)

        # Прескачемо фолдере (имају величину 0 и завршавају са /).
        if name.endswith("/"):
            continue

        # Релативна путања без "assets/" префикса.
        rel_path = name[len("assets/"):]
        assets.append((rel_path, info.file_size))

    return assets


def _group_by_category(
    assets: list[tuple[str, int]]
) -> dict[str, list[tuple[str, int]]]:
    """Групише фајлове по категоријама на основу екстензије."""
    grouped: dict[str, list[tuple[str, int]]] = {}

    for rel_path, size in assets:
        category = _categorize(rel_path)
        if category not in grouped:
            grouped[category] = []
        grouped[category].append((rel_path, size))

    return grouped


def _categorize(rel_path: str) -> str:
    """Одређује категорију фајла на основу екстензије."""
    lower = rel_path.lower()

    for category, info in CATEGORIES.items():
        for ext in info["ext"]:
            if lower.endswith(ext):
                return category

    return "Other"


def _print_category(category: str, files: list[tuple[str, int]]) -> None:
    """Приказује фајлове једне категорије."""
    # Боја за ову категорију.
    if category in CATEGORIES:
        color = CATEGORIES[category]["color"]
    else:
        color = OTHER_COLOR

    console.print(f"[bold {color}]{category}[/bold {color}] ({len(files)})\n")

    for rel_path, size in sorted(files):
        size_str = _format_size(size)
        console.print(f"  {rel_path}  [dim]({size_str})[/dim]")

    console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"