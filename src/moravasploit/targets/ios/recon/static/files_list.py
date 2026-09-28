# Модул за приказ свих фајлова у IPA фајлу.
# Приказује структуру апликације, фолдере, framework-е,
# ресурсе и све остало што се налази унутар .app фолдера.
import zipfile

from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Категорије фајлова по наставку (екстензији).
# Свака категорија има боју за приказ.
CATEGORIES = {
    "Framework": {
        "ext": (),
        "color": "bright_cyan",
        "note": "directories ending with .framework/",
    },
    "Extension": {
        "ext": (".appex",),
        "color": "bright_magenta",
        "note": "app extensions",
    },
    "Configuration": {
        "ext": (".plist", ".json", ".xml", ".strings", ".stringsdict",
                ".yaml", ".yml", ".ini", ".conf", ".cfg", ".toml"),
        "color": "cyan",
        "note": None,
    },
    "Certificate/Profile": {
        "ext": (".mobileprovision", ".cer", ".crt", ".pem", ".p12",
                ".pfx", ".der"),
        "color": "bold red",
        "note": None,
    },
    "Web": {
        "ext": (".html", ".htm", ".css", ".js"),
        "color": "magenta",
        "note": None,
    },
    "Database": {
        "ext": (".db", ".sqlite", ".sqlite3", ".realm"),
        "color": "yellow",
        "note": None,
    },
    "Text": {
        "ext": (".txt", ".md", ".log", ".csv"),
        "color": "white",
        "note": None,
    },
    "ML Model": {
        "ext": (".mlmodel", ".mlmodelc", ".tflite", ".onnx", ".pb",
                ".pt", ".h5", ".coreml"),
        "color": "bright_green",
        "note": None,
    },
    "Binary/Library": {
        "ext": (".dylib", ".a", ".so"),
        "color": "bright_yellow",
        "note": None,
    },
    "Media": {
        "ext": (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                ".heic", ".pdf", ".mp3", ".mp4", ".wav", ".m4a",
                ".ogg", ".aac", ".ttf", ".otf", ".ttc"),
        "color": "dim",
        "note": None,
    },
    "Localization": {
        "ext": (".lproj",),
        "color": "blue",
        "note": "localization directories",
    },
}

# Категорија за све остало.
OTHER_COLOR = "dim"


def run() -> None:
    """Приказује све фајлове у IPA фајлу."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Files list[/bold cyan]\n")

    # Отварамо IPA као ZIP и прикупљамо све фајлове из .app/.
    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            files = _collect_files(z, app_name)
    except Exception as error:
        console.print(f"[red]Failed to read IPA:[/red] {error}\n")
        return

    if not files:
        console.print("  [dim]No files found in .app folder.[/dim]\n")
        return

    # Групишемо фајлове по категоријама.
    grouped = _group_by_category(files)

    # Укупно.
    total_size = sum(size for _, size, _ in files)
    console.print(
        f"[bold]Total:[/bold] {len(files)} entries, "
        f"{_format_size(total_size)}\n"
    )

    # Приказујемо категорије редом (по дефинисаном реду).
    for category in list(CATEGORIES.keys()) + ["Other"]:
        cat_files = grouped.get(category, [])
        if not cat_files:
            continue
        _print_category(category, cat_files)


def _collect_files(
    zip_file, app_name: str
) -> list[tuple[str, int, bool]]:
    """Прикупља све фајлове у .app фолдеру.

    Враћа листу (релативна_путања, величина, да_ли_је_фолдер).
    """
    files: list[tuple[str, int, bool]] = []
    app_prefix = f"Payload/{app_name}.app/"

    for name in zip_file.namelist():
        if not name.startswith(app_prefix):
            continue

        info = zip_file.getinfo(name)
        rel_path = name[len(app_prefix):]

        if not rel_path:
            continue

        # Фолдери имају величину 0 и завршавају са /.
        is_dir = name.endswith("/")

        files.append((rel_path, info.file_size, is_dir))

    return files


def _group_by_category(
    files: list[tuple[str, int, bool]]
) -> dict[str, list[tuple[str, int]]]:
    """Групише фајлове по категоријама."""
    grouped: dict[str, list[tuple[str, int]]] = {}

    for rel_path, size, is_dir in files:
        # Прескачемо чисте фолдере у приказу (осим ако су .framework
        # или .lproj, који су занимљиви као категорија).
        category = _categorize(rel_path, is_dir)

        if category is None:
            continue

        if category not in grouped:
            grouped[category] = []
        grouped[category].append((rel_path, size))

    return grouped


def _categorize(rel_path: str, is_dir: bool) -> str | None:
    """Одређује категорију фајла."""
    lower = rel_path.lower().rstrip("/")

    # Фолдери који нас занимају као категорија.
    if is_dir:
        if lower.endswith(".framework"):
            return "Framework"
        if lower.endswith(".lproj"):
            return "Localization"
        # Остале фолдере прескачемо.
        return None

    # Проверавамо сваку категорију.
    for category, info in CATEGORIES.items():
        for ext in info["ext"]:
            if lower.endswith(ext):
                return category

    return "Other"


def _print_category(
    category: str, files: list[tuple[str, int]]
) -> None:
    """Приказује фајлове једне категорије."""
    if category in CATEGORIES:
        color = CATEGORIES[category]["color"]
        note = CATEGORIES[category].get("note")
    else:
        color = OTHER_COLOR
        note = None

    # Заглавље са додатном напоменом ако постоји.
    header = f"[bold {color}]{category}[/bold {color}] ({len(files)})"
    if note:
        header += f"  [dim]({note})[/dim]"
    console.print(f"{header}\n")

    for rel_path, size in sorted(files):
        if size == 0 and rel_path.endswith("/"):
            # Фолдер без величине.
            console.print(f"  {rel_path}")
        else:
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