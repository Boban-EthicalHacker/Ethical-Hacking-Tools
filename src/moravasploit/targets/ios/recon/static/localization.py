# Модул за приказ локализације апликације.
# iOS апликације чувају преводе у .lproj фолдерима
# (нпр. en.lproj, sr.lproj, de.lproj). Сваки садржи
# .strings фајлове са преводима.
import zipfile

from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Мапа ISO кôдова језика у читљива имена.
# Покрива најчешће језике. Остали ће бити приказани као кôд.
LANGUAGE_NAMES = {
    "en": "English",
    "sr": "Serbian",
    "hr": "Croatian",
    "bs": "Bosnian",
    "sl": "Slovenian",
    "mk": "Macedonian",
    "bg": "Bulgarian",
    "de": "German",
    "fr": "French",
    "es": "Spanish",
    "it": "Italian",
    "pt": "Portuguese",
    "pt-BR": "Portuguese (Brazil)",
    "pt-PT": "Portuguese (Portugal)",
    "nl": "Dutch",
    "sv": "Swedish",
    "no": "Norwegian",
    "da": "Danish",
    "fi": "Finnish",
    "is": "Icelandic",
    "pl": "Polish",
    "cs": "Czech",
    "sk": "Slovak",
    "hu": "Hungarian",
    "ro": "Romanian",
    "el": "Greek",
    "tr": "Turkish",
    "ru": "Russian",
    "uk": "Ukrainian",
    "be": "Belarusian",
    "ar": "Arabic",
    "he": "Hebrew",
    "fa": "Persian",
    "hi": "Hindi",
    "th": "Thai",
    "vi": "Vietnamese",
    "id": "Indonesian",
    "ms": "Malay",
    "ja": "Japanese",
    "ko": "Korean",
    "zh": "Chinese",
    "zh-Hans": "Chinese (Simplified)",
    "zh-Hant": "Chinese (Traditional)",
    "zh-CN": "Chinese (China)",
    "zh-TW": "Chinese (Taiwan)",
    "zh-HK": "Chinese (Hong Kong)",
    "ca": "Catalan",
    "eu": "Basque",
    "gl": "Galician",
    "af": "Afrikaans",
    "sw": "Swahili",
    "am": "Amharic",
    "bn": "Bengali",
    "ta": "Tamil",
    "te": "Telugu",
    "ml": "Malayalam",
    "kn": "Kannada",
    "mr": "Marathi",
    "gu": "Gujarati",
    "pa": "Punjabi",
    "ur": "Urdu",
    "fil": "Filipino",
    "base": "Base (fallback)",
}


def run() -> None:
    """Приказује језике на које је апликација преведена."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Localization[/bold cyan]\n")

    # Тражимо све .lproj фолдере у .app фолдеру.
    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            locales = _collect_locales(z, app_name)
    except Exception as error:
        console.print(f"[red]Failed to read IPA:[/red] {error}\n")
        return

    if not locales:
        console.print(
            "  [dim]No localization folders (.lproj) found.[/dim]\n"
        )
        console.print(
            "  [dim]This app has no localizations, or uses a "
            "non-standard structure.[/dim]\n"
        )
        return

    # Укупно.
    console.print(
        f"[bold]Total:[/bold] {len(locales)} localizations\n"
    )

    # Сортирамо језике — прво они са читљивим именом.
    sorted_locales = sorted(
        locales.items(),
        key=lambda x: (
            LANGUAGE_NAMES.get(x[0], "zzz" + x[0]),
        ),
    )

    # Приказујемо сваки језик.
    for code, data in sorted_locales:
        _print_locale(code, data)


def _collect_locales(zip_file, app_name: str) -> dict:
    """Прикупља све .lproj фолдере и броји фајлове у сваком.

    Враћа речник: {код_језика: {"files": број, "size": укупан_бајтова}}
    """
    app_prefix = f"Payload/{app_name}.app/"
    locales: dict[str, dict] = {}

    for name in zip_file.namelist():
        if not name.startswith(app_prefix):
            continue

        rel = name[len(app_prefix):]

        # Тражимо .lproj/ у путањи.
        if ".lproj/" not in rel:
            continue

        # Извлачимо код језика.
        idx = rel.index(".lproj/")
        locale_code = rel[:idx]

        # Ако је већ обрађен, само ажурирамо.
        if locale_code not in locales:
            locales[locale_code] = {"files": 0, "size": 0}

        # Ако је фајл (не фолдер), бројимо га.
        if not name.endswith("/"):
            info = zip_file.getinfo(name)
            locales[locale_code]["files"] += 1
            locales[locale_code]["size"] += info.file_size

    return locales


def _print_locale(code: str, data: dict) -> None:
    """Приказује један језик."""
    # Читљиво име језика.
    name = LANGUAGE_NAMES.get(code, "Unknown")

    # Форматирамо величину.
    size = data["size"]
    size_str = _format_size(size)

    # Боја — "base" и "en" су стандардни, остали су додатни преводи.
    if code in ("base", "en"):
        color = "dim"
    else:
        color = "bold"

    console.print(
        f"  [{color}]{code:12s}[/{color}]  "
        f"[dim]{name:24s}[/dim]  "
        f"{data['files']} files, {size_str}"
    )


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"