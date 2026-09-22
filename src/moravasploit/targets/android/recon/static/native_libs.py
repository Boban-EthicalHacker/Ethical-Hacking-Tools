# Модул за приказ нативних библиотека (.so фајлова) у APK-у.
# Нативне библиотеке су написане у C или C++ и могу да садрже
# рањивости које не постоје у Java/Kotlin коду (buffer overflow,
# use-after-free, итд.). Такође показују које се спољне
# библиотеке користе (OpenSSL, curl, sqlite...).
import zipfile

from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Познате нативне библиотеке и њихови препознатљиви делови имена.
# Служи за препознавање која се спољна библиотека користи.
KNOWN_LIBS = {
    "openssl": "OpenSSL (TLS/SSL)",
    "libssl": "OpenSSL (TLS/SSL)",
    "libcrypto": "OpenSSL crypto",
    "libcurl": "curl (HTTP клијент)",
    "libsqlite": "SQLite (база података)",
    "sqlite": "SQLite (база података)",
    "libc++_shared": "C++ runtime",
    "liblog": "Android logger",
    "libz": "zlib (компресија)",
    "libjpeg": "JPEG декодер",
    "libpng": "PNG декодер",
    "libwebp": "WebP декодер",
    "ffmpeg": "FFmpeg (видео)",
    "libavcodec": "FFmpeg кодек",
    "libavformat": "FFmpeg формат",
    "libtor": "Tor",
    "libsodium": "libsodium (криптографија)",
    "libsrtp": "SRTP",
    "libwebrtc": "WebRTC",
    "librealm": "Realm база",
    "libnative-lib": "Нативни део апликације",
}


def run() -> None:
    """Приказује нативне библиотеке у APK-у."""
    result = load_apk()
    if result is None:
        return

    apk_path, _ = result

    console.print("\n[bold cyan]Native libraries[/bold cyan]\n")

    # Отварамо APK као ZIP и тражимо све .so фајлове.
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            libs = _collect_libs(z)
    except Exception as error:
        console.print(f"[red]Failed to read APK:[/red] {error}\n")
        return

    if not libs:
        console.print("  [dim]No native libraries found.[/dim]\n")
        return

    # Групишемо библиотеке по архитектури.
    for arch in sorted(libs.keys()):
        _print_architecture(arch, libs[arch])

    # Укупно.
    total = sum(len(v) for v in libs.values())
    console.print(f"[bold]Total:[/bold] {total} files "
                  f"in {len(libs)} architecture(s)\n")


def _collect_libs(zip_file) -> dict[str, list[tuple[str, int]]]:
    """Прикупља .so фајлове груписане по архитектури."""
    libs: dict[str, list[tuple[str, int]]] = {}

    for name in zip_file.namelist():
        # Тражимо само фајлове у lib/ фолдеру са .so екстензијом.
        if not name.startswith("lib/") or not name.endswith(".so"):
            continue

        # Путања је типа lib/arm64-v8a/libfoo.so.
        parts = name.split("/")
        if len(parts) < 3:
            continue

        arch = parts[1]
        file_name = parts[-1]
        info = zip_file.getinfo(name)

        if arch not in libs:
            libs[arch] = []

        libs[arch].append((file_name, info.file_size))

    return libs


def _print_architecture(arch: str, libs: list[tuple[str, int]]) -> None:
    """Приказује библиотеке једне архитектуре."""
    console.print(f"[bold]{arch}[/bold] ({len(libs)})\n")

    # Сортирамо по имену.
    for name, size in sorted(libs):
        # Тражимо да ли је позната библиотека.
        known = _identify(name)

        # Приказујемо величину у читљивом облику.
        size_str = _format_size(size)

        if known:
            console.print(
                f"  {name}  [dim]({size_str})[/dim]  "
                f"[green]{known}[/green]"
            )
        else:
            console.print(f"  {name}  [dim]({size_str})[/dim]")

    console.print()


def _identify(file_name: str) -> str | None:
    """Покушава да препозна библиотеку по имену."""
    lower = file_name.lower()
    for key, description in KNOWN_LIBS.items():
        if key.lower() in lower:
            return description
    return None


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"