# Модул за анализу .framework фолдера у IPA фајлу.
# Framework-ови су спољне библиотеке које апликација користи.
# Могу бити системски (Apple SDK) или треће стране (Google, Facebook,
# Firebase, итд.) — ови други су често занимљиви за безбедност.
import plistlib
import zipfile

from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Познати framework-ови трећих страна.
# Кључ је део имена, вредност је опис.
KNOWN_FRAMEWORKS = {
    "Firebase": "Google Firebase",
    "GoogleAnalytics": "Google Analytics",
    "GoogleMaps": "Google Maps",
    "GoogleSignIn": "Google Sign-In",
    "FBSDK": "Facebook SDK",
    "Facebook": "Facebook SDK",
    "Twitter": "Twitter SDK",
    "Amazon": "Amazon SDK",
    "Stripe": "Stripe плаћања",
    "Braintree": "Braintree плаћања",
    "PayPal": "PayPal плаћања",
    "Adjust": "Adjust аналитика",
    "AppsFlyer": "AppsFlyer аналитика",
    "Mixpanel": "Mixpanel аналитика",
    "Amplitude": "Amplitude аналитика",
    "Segment": "Segment аналитика",
    "Flurry": "Flurry аналитика",
    "Crashlytics": "Crashlytics",
    "Sentry": "Sentry грешке",
    "Bugsnag": "Bugsnag грешке",
    "Mapbox": "Mapbox мапе",
    "AFNetworking": "AFNetworking HTTP",
    "Alamofire": "Alamofire HTTP",
    "SDWebImage": "SDWebImage",
    "Kingfisher": "Kingfisher",
    "Realm": "Realm база",
    "SQLite": "SQLite база",
    "OpenSSL": "OpenSSL",
    "BoringSSL": "BoringSSL",
    "CryptoSwift": "CryptoSwift",
    "SwiftyRSA": "SwiftyRSA",
    "KeychainAccess": "Keychain access",
    "lottie": "Lottie анимација",
    "PhoneNumberKit": "Phone number",
    "SVGKit": "SVG rendering",
    "Charts": "Charts",
    "Hero": "Hero анимација",
    "SkeletonView": "Skeleton view",
    "ZIPFoundation": "ZIP",
    "SSZipArchive": "ZIP",
    "SwiftProtobuf": "Protocol Buffers",
    "Protobuf": "Protocol Buffers",
}

# Категорије framework-а.
TRACKER_KEYS = (
    "Analytics", "Adjust", "AppsFlyer", "Mixpanel", "Amplitude",
    "Segment", "Flurry", "Crashlytics", "Sentry", "Bugsnag",
)


def run() -> None:
    """Анализира .framework фолдере у IPA фајлу."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Frameworks[/bold cyan]\n")

    # Прикупљамо све framework-ове.
    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            frameworks = _collect_frameworks(z, app_name)
    except Exception as error:
        console.print(f"[red]Failed to read IPA:[/red] {error}\n")
        return

    if not frameworks:
        console.print(
            "  [dim]No frameworks found in the app.[/dim]\n"
        )
        console.print(
            "  [dim]This app either has no embedded frameworks, or "
            "uses only static linking.[/dim]\n"
        )
        return

    # Укупно.
    total_size = sum(fw["size"] for fw in frameworks)
    console.print(
        f"[bold]Total:[/bold] {len(frameworks)} frameworks, "
        f"{_format_size(total_size)}\n"
    )

    # Приказујемо сваки framework.
    for fw in sorted(frameworks, key=lambda x: x["name"]):
        _print_framework(fw)


def _collect_frameworks(
    zip_file, app_name: str
) -> list[dict]:
    """Прикупља све framework-ове у .app фолдеру.

    Враћа листу речника са подацима о сваком framework-у.
    """
    app_prefix = f"Payload/{app_name}.app/"

    # Прво проналазимо све .framework фолдере.
    framework_paths: set[str] = set()

    for name in zip_file.namelist():
        if not name.startswith(app_prefix):
            continue

        rel = name[len(app_prefix):]

        # Тражимо .framework/ у путањи.
        if ".framework/" not in rel:
            continue

        # Извлачимо путању до .framework фолдера.
        idx = rel.index(".framework/")
        fw_rel = rel[: idx + len(".framework")]

        framework_paths.add(fw_rel)

    # За сваки framework узимамо податке.
    frameworks = []

    for fw_path in framework_paths:
        fw_name = fw_path.split("/")[-1]
        full_prefix = f"{app_prefix}{fw_path}/"

        # Укупан број фајлова и величина.
        file_count = 0
        total_size = 0
        binary_name = None

        for name in zip_file.namelist():
            if not name.startswith(full_prefix):
                continue

            info = zip_file.getinfo(name)
            if name.endswith("/"):
                continue

            file_count += 1
            total_size += info.file_size

            # Бинар се зове исто као framework без .framework.
            expected_binary = fw_name[:-len(".framework")]
            rel = name[len(full_prefix):]

            if rel == expected_binary:
                binary_name = rel

        # Читамо Info.plist ако постоји.
        plist_data = None
        plist_path = f"{full_prefix}Info.plist"

        if plist_path in zip_file.namelist():
            try:
                raw = zip_file.read(plist_path)
                plist_data = plistlib.loads(raw)
            except Exception:
                plist_data = None

        # Препознајемо framework.
        known = _identify(fw_name)
        is_tracker = any(key in fw_name for key in TRACKER_KEYS)

        frameworks.append({
            "name": fw_name,
            "path": fw_path,
            "size": total_size,
            "file_count": file_count,
            "binary_name": binary_name,
            "plist": plist_data,
            "known": known,
            "is_tracker": is_tracker,
        })

    return frameworks


def _identify(fw_name: str) -> str | None:
    """Препознаје познати framework по имену."""
    lower = fw_name.lower()
    for key, description in KNOWN_FRAMEWORKS.items():
        if key.lower() in lower:
            return description
    return None


def _print_framework(fw: dict) -> None:
    """Приказује један framework."""
    # Боја за име — црвено ако је tracker, жуто ако је познат,
    # иначе нормално.
    if fw["is_tracker"]:
        color = "bold red"
        marker = " [bold red](tracker)[/bold red]"
    elif fw["known"]:
        color = "bold yellow"
        marker = f" [yellow]({fw['known']})[/yellow]"
    else:
        color = "bold"
        marker = ""

    console.print(f"[{color}]{fw['name']}[/{color}]{marker}")
    console.print(f"  Path:       {fw['path']}")
    console.print(f"  Size:       {_format_size(fw['size'])}")
    console.print(f"  Files:      {fw['file_count']}")

    if fw["binary_name"]:
        console.print(f"  Binary:     {fw['binary_name']}")

    # Ако имамо Info.plist, приказујемо верзију.
    plist = fw["plist"]
    if plist:
        version = plist.get("CFBundleShortVersionString")
        bundle_id = plist.get("CFBundleIdentifier")

        if version:
            console.print(f"  Version:    {version}")
        if bundle_id:
            console.print(f"  Bundle ID:  {bundle_id}")

    console.print()


def _format_size(size: int) -> str:
    """Претвара величину у бајтовима у читљив облик."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"