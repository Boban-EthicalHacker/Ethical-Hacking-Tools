# Први модул у iOS / recon / static грани.
# Чита IPA фајл и приказује основне информације из Info.plist.
# Не захтева уређај, ни macOS.
from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Мапа познатих дозвола (usage descriptions) у Info.plist-у.
# Кључ је кључ у plist-у, вредност је читљиво име.
USAGE_DESCRIPTIONS = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSLocationWhenInUseUsageDescription": "Location (when in use)",
    "NSLocationAlwaysUsageDescription": "Location (always)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": (
        "Location (always and when in use)"
    ),
    "NSPhotoLibraryUsageDescription": "Photo library (read)",
    "NSPhotoLibraryAddUsageDescription": "Photo library (write)",
    "NSContactsUsageDescription": "Contacts",
    "NSCalendarsUsageDescription": "Calendars",
    "NSRemindersUsageDescription": "Reminders",
    "NSBluetoothPeripheralUsageDescription": "Bluetooth",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth (always)",
    "NSMotionUsageDescription": "Motion and fitness",
    "NSHealthShareUsageDescription": "Health (read)",
    "NSHealthUpdateUsageDescription": "Health (write)",
    "NSFaceIDUsageDescription": "Face ID",
    "NSSpeechRecognitionUsageDescription": "Speech recognition",
    "NSUserTrackingUsageDescription": "User tracking",
    "NSLocalNetworkUsageDescription": "Local network",
    "NSUserNotificationUsageDescription": "User notifications",
    "NSFocusStatusUsageDescription": "Focus status",
    "NSNearbyInteractionUsageDescription": "Nearby interaction",
    "NSFallDetectionUsageDescription": "Fall detection",
}


def run() -> None:
    """Приказује основне информације из IPA фајла."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, info, app_name = result

    console.print("\n[bold cyan]IPA information[/bold cyan]\n")

    # Основни подаци.
    console.print(f"[bold]File:[/bold]          {ipa_path.name}")
    console.print(f"[bold]App name:[/bold]      {app_name}")
    console.print(
        f"[bold]Bundle ID:[/bold]     "
        f"{info.get('CFBundleIdentifier', '(unknown)')}"
    )
    console.print(
        f"[bold]Display name:[/bold]  "
        f"{info.get('CFBundleDisplayName', info.get('CFBundleName', '(unknown)'))}"
    )
    console.print(
        f"[bold]Version:[/bold]       "
        f"{info.get('CFBundleShortVersionString', '(unknown)')}"
    )
    console.print(
        f"[bold]Build:[/bold]         "
        f"{info.get('CFBundleVersion', '(unknown)')}"
    )
    console.print(
        f"[bold]Minimum iOS:[/bold]   "
        f"{info.get('MinimumOSVersion', '(unknown)')}"
    )
    console.print(
        f"[bold]Platform:[/bold]      "
        f"{info.get('DTPlatformName', '(unknown)')}"
    )
    console.print(
        f"[bold]SDK:[/bold]           "
        f"{info.get('DTSDKName', '(unknown)')}"
    )

    # Дозволе.
    _print_usage_descriptions(info)

    console.print()


def _print_usage_descriptions(info: dict) -> None:
    """Приказује дозволе за које апликација тражи приступ."""
    found = []

    for key, label in USAGE_DESCRIPTIONS.items():
        if key in info:
            found.append((label, info[key]))

    console.print(f"\n[bold]Usage descriptions ({len(found)}):[/bold]\n")

    if not found:
        console.print("  [dim]None declared.[/dim]")
        return

    for label, description in found:
        # Скраћујемо превише дугачке описе.
        if isinstance(description, str) and len(description) > 80:
            description = description[:77] + "..."

        console.print(f"  [bold]{label}:[/bold] {description}")