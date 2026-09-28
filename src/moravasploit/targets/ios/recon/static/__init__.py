# Модул за статичку анализу IPA фајлова.
from rich.console import Console

from moravasploit.core.menu import ask_choice
from moravasploit.targets.ios.recon.static import (
    asset_car,
    ats_check,
    binary_info,
    check_encryption,
    entitlements,
    files_list,
    frameworks,
    ipa_hash,
    ipa_info,
    localization,
    plist_full,
    strings_scan,
)

console = Console()

# Речник модула у static грани.
MODULES: dict[str, tuple[str, object]] = {
    "1": ("ipa_info", ipa_info.run),
    "2": ("binary_info", binary_info.run),
    "3": ("files_list", files_list.run),
    "4": ("plist_full", plist_full.run),
    "5": ("strings_scan", strings_scan.run),
    "6": ("ipa_hash", ipa_hash.run),
    "7": ("check_encryption", check_encryption.run),
    "8": ("frameworks", frameworks.run),
    "9": ("entitlements", entitlements.run),
    "10": ("asset_car", asset_car.run),
    "11": ("ats_check", ats_check.run),
    "12": ("localization", localization.run),
}


def menu() -> None:
    """Приказује мени модула за статичку анализу IPA фајлова."""
    while True:
        console.print("\n[bold]iOS / recon / static - choose module:[/bold]\n")

        for key, (name, _) in MODULES.items():
            console.print(f"  [{key}] {name}")

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]")

        choice = ask_choice(list(MODULES.keys()))

        if choice is None:
            return

        _, run_function = MODULES[choice]
        run_function()