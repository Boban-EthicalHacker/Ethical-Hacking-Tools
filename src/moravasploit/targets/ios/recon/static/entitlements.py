# Модул за приказ entitlements из embedded.mobileprovision фајла.
# Entitlements су системске дозволе које Apple даје апликацији
# (keychain access, app groups, push notifications, background modes,
# associated domains, healthkit, итд.). Разликују се од
# корисничких дозвола (камера, локација) — то су системске дозволе.
#
# Подаци се налазе у embedded.mobileprovision фајлу који Apple
# убацује у IPA приликом потписивања. Фајл је у CMS (PKCS#7)
# формату — потребно га је парсирати.
import plistlib
import zipfile

from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Читљива имена за познате entitlements.
# Кључ је кључ у entitlements речнику, вредност је опис.
KNOWN_ENTITLEMENTS = {
    "application-identifier": "App identifier (team + bundle)",
    "com.apple.developer.team-identifier": "Apple Developer team ID",
    "keychain-access-groups": "Keychain access groups",
    "get-task-allow": "Allow debugging (should be false in release)",
    "com.apple.developer.associated-domains": "Associated domains",
    "com.apple.developer.icloud-container-identifiers": "iCloud containers",
    "com.apple.developer.icloud-services": "iCloud services",
    "com.apple.developer.ubiquity-kvstore-identifier": "iCloud key-value store",
    "aps-environment": "Push notifications (Apple Push Service)",
    "com.apple.developer.healthkit": "HealthKit access",
    "com.apple.developer.healthkit.access": "HealthKit data types",
    "com.apple.developer.homekit": "HomeKit access",
    "com.apple.developer.siri": "Siri integration",
    "com.apple.developer.nfc.readersession.formats": "NFC reading",
    "com.apple.developer.networking.wifi-info": "Wi-Fi info access",
    "com.apple.developer.networking.vpn.api": "VPN API",
    "com.apple.developer.networking.multipath": "Multipath networking",
    "com.apple.developer.pass-type-identifiers": "Apple Wallet passes",
    "com.apple.developer.in-app-payments": "Apple Pay",
    "com.apple.developer.applesignin": "Sign in with Apple",
    "com.apple.developer.default-data-protection": "Data protection level",
    "com.apple.developer.payment-pass-provisioning": "Payment pass",
    "com.apple.developer.usernotifications.communication": "Communication notifications",
    "com.apple.developer.usernotifications.time-sensitive": "Time-sensitive notifications",
    "com.apple.developer.carplay-audio": "CarPlay audio",
    "com.apple.developer.carplay-communication": "CarPlay communication",
    "com.apple.developer.carplay-maps": "CarPlay maps",
    "com.apple.developer.carplay-parking": "CarPlay parking",
    "com.apple.developer.carplay-quick-ordering": "CarPlay quick ordering",
    "com.apple.developer.coreml.compiler.allow-unsigned-models": "CoreML unsigned models",
    "com.apple.developer.kernel.increased-memory-limit": "Increased memory limit",
    "com.apple.developer.kernel.extended-virtual-addressing": "Extended virtual addressing",
    "com.apple.external-accessory.wireless-configuration": "Wireless accessory config",
}

# Entitlements који су безбедносно осетљиви и заслужују црвену боју.
DANGEROUS_ENTITLEMENTS = {
    "get-task-allow",
    "com.apple.private.security.no-container",
    "com.apple.private.security.container-required",
    "task_for_pid-allow",
    "com.apple.system-task-ports",
    "com.apple.private.skip-library-validation",
    "com.apple.private.amfi.can-load-cdhash",
    "dynamic-codesigning",
    "com.apple.private.persona-mgmt",
    "com.apple.private.hid.client.event-monitor",
    "com.apple.private.tcc.allow",
    "com.apple.private.tcc.manager",
    "com.apple.rootless.install",
    "com.apple.rootless.install.heritable",
    "com.apple.private.security.storage.AppDataContainers",
}


def run() -> None:
    """Приказује entitlements из embedded.mobileprovision."""
    result = load_ipa()
    if result is None:
        return

    ipa_path, _, app_name = result

    console.print("\n[bold cyan]Entitlements[/bold cyan]\n")

    # Тражимо embedded.mobileprovision у .app фолдеру.
    provision_path = f"Payload/{app_name}.app/embedded.mobileprovision"

    try:
        with zipfile.ZipFile(str(ipa_path), "r") as z:
            names = z.namelist()

            if provision_path not in names:
                console.print(
                    "  [yellow]No embedded.mobileprovision file "
                    "found in the app.[/yellow]\n"
                )
                console.print(
                    "  [dim]This is common for CTF and unsigned apps. "
                    "App Store apps always include this file.[/dim]\n"
                )
                return

            raw_data = z.read(provision_path)
    except Exception as error:
        console.print(f"[red]Failed to read file:[/red] {error}\n")
        return

    # Парсирамо mobileprovision (CMS/PKCS#7 формат).
    entitlements = _extract_entitlements(raw_data)

    if entitlements is None:
        console.print(
            "  [red]Failed to parse mobileprovision file.[/red]\n"
        )
        return

    if not entitlements:
        console.print(
            "  [dim]No entitlements found in the provisioning profile.[/dim]\n"
        )
        return

    console.print(
        f"[bold]Total:[/bold] {len(entitlements)} entitlements\n"
    )

    # Приказујемо сваки entitlement.
    for key in sorted(entitlements.keys()):
        _print_entitlement(key, entitlements[key])

    console.print()


def _extract_entitlements(raw_data: bytes) -> dict | None:
    """Извлачи entitlements из mobileprovision фајла.

    Фајл је у CMS (PKCS#7) формату. Садржи XML plist унутра,
    који почиње са <?xml и завршава са </plist>.

    Враћа речник entitlements или None ако парсирање не успе.
    """
    # Проналазимо почетак и крај XML plist-а у сировим бајтовима.
    start_marker = b"<?xml"
    end_marker = b"</plist>"

    start = raw_data.find(start_marker)
    if start == -1:
        return None

    end = raw_data.find(end_marker, start)
    if end == -1:
        return None

    # Узимамо део од <?xml до </plist>.
    plist_data = raw_data[start : end + len(end_marker)]

    # Парсирамо plist.
    try:
        plist = plistlib.loads(plist_data)
    except Exception:
        return None

    # Entitlements су под кључем "Entitlements".
    if not isinstance(plist, dict):
        return None

    entitlements = plist.get("Entitlements")
    if not isinstance(entitlements, dict):
        return None

    return entitlements


def _print_entitlement(key: str, value) -> None:
    """Приказује један entitlement."""
    # Опис ако га познајемо.
    description = KNOWN_ENTITLEMENTS.get(key)

    # Боја — црвено за опасне, нормално за остале.
    is_dangerous = key in DANGEROUS_ENTITLEMENTS

    if is_dangerous:
        color = "bold red"
        warning = "  [bold red]!!![/bold red]"
    else:
        color = "bold"
        warning = ""

    console.print(f"[{color}]{key}[/{color}]{warning}")

    if description:
        console.print(f"  [dim]{description}[/dim]")

    # Приказујемо вредност.
    _print_value(value)

    console.print()


def _print_value(value) -> None:
    """Приказује вредност entitlement-а."""
    if isinstance(value, bool):
        if value:
            console.print(f"  [green]true[/green]")
        else:
            console.print(f"  [red]false[/red]")
    elif isinstance(value, list):
        console.print(f"  [{len(value)} items]")
        for item in value:
            console.print(f"    - {item}")
    elif isinstance(value, dict):
        console.print("  [dict]")
        for k, v in value.items():
            console.print(f"    {k}: {v}")
    else:
        console.print(f"  {value}")