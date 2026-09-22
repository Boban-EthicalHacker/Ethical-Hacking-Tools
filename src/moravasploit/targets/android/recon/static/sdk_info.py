# Модул за приказ SDK верзија апликације.
# Приказује minSdkVersion, targetSdkVersion и compileSdkVersion,
# плус безбедносна упозорења на основу тих вредности.
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Мапа Android верзија по API нивоу.
# Користи се за приказ читљивог имена верзије.
API_VERSIONS = {
    1: "1.0",
    2: "1.1",
    3: "1.5 Cupcake",
    4: "1.6 Donut",
    5: "2.0 Eclair",
    6: "2.0.1 Eclair",
    7: "2.1 Eclair",
    8: "2.2 Froyo",
    9: "2.3 Gingerbread",
    10: "2.3.3 Gingerbread",
    11: "3.0 Honeycomb",
    12: "3.1 Honeycomb",
    13: "3.2 Honeycomb",
    14: "4.0 Ice Cream Sandwich",
    15: "4.0.3 Ice Cream Sandwich",
    16: "4.1 Jelly Bean",
    17: "4.2 Jelly Bean",
    18: "4.3 Jelly Bean",
    19: "4.4 KitKat",
    20: "4.4W KitKat Wear",
    21: "5.0 Lollipop",
    22: "5.1 Lollipop",
    23: "6.0 Marshmallow",
    24: "7.0 Nougat",
    25: "7.1 Nougat",
    26: "8.0 Oreo",
    27: "8.1 Oreo",
    28: "9.0 Pie",
    29: "10.0",
    30: "11.0",
    31: "12.0",
    32: "12L",
    33: "13.0",
    34: "14.0",
    35: "15.0",
    36: "16.0",
}


def run() -> None:
    """Приказује SDK верзије апликације и безбедносна упозорења."""
    result = load_apk()
    if result is None:
        return

    _, apk = result

    console.print("\n[bold cyan]SDK information[/bold cyan]\n")

    # Узимамо вредности из манифеста.
    min_sdk = _to_int(apk.get_min_sdk_version())
    target_sdk = _to_int(apk.get_target_sdk_version())
    compile_sdk = _to_int(
        apk.get_attribute_value("manifest", "compileSdkVersion")
    )

    # Приказујемо три главне вредности.
    _print_version("Minimum SDK", min_sdk)
    _print_version("Target SDK", target_sdk)
    _print_version("Compile SDK", compile_sdk)

    # Приказујемо упозорења.
    warnings = _collect_warnings(min_sdk, target_sdk)
    _print_warnings(warnings)


def _to_int(value) -> int | None:
    """Претвара вредност у int ако је могуће."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _print_version(label: str, value: int | None) -> None:
    """Приказује једну SDK верзију."""
    if value is None:
        console.print(f"[bold]{label}:[/bold]  [dim]not specified[/dim]")
        return

    # Читљиво име Android верзије (ако постоји).
    name = API_VERSIONS.get(value, "unknown")
    console.print(
        f"[bold]{label}:[/bold]  API {value}  [dim](Android {name})[/dim]"
    )


def _collect_warnings(
    min_sdk: int | None, target_sdk: int | None
) -> list[tuple[str, str]]:
    """Прикупља безбедносна упозорења на основу SDK верзија.

    Враћа листу (ниво_озбиљности, порука).
    """
    warnings: list[tuple[str, str]] = []

    if target_sdk is not None:
        if target_sdk < 28:
            warnings.append((
                "red",
                "targetSdk < 28: cleartext (HTTP) traffic is allowed "
                "by default",
            ))
        if target_sdk < 30:
            warnings.append((
                "yellow",
                "targetSdk < 30: legacy external storage model is used",
            ))
        if target_sdk < 31:
            warnings.append((
                "yellow",
                "targetSdk < 31: exported components do not require "
                "an explicit android:exported attribute",
            ))
        if target_sdk < 33:
            warnings.append((
                "dim",
                "targetSdk < 33: notifications do not require "
                "runtime permission",
            ))

    if min_sdk is not None:
        if min_sdk < 23:
            warnings.append((
                "yellow",
                "minSdk < 23: runtime permissions are not enforced "
                "on older devices",
            ))
        if min_sdk < 21:
            warnings.append((
                "red",
                "minSdk < 21: very old devices, no modern security "
                "features",
            ))

    return warnings


def _print_warnings(warnings: list[tuple[str, str]]) -> None:
    """Приказује безбедносна упозорења."""
    if not warnings:
        console.print(
            "\n[bold green]No security warnings for these SDK versions.[/bold green]\n"
        )
        return

    console.print(f"\n[bold]Warnings ({len(warnings)}):[/bold]\n")

    # Нивои озбиљности са читљивим ознакама.
    labels = {
        "red": ("HIGH", "bold red"),
        "yellow": ("MEDIUM", "yellow"),
        "dim": ("LOW", "dim"),
    }

    for level, message in warnings:
        label, color = labels.get(level, ("INFO", "white"))
        console.print(f"  [{color}]\\[{label}][/{color}]  {message}")

    console.print()