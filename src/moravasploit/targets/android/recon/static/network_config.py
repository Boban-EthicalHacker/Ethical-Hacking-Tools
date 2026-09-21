# Модул за приказ мрежне безбедносне конфигурације апликације.
# Проверава да ли апликација дозвољава нешифровани (cleartext) саобраћај,
# које сертификате прихвата и да ли користи certificate pinning.
import zipfile

from lxml import etree
from pyaxmlparser.axmlprinter import AXMLPrinter
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Андроид namespace за атрибуте у манифесту.
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def run() -> None:
    """Приказује мрежну безбедносну конфигурацију апликације."""
    result = load_apk()
    if result is None:
        return

    apk_path, apk = result

    console.print("\n[bold cyan]Network security configuration[/bold cyan]\n")

    # Прво читамо шта манифест каже.
    cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
    config_path = apk.get_attribute_value(
        "application", "networkSecurityConfig"
    )

    _print_manifest_settings(cleartext, config_path)

    # Ако постоји посебан network security config фајл, парсирамо га.
    if config_path:
        _print_config_file(apk_path, config_path)
    else:
        console.print(
            "[dim]No dedicated network security config file.[/dim]\n"
        )


def _print_manifest_settings(cleartext, config_path) -> None:
    """Приказује подешавања из манифеста."""
    console.print("[bold]From AndroidManifest.xml[/bold]\n")

    # usesCleartextTraffic: ако није наведено, подразумевано је false
    # за Android 9+ (API 28+), али true за старије верзије.
    if cleartext is None:
        console.print(
            "[bold]Uses cleartext traffic:[/bold] "
            "[yellow]not specified[/yellow] "
            "[dim](defaults to false on Android 9+)[/dim]"
        )
    elif str(cleartext).lower() == "true":
        console.print(
            "[bold]Uses cleartext traffic:[/bold] "
            "[bold red]TRUE[/bold red] "
            "[dim](allows unencrypted HTTP)[/dim]"
        )
    else:
        console.print(
            "[bold]Uses cleartext traffic:[/bold] "
            "[green]false[/green]"
        )

    # Путања до посебног конфиг фајла.
    if config_path:
        console.print(f"[bold]Network security config:[/bold] {config_path}")
    else:
        console.print("[bold]Network security config:[/bold] [dim]not set[/dim]")

    console.print()


def _print_config_file(apk_path, config_path: str) -> None:
    """Чита и приказује network security config фајл."""
    console.print("[bold]From network security config[/bold]\n")

    # Отварамо APK као ZIP и тражимо све XML фајлове у res/.
    # Пошто F-Droid (и многе друге апликације) користе обфускацију
    # имена ресурса, не можемо да тражимо по имену. Уместо тога,
    # пролазимо кроз све XML фајлове и тражимо онај чији је
    # коренски елемент 'network-security-config'.
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            xml_files = [
                name
                for name in z.namelist()
                if name.startswith("res/") and name.endswith(".xml")
            ]

            if not xml_files:
                console.print(
                    "  [red]No XML files found in res/.[/red]\n"
                )
                return

            # Пролазимо кроз све XML фајлове и тражимо прави.
            root = _find_network_config(z, xml_files)

        if root is None:
            console.print(
                "  [red]Network security config not found in APK.[/red]\n"
            )
            return

    except Exception as error:
        console.print(f"  [red]Failed to read config:[/red] {error}\n")
        return

    # Приказујемо основно подешавање cleartext-a.
    base_config = root.find("base-config")
    if base_config is not None:
        cleartext = base_config.get(
            "{http://schemas.android.com/apk/res/android}cleartextTrafficPermitted"
        )
        if cleartext is not None:
            if cleartext.lower() == "true":
                console.print(
                    "  [bold]Base config cleartext:[/bold] "
                    "[bold red]permitted[/bold red]"
                )
            else:
                console.print(
                    "  [bold]Base config cleartext:[/bold] "
                    "[green]not permitted[/green]"
                )

    # Trust anchors (које сертификате апликација прихвата).
    trust_anchors = root.findall(".//trust-anchors")
    if trust_anchors:
        console.print(
            f"  [bold]Trust anchors:[/bold] {len(trust_anchors)} block(s)"
        )

    # Certificate pinning.
    pin_sets = root.findall(".//pin-set")
    if pin_sets:
        console.print(
            f"  [bold]Pin sets:[/bold] {len(pin_sets)} "
            "[green](certificate pinning in use)[/green]"
        )
    else:
        console.print(
            "  [bold]Pin sets:[/bold] [yellow]none[/yellow] "
            "[dim](no certificate pinning)[/dim]"
        )

    # Domain-specific правила.
    domains = root.findall(".//domain-config")
    if domains:
        console.print(
            f"  [bold]Domain-specific rules:[/bold] {len(domains)}"
        )

    console.print()


def _find_network_config(zip_file, xml_files: list[str]):
    """Проналази network security config XML у листи фајлова.

    Враћа root елемент ако је пронађен, иначе None.
    """
    for name in xml_files:
        try:
            data = zip_file.read(name)
            printer = AXMLPrinter(data)
            xml_bytes = printer.get_xml()
            root = etree.fromstring(xml_bytes)
        except Exception:
            # Неки XML фајлови нису у бинарном Android формату.
            # Прескачемо их.
            continue

        # Проверавамо да ли је ово network security config.
        if root.tag == "network-security-config":
            console.print(f"  [dim]Found: {name}[/dim]\n")
            return root

    return None