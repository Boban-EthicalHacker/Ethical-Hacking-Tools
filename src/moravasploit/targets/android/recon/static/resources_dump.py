# Модул за приказ стринг ресурса из resources.arsc.
# Ово су текстови из res/values/strings.xml који су након
# компајлирања смештени у бинарни resources.arsc фајл.
import zipfile

from pyaxmlparser.arscparser import ARSCParser
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Максималан број стрингова који приказујемо.
MAX_STRINGS = 300

# Максимална дужина вредности пре скраћивања.
MAX_VALUE_LENGTH = 80

# Максималан број линија сировог XML-а који приказујемо.
MAX_LINES = 60


def run() -> None:
    """Приказује стринг ресурсе из resources.arsc."""
    result = load_apk()
    if result is None:
        return

    apk_path, _ = result

    console.print("\n[bold cyan]Resources dump[/bold cyan]\n")

    # Читамо resources.arsc из APK-а.
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            arsc_data = z.read("resources.arsc")
    except KeyError:
        console.print("[red]resources.arsc not found in APK.[/red]\n")
        return
    except Exception as error:
        console.print(f"[red]Failed to read resources.arsc:[/red] {error}\n")
        return

    # Парсирамо табелу ресурса.
    try:
        arsc = ARSCParser(arsc_data)
    except Exception as error:
        console.print(f"[red]Failed to parse resources table:[/red] {error}\n")
        return

    # Приказујемо основне информације.
    _print_summary(arsc)

    # Приказујемо стринг ресурсе.
    _print_strings(arsc)


def _print_summary(arsc) -> None:
    """Приказује број пакета, локала и типова ресурса."""
    try:
        packages = arsc.get_packages_names()
    except Exception:
        packages = []

    if not packages:
        console.print("  [dim]No packages in resources table.[/dim]\n")
        return

    console.print(f"[bold]Packages:[/bold] {len(packages)}\n")

    for pkg_name in packages:
        console.print(f"[bold cyan]Package: {pkg_name}[/bold cyan]\n")

        # Локали.
        try:
            locales = arsc.get_locales(pkg_name)
        except Exception:
            locales = []

        if locales:
            console.print(f"  [bold]Locales:[/bold] {len(locales)}")
            preview = [loc for loc in locales[:8] if loc]
            console.print(f"  [dim]{', '.join(preview)}[/dim]")
            if len(locales) > 8:
                console.print(f"  [dim]... and {len(locales) - 8} more[/dim]")

        # Типови ресурса.
        try:
            types = arsc.get_types(pkg_name, "")
        except Exception:
            types = []

        if types:
            console.print(f"  [bold]Resource types:[/bold] {len(types)}")
            console.print(f"  [dim]{', '.join(sorted(types))}[/dim]")

        console.print()


def _print_strings(arsc) -> None:
    """Приказује стринг ресурсе из табеле."""
    try:
        strings = arsc.get_strings_resources()
    except Exception as error:
        console.print(f"[red]Failed to read strings:[/red] {error}\n")
        return

    if not strings:
        console.print("  [dim]No string resources found.[/dim]\n")
        return

    # Ако је резултат речник, приказујемо га директно.
    if isinstance(strings, dict):
        total = len(strings)
        console.print(f"[bold]String resources:[/bold] {total}\n")

        shown = 0
        for key in sorted(strings.keys()):
            if shown >= MAX_STRINGS:
                remaining = total - MAX_STRINGS
                console.print(f"  [dim]... and {remaining} more[/dim]")
                break

            value = strings[key]
            if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
                value = value[: MAX_VALUE_LENGTH - 3] + "..."

            console.print(f"  [dim]{key}[/dim] = {value}")
            shown += 1

        console.print()
        return

    # Ако је резултат bytes, декодирамо га као текст.
    if isinstance(strings, bytes):
        try:
            text = strings.decode("utf-8", errors="replace")
        except Exception as error:
            console.print(f"[red]Failed to decode:[/red] {error}\n")
            return

        # Бројимо линије.
        lines = text.splitlines()
        total = len(lines)

        console.print(
            f"[bold]String resources (raw XML):[/bold] "
            f"{len(strings)} bytes, {total} lines\n"
        )

        # Приказујемо само првих MAX_LINES линија.
        for line in lines[:MAX_LINES]:
            console.print(f"  {line}")

        if total > MAX_LINES:
            console.print(
                f"  [dim]... and {total - MAX_LINES} more lines[/dim]"
            )

        console.print()
        return

    # Ако није ни речник ни bytes, приказујемо шта смо добили.
    console.print(f"[bold]String resources:[/bold] {len(strings)}\n")
    for item in list(strings)[:MAX_STRINGS]:
        console.print(f"  {item}")
    console.print()