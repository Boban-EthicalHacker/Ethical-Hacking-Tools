# Модул за проверу App Transport Security (ATS) подешавања.
# ATS је Apple-ов механизам који захтева шифровану (HTTPS)
# комуникацију. Ако апликација жели да користи нешифровани
# HTTP, мора то експлицитно да дозволи у Info.plist-у.
#
# Ако апликација дозвољава HTTP, сва комуникација може бити
# пресретнута на мрежи. Ово је безбедносни проблем.
from rich.console import Console

from moravasploit.targets.ios.recon.static._loader import load_ipa

console = Console()

# Кључ у Info.plist-у где се налази ATS конфигурација.
ATS_KEY = "NSAppTransportSecurity"


def run() -> None:
    """Проверава ATS подешавања апликације."""
    result = load_ipa()
    if result is None:
        return

    _, info, _ = result

    console.print("\n[bold cyan]App Transport Security[/bold cyan]\n")

    # Проверавамо да ли постоји ATS конфигурација.
    ats = info.get(ATS_KEY)

    # Ако нема ATS кључа, апликација користи подразумевано понашање.
    if ats is None:
        console.print(
            "[bold green]No custom ATS configuration.[/bold green]\n"
        )
        console.print(
            "  The app uses default ATS behavior: [green]HTTPS required, "
            "HTTP blocked[/green].\n"
        )
        console.print(
            "  [dim]This is the secure default. No action needed.[/dim]\n"
        )
        return

    if not isinstance(ats, dict):
        console.print(
            "  [red]Invalid ATS configuration format.[/red]\n"
        )
        return

    # Прикупљамо упозорења.
    warnings = []

    # Главно подешавање — да ли дозвољава све HTTP.
    _print_arbitrary_loads(ats, warnings)

    # Дозвољени изузеци по доменима.
    _print_exception_domains(ats, warnings)

    # Остала подешавања.
    _print_other_settings(ats)

    # Приказујемо закључак.
    _print_conclusion(warnings)


def _print_arbitrary_loads(ats: dict, warnings: list) -> None:
    """Проверава NSAllowsArbitraryLoads."""
    console.print("[bold]Main settings[/bold]\n")

    # NSAllowsArbitraryLoads — главни прекидач.
    # Ако је true, апликација може да користи HTTP ка било ком домену.
    arbitrary = ats.get("NSAllowsArbitraryLoads")

    if arbitrary is True:
        console.print(
            "  [bold]NSAllowsArbitraryLoads:[/bold]  "
            "[bold red]TRUE[/bold red]"
        )
        console.print(
            "    [red]Allows unencrypted HTTP to any domain. "
            "Serious security issue.[/red]"
        )
        warnings.append(
            "NSAllowsArbitraryLoads is enabled — all HTTP is allowed"
        )
    elif arbitrary is False:
        console.print(
            "  [bold]NSAllowsArbitraryLoads:[/bold]  "
            "[green]FALSE[/green]"
        )
        console.print(
            "    [dim]HTTP blocked by default.[/dim]"
        )

    # NSAllowsArbitraryLoadsInWebContent — за WebView.
    web_content = ats.get("NSAllowsArbitraryLoadsInWebContent")
    if web_content is True:
        console.print(
            "  [bold]NSAllowsArbitraryLoadsInWebContent:[/bold]  "
            "[yellow]TRUE[/yellow]"
        )
        console.print(
            "    [yellow]WebView може да учита HTTP садржај.[/yellow]"
        )
        warnings.append(
            "WebView allows arbitrary HTTP content"
        )

    # NSAllowsArbitraryLoadsForMedia — за медије.
    media = ats.get("NSAllowsArbitraryLoadsForMedia")
    if media is True:
        console.print(
            "  [bold]NSAllowsArbitraryLoadsForMedia:[/bold]  "
            "[yellow]TRUE[/yellow]"
        )
        console.print(
            "    [yellow]Медијски садржај може да се учита преко HTTP.[/yellow]"
        )
        warnings.append(
            "Media content can be loaded over HTTP"
        )

    # NSAllowsLocalNetworking — за локалну мрежу.
    local = ats.get("NSAllowsLocalNetworking")
    if local is True:
        console.print(
            "  [bold]NSAllowsLocalNetworking:[/bold]  "
            "[dim]TRUE[/dim]"
        )
        console.print(
            "    [dim]Дозвољава HTTP за локалне адресе (нпр. 127.0.0.1).[/dim]"
        )

    console.print()


def _print_exception_domains(ats: dict, warnings: list) -> None:
    """Приказује изузетке по доменима."""
    domains = ats.get("NSExceptionDomains")

    if not domains:
        return

    console.print(f"[bold]Exception domains ({len(domains)})[/bold]\n")

    for domain, config in sorted(domains.items()):
        if not isinstance(config, dict):
            continue

        # Да ли овај домен дозвољава HTTP.
        allows_http = config.get("NSExceptionAllowsInsecureHTTPLoads")
        includes_subdomains = config.get("NSIncludesSubdomains")

        if allows_http is True:
            console.print(
                f"  [bold red]{domain}[/bold red] "
                "— insecure HTTP allowed"
            )
            warnings.append(
                f"Domain {domain} allows insecure HTTP"
            )
        else:
            console.print(f"  [dim]{domain}[/dim]")

        if includes_subdomains is True:
            console.print("    [dim]includes subdomains[/dim]")

        # Минимална верзија TLS-а.
        min_tls = config.get("NSExceptionMinimumTLSVersion")
        if min_tls:
            console.print(
                f"    minimum TLS: {min_tls}"
            )

    console.print()


def _print_other_settings(ats: dict) -> None:
    """Приказује остала ATS подешавања."""
    # NSRequiresCertificateTransparency
    requires_ct = ats.get("NSRequiresCertificateTransparency")
    if requires_ct is True:
        console.print(
            "[bold]NSRequiresCertificateTransparency:[/bold]  "
            "[green]TRUE[/green]"
        )
        console.print(
            "  [dim]Захтева Certificate Transparency за TLS "
            "сертификате.[/dim]\n"
        )

    # NSAllowsArbitraryLoadsInWebContent (већ приказано горе).
    # Може се додати још, али ово је довољно за основну проверу.


def _print_conclusion(warnings: list) -> None:
    """Приказује закључак на основу упозорења."""
    if not warnings:
        console.print(
            "[bold green]Conclusion: ATS configuration is secure.[/bold green]\n"
        )
        return

    console.print(
        f"[bold red]Conclusion: {len(warnings)} security issue(s) found.[/bold red]\n"
    )

    for warning in warnings:
        console.print(f"  [red]• {warning}[/red]")

    console.print()