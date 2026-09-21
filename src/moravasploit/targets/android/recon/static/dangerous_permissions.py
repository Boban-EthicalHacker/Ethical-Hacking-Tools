# Модул за приказ опасних дозвола које апликација тражи.
# Опасне дозволе су оне које могу да угрозе приватност корисника
# или безбедност уређаја. Све остале дозволе се само преброје.
from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# Скуп опасних дозвола. Свака је наведена пуним именом без префикса.
# Листа је заснована на званичној Android класификацији опасних
# дозвола, плус неколико које су често злоупотребљене.
DANGEROUS = {
    # Камера и микрофон
    "CAMERA",
    "RECORD_AUDIO",
    "BODY_SENSORS",
    "ACTIVITY_RECOGNITION",

    # Локација
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",

    # Контакти и налози
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "GET_ACCOUNTS",

    # Календар
    "READ_CALENDAR",
    "WRITE_CALENDAR",

    # СМС и ММС
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "RECEIVE_MMS",
    "RECEIVE_WAP_PUSH",
    "READ_CELL_BROADCASTS",

    # Позиви
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "CALL_PHONE",
    "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS",
    "ANSWER_PHONE_CALLS",
    "ADD_VOICEMAIL",
    "USE_SIP",
    "PROCESS_OUTGOING_CALLS",

    # Складиште
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE",

    # Блутут
    "BLUETOOTH_SCAN",
    "BLUETOOTH_CONNECT",
    "BLUETOOTH_ADVERTISE",

    # Остало
    "POST_NOTIFICATIONS",
    "NEARBY_WIFI_DEVICES",
    "QUERY_ALL_PACKAGES",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "PACKAGE_USAGE_STATS",
}


def run() -> None:
    """Приказује опасне дозволе које апликација тражи."""
    result = load_apk()
    if result is None:
        return

    _, apk = result

    # Узимамо све дозволе.
    permissions = apk.get_permissions() or []

    console.print("\n[bold cyan]Dangerous permissions[/bold cyan]\n")

    # Раздвајамо опасне од осталих.
    dangerous = []
    safe_count = 0

    for perm in permissions:
        # Узимамо само последњи део имена (после последње тачке).
        short = perm.rsplit(".", 1)[-1]
        if short in DANGEROUS:
            dangerous.append((perm, short))
        else:
            safe_count += 1

    if not dangerous:
        console.print(
            "  [green]No dangerous permissions found.[/green]\n"
        )
        console.print(f"[bold]Total permissions:[/bold] {len(permissions)}")
        console.print(f"[bold]Safe permissions:[/bold] {safe_count}\n")
        return

    # Приказујемо опасне дозволе црвено, једну по једну.
    console.print(f"[bold red]Found {len(dangerous)} dangerous permission(s):[/bold red]\n")

    for full, _ in sorted(dangerous):
        console.print(f"  [bold red]{full}[/bold red]")

    console.print()
    console.print(f"[bold]Total permissions:[/bold] {len(permissions)}")
    console.print(f"[bold red]Dangerous:[/bold red] {len(dangerous)}")
    console.print(f"[bold green]Other:[/bold green] {safe_count}\n")