# Модул за претрагу текстуалних образаца у APK фајлу.
# Тражи URL-ове, IP адресе, емаил адресе и познате API кључеве.
# Обрасци се траже у свим фајловима унутар APK-а, јер DEX фајлови
# чувају стрингове у скоро читљивом облику.
import ipaddress
import re
import zipfile

from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()

# URL: http:// или https:// праћено дозвољеним знаковима.
URL_RE = re.compile(
    rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}"
)

# IPv4 адреса.
IP_RE = re.compile(
    rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Емаил адреса - строжи образац.
# Локални део мора да почне словом или бројем, не тачком.
# Домен мора да има бар једну тачку и TLD од 2-10 слова.
EMAIL_RE = re.compile(
    rb"\b[a-zA-Z0-9][a-zA-Z0-9._%+\-]{1,62}"
    rb"@"
    rb"[a-zA-Z0-9][a-zA-Z0-9\-]{1,62}"
    rb"(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})*"
    rb"\.[a-zA-Z]{2,10}\b"
)

# Познати API кључеви (само неки од најчешћих).
API_KEYS = {
    "AWS Access Key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(rb"AIza[0-9A-Za-z_\-]{35}"),
    "OpenAI Key": re.compile(rb"sk-[a-zA-Z0-9]{20,}"),
    "Stripe Live Key": re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"),
    "GitHub Token": re.compile(rb"gh[ps]_[a-zA-Z0-9]{36,}"),
}

# Познати OID префикси (Object Identifiers).
# Ови бројеви изгледају као IPv4 адресе, али нису.
# Налазе се у сертификатима и ASN.1 структурама.
OID_PREFIXES = (
    b"0.0.",
    b"0.4.",
    b"0.9.",
    b"0.15.",
    b"1.0.",
    b"1.1.",
    b"1.2.",
    b"1.3.",
    b"1.9.",
    b"2.5.",
    b"2.16.",
    b"2.49.",
    b"2.999.",
    b"3.1.",
    b"4.1.",
    b"5.5.",
    b"7.1.",
    b"61.1.",
    b"101.3.",
)

# Познати namespace URL-ови који нису прави сервери.
# Ово су XML и стандардни namespace-ови, не мрежни ресурси.
NAMESPACE_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://purl.org",
    "http://xml.org",
    "http://www.apache.org",
    "http://www.mozilla.org",
    "http://www.inkscape.org",
    "http://www.adobe.com",
    "http://ns.adobe.com",
    "http://www.bouncycastle.org",
    "http://www.slf4j.org",
    "http://logback.qos.ch",
    "http://creativecommons.org",
    "https://spdx.org",
    "https://www.bouncycastle.org",
    "https://www.slf4j.org",
)

# Максимална величина фајла који читамо (у бајтовима).
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB


def run() -> None:
    """Претражује APK фајл за текстуалним обрасцима."""
    result = load_apk()
    if result is None:
        return

    apk_path, _ = result

    console.print("\n[bold cyan]Strings scan[/bold cyan]\n")

    # Скупови за чување јединствених резултата.
    urls: set[str] = set()
    ips: set[str] = set()
    emails: set[str] = set()
    api_keys: dict[str, set[str]] = {name: set() for name in API_KEYS}

    # Отварамо APK као ZIP.
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            for name in z.namelist():
                info = z.getinfo(name)

                # Прескачемо превелике фајлове.
                if info.file_size > MAX_FILE_SIZE:
                    continue

                try:
                    data = z.read(name)
                except Exception:
                    continue

                # URL-ови - филтрирамо namespace-ове.
                for match in URL_RE.findall(data):
                    text = match.decode("utf-8", errors="replace")
                    if not _is_namespace(text):
                        urls.add(text)

                # IP адресе - филтрирамо OID-ове и невалидне.
                for match in IP_RE.findall(data):
                    if _is_valid_ip(match):
                        ips.add(match.decode("ascii"))

                # Емаил адресе.
                for match in EMAIL_RE.findall(data):
                    text = match.decode("utf-8", errors="replace")
                    emails.add(text)

                # API кључеви.
                for key_name, pattern in API_KEYS.items():
                    for match in pattern.findall(data):
                        text = match.decode("utf-8", errors="replace")
                        api_keys[key_name].add(text)

    except Exception as error:
        console.print(f"[red]Failed to scan APK:[/red] {error}\n")
        return

    # Приказујемо резултате.
    _print_section("URLs", urls)
    _print_section("IP addresses", ips)
    _print_section("Email addresses", emails)
    _print_api_keys(api_keys)


def _is_namespace(url: str) -> bool:
    """Проверава да ли је URL познати namespace."""
    for prefix in NAMESPACE_PREFIXES:
        if url.startswith(prefix):
            return True
    return False


def _is_valid_ip(raw: bytes) -> bool:
    """Проверава да ли је пронађени низ стварна IP адреса.

    Одбацује OID-ове и невалидне адресе.
    """
    # Прво проверавамо OID префиксе.
    for prefix in OID_PREFIXES:
        if raw.startswith(prefix):
            return False

    # Проверавамо да ли је валидна IPv4 адреса.
    try:
        ip = ipaddress.IPv4Address(raw.decode("ascii"))
    except (ipaddress.AddressValueError, UnicodeDecodeError):
        return False

    # Одбацујемо broadcast.
    if ip == ipaddress.IPv4Address("255.255.255.255"):
        return False

    # Прихватамо приватне, loopback и multicast адресе.
    # Одбацујемо све остало са првим октетом мањим од 8
    # (вероватно OID који није у листи префикса).
    first_octet = int(str(ip).split(".")[0])
    if first_octet < 8 and not (ip.is_private or ip.is_loopback):
        return False

    return True


def _print_section(title: str, items: set[str]) -> None:
    """Приказује једну секцију резултата."""
    console.print(f"[bold]{title}[/bold] ({len(items)})\n")

    if not items:
        console.print("  [dim]None found.[/dim]\n")
        return

    for item in sorted(items):
        console.print(f"  {item}")

    console.print()


def _print_api_keys(api_keys: dict[str, set[str]]) -> None:
    """Приказује пронађене API кључеве."""
    total = sum(len(v) for v in api_keys.values())

    console.print(f"[bold]API keys[/bold] ({total})\n")

    if total == 0:
        console.print("  [dim]None found.[/dim]\n")
        return

    for name, keys in api_keys.items():
        if not keys:
            continue

        console.print(f"  [bold red]{name}:[/bold red]")
        for key in sorted(keys):
            console.print(f"    [red]{key}[/red]")
        console.print()