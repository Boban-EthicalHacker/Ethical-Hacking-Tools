# Модул за приказ TLS сертификата на систему.
# Чита системске CA сертификате, приватне кључеве,
# и додатне сертификате из различитих локација.
#
# Истекли сертификати, self-signed сертификати и слаби
# кључеви су безбедносни проблеми.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

console = Console()

# Директоријуми са сертификатима.
CA_DIRS = [
    Path("/etc/ssl/certs"),
    Path("/usr/local/share/ca-certificates"),
    Path("/etc/pki/ca-trust/source/anchors"),
]

# Директоријуми са приватним кључевима.
KEY_DIRS = [
    Path("/etc/ssl/private"),
    Path("/etc/pki/tls/private"),
]

# Максималан број сертификата које приказујемо.
MAX_DISPLAY = 20

# Минимална дужина RSA кључа (битова).
MIN_RSA_BITS = 2048


def run() -> dict:
    """Приказује TLS сертификате на систему.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]TLS certificates[/bold cyan]\n")

    # Проверавамо да ли је openssl доступан.
    if not shutil.which("openssl"):
        console.print(
            "  [yellow]openssl is not available.[/yellow]\n"
        )
        return _empty_result()

    # Читамо CA сертификате.
    ca_certs = _read_ca_certs()

    # Читамо приватне кључеве.
    private_keys = _read_private_keys()

    # Анализирамо.
    analysis = _analyze(ca_certs)

    # Правимо резиме.
    summary = {
        "total_ca_certs": len(ca_certs),
        "total_private_keys": len(private_keys),
        "expired": analysis.get("expired_count", 0),
        "expiring_soon": analysis.get("expiring_soon_count", 0),
        "self_signed": analysis.get("self_signed_count", 0),
        "weak_keys": analysis.get("weak_keys_count", 0),
    }

    data = {
        "ca_certs": ca_certs,
        "private_keys": private_keys,
        "analysis": analysis,
        "summary": summary,
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "ca_certs": [],
        "private_keys": [],
        "analysis": {},
        "summary": {
            "total_ca_certs": 0,
            "total_private_keys": 0,
            "expired": 0,
            "expiring_soon": 0,
            "self_signed": 0,
            "weak_keys": 0,
        },
    }


def _read_ca_certs() -> list[dict]:
    """Чита CA сертификате из системских директоријума.

    Због великог броја сертификата (обично 100+), читамо
    само основне информације за све.
    """
    certs = []
    seen_paths = set()

    # Фајлови које прескачемо — bundle фајлови који садрже
    # више сертификата, не појединачне.
    SKIP_FILES = {
        "ca-certificates.crt",
        "ca-bundle.crt",
        "tls-ca-bundle.pem",
        "cert.pem",
    }

    for ca_dir in CA_DIRS:
        if not ca_dir.exists() or not ca_dir.is_dir():
            continue

        try:
            entries = sorted(ca_dir.iterdir())
        except (PermissionError, Exception):
            continue

        for file_path in entries:
            # Прескачемо bundle фајлове.
            if file_path.name in SKIP_FILES:
                continue

            if file_path.is_symlink():
                # Пратимо symlink.
                try:
                    target = file_path.resolve()
                except Exception:
                    continue

                if str(target) in seen_paths:
                    continue
                seen_paths.add(str(target))

                cert = _read_certificate(target, str(file_path))
            elif file_path.is_file():
                if str(file_path) in seen_paths:
                    continue

                name = file_path.name

                # Филтрирамо само .crt, .pem и .cer.
                if not name.endswith((".crt", ".pem", ".cer")):
                    continue

                # Прескачемо hash симлинкове (обично су без екстензије).
                if len(name) == 8 and all(
                    c in "0123456789abcdef." for c in name
                ):
                    continue

                seen_paths.add(str(file_path))
                cert = _read_certificate(file_path, str(file_path))
            else:
                continue

            if cert:
                certs.append(cert)

    return certs

def _read_certificate(path: Path, original_path: str) -> dict | None:
    """Чита један сертификат."""
    if not path.exists():
        return None

    try:
        # Користимо openssl да извучемо информације.
        result = _run_openssl([
            "x509", "-in", str(path), "-noout",
            "-subject", "-issuer", "-dates",
            "-serial", "-fingerprint", "-sha256",
        ])

        if not result:
            return None

        cert = _parse_x509_output(result)
        cert["path"] = original_path
        if original_path != str(path):
            cert["real_path"] = str(path)

        # Извлачимо величину кључа.
        pubkey_info = _get_pubkey_info(path)
        if pubkey_info:
            cert.update(pubkey_info)

        return cert

    except Exception:
        return None


def _run_openssl(args: list[str]) -> str | None:
    """Покреће openssl команду."""
    try:
        proc = subprocess.run(
            ["openssl"] + args,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None


def _parse_x509_output(output: str) -> dict:
    """Парсира openssl x509 излаз."""
    result = {
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "serial": None,
        "fingerprint": None,
    }

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("subject="):
            result["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            result["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            result["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            result["not_after"] = line.split("=", 1)[1].strip()
        elif line.startswith("serial="):
            result["serial"] = line.split("=", 1)[1].strip()
        elif "Fingerprint=" in line:
            result["fingerprint"] = line.split("=", 1)[1].strip()

    return result


def _get_pubkey_info(path: Path) -> dict | None:
    """Извлачи информације о јавном кључу."""
    result = _run_openssl([
        "x509", "-in", str(path), "-noout", "-text",
    ])

    if not result:
        return None

    info = {
        "key_type": None,
        "key_bits": None,
        "signature_algorithm": None,
    }

    for line in result.splitlines():
        line = line.strip()

        if "Public Key Algorithm:" in line:
            info["key_type"] = line.split(":", 1)[1].strip()
        elif "Public-Key:" in line:
            # "(2048 bit)"
            try:
                bits = line.split("(")[1].split()[0]
                info["key_bits"] = int(bits)
            except (IndexError, ValueError):
                pass
        elif (
            "Signature Algorithm:" in line
            and info["signature_algorithm"] is None
        ):
            info["signature_algorithm"] = line.split(":", 1)[1].strip()

    return info


def _read_private_keys() -> list[dict]:
    """Чита приватне кључеве.

    Не читамо садржај кључева — само метаподатке (име, величину,
    permissions, тип).
    """
    keys = []

    for key_dir in KEY_DIRS:
        if not key_dir.exists() or not key_dir.is_dir():
            continue

        try:
            entries = sorted(key_dir.iterdir())
        except (PermissionError, Exception):
            continue

        for file_path in entries:
            if not file_path.is_file() and not file_path.is_symlink():
                continue

            entry = {
                "path": str(file_path),
                "name": file_path.name,
            }

            try:
                st = file_path.stat()
                entry["size_bytes"] = st.st_size
                entry["uid"] = st.st_uid
                entry["gid"] = st.st_gid
                entry["mode"] = _mode_to_string(st.st_mode)
            except Exception:
                pass

            # Проверавамо да ли је стварно кључ.
            key_info = _check_key_type(file_path)
            if key_info:
                entry.update(key_info)
            else:
                # Није кључ, прескачемо.
                continue

            keys.append(entry)

    return keys


def _check_key_type(path: Path) -> dict | None:
    """Проверава да ли је фајл приватан кључ и који тип."""
    # Читамо прву линију — кључеви имају "-BEGIN ... PRIVATE KEY-".
    try:
        with open(path, "rb") as f:
            first_line = f.readline(100).decode("utf-8", errors="replace")
    except (PermissionError, Exception):
        return None

    first_line = first_line.strip()

    if "PRIVATE KEY" not in first_line:
        return None

    # Препознајемо тип.
    if "RSA PRIVATE KEY" in first_line:
        key_type = "RSA"
    elif "EC PRIVATE KEY" in first_line:
        key_type = "EC"
    elif "DSA PRIVATE KEY" in first_line:
        key_type = "DSA"
    elif "OPENSSH PRIVATE KEY" in first_line:
        key_type = "OpenSSH"
    elif "ENCRYPTED PRIVATE KEY" in first_line:
        key_type = "Encrypted"
    elif "PRIVATE KEY" in first_line:
        key_type = "PKCS#8"
    else:
        key_type = "Unknown"

    return {
        "key_type": key_type,
        "encrypted": "ENCRYPTED" in first_line,
    }


def _mode_to_string(mode: int) -> str:
    """Конвертује mode у читљив облик (rwx...)."""
    import stat as stat_mod
    return stat_mod.filemode(mode)


def _analyze(ca_certs: list[dict]) -> dict:
    """Анализира CA сертификате.

    Важна напомена: root CA сертификати су по дефиницији
    self-signed (сами себе потписују). То је нормално.
    Означавамо само сертификате који НИСУ у стандардном
    системском trust store-у, јер су они сумњиви.
    """
    result = {
        "expired": [],
        "expiring_soon": [],
        "self_signed": [],
        "weak_keys": [],
        "expired_count": 0,
        "expiring_soon_count": 0,
        "self_signed_count": 0,
        "weak_keys_count": 0,
    }

    now = datetime.now(timezone.utc)

    for cert in ca_certs:
        # Проверавамо да ли је истекао.
        not_after = cert.get("not_after")
        if not_after:
            try:
                expiry = _parse_cert_date(not_after)
                if expiry:
                    if expiry < now:
                        result["expired"].append(cert)
                    elif (expiry - now).days < 30:
                        result["expiring_soon"].append(cert)
            except Exception:
                pass

        # Проверавамо да ли је self-signed.
        # Root CA сертификати су нормално self-signed.
        # Означавамо само оне који НИСУ у стандардном
        # системском trust store-у (/usr/share/ca-certificates).
        subject = cert.get("subject")
        issuer = cert.get("issuer")

        if subject and issuer and subject == issuer:
            real_path = cert.get("real_path", "") or ""
            original_path = cert.get("path", "") or ""

            # Ако је у стандардном mozilla trust store-у, прескачемо.
            is_standard = (
                "/usr/share/ca-certificates/mozilla/" in real_path
                or "/usr/share/ca-certificates/" in real_path
                or "/usr/share/pki/" in real_path
            )

            if not is_standard:
                result["self_signed"].append(cert)

        # Проверавамо величину кључа.
        key_bits = cert.get("key_bits")
        key_type = cert.get("key_type", "")

        if key_bits and "RSA" in (key_type or ""):
            if key_bits < MIN_RSA_BITS:
                result["weak_keys"].append(cert)

    # Бројеви.
    result["expired_count"] = len(result["expired"])
    result["expiring_soon_count"] = len(result["expiring_soon"])
    result["self_signed_count"] = len(result["self_signed"])
    result["weak_keys_count"] = len(result["weak_keys"])

    return result


def _parse_cert_date(date_str: str) -> datetime | None:
    """Парсира датум из openssl формата.

    Пример: "Jan 15 12:00:00 2030 GMT"
    """
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",  # два размака за једноцифрени дан
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            # Додајемо UTC timezone ако је GMT.
            if "GMT" in date_str:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    ca_certs = data.get("ca_certs", [])
    private_keys = data.get("private_keys", [])
    analysis = data.get("analysis", {})
    summary = data.get("summary", {})

    # Резиме.
    console.print(
        f"[bold]CA certificates:[/bold]    {summary.get('total_ca_certs', 0)}"
    )
    console.print(
        f"[bold]Private keys:[/bold]       {summary.get('total_private_keys', 0)}"
    )

    if summary.get("expired", 0) > 0:
        console.print(
            f"[bold red]Expired:[/bold red]            "
            f"{summary['expired']}"
        )

    if summary.get("expiring_soon", 0) > 0:
        console.print(
            f"[bold yellow]Expiring (30d):[/bold yellow]     "
            f"{summary['expiring_soon']}"
        )

    if summary.get("self_signed", 0) > 0:
        console.print(
            f"[bold yellow]Self-signed:[/bold yellow]        "
            f"{summary['self_signed']}"
        )

    if summary.get("weak_keys", 0) > 0:
        console.print(
            f"[bold red]Weak keys:[/bold red]          "
            f"{summary['weak_keys']}"
        )

    console.print()

    # Приказујемо проблеме.
    _print_issues(analysis)

    # Приватни кључеви.
    if private_keys:
        console.print(
            f"[bold]Private keys ({len(private_keys)}):[/bold]\n"
        )

        for key in private_keys[:MAX_DISPLAY]:
            _print_private_key(key)

        if len(private_keys) > MAX_DISPLAY:
            console.print(
                f"  [dim]... and "
                f"{len(private_keys) - MAX_DISPLAY} more[/dim]"
            )
        console.print()

    # CA сертификати.
    if ca_certs:
        show_count = min(MAX_DISPLAY, len(ca_certs))
        console.print(
            f"[bold]CA certificates ({len(ca_certs)}) — "
            f"showing first {show_count}:[/bold]\n"
        )

        for cert in ca_certs[:MAX_DISPLAY]:
            _print_cert(cert)

        if len(ca_certs) > MAX_DISPLAY:
            console.print(
                f"  [dim]... and {len(ca_certs) - MAX_DISPLAY} more[/dim]"
            )
        console.print()


def _print_issues(analysis: dict) -> None:
    """Приказује пронађене проблеме."""
    expired = analysis.get("expired", [])
    expiring = analysis.get("expiring_soon", [])
    self_signed = analysis.get("self_signed", [])
    weak = analysis.get("weak_keys", [])

    if not any([expired, expiring, self_signed, weak]):
        console.print(
            "[bold green]No issues found in CA certificates.[/bold green]\n"
        )
        return

    # Истекли.
    if expired:
        console.print(
            f"[bold red]Expired certificates "
            f"({len(expired)}):[/bold red]\n"
        )
        for cert in expired[:5]:
            console.print(f"  [red]{cert.get('path')}[/red]")
            console.print(
                f"    [dim]Not after: {cert.get('not_after')}[/dim]"
            )
        if len(expired) > 5:
            console.print(
                f"  [dim]... and {len(expired) - 5} more[/dim]"
            )
        console.print()

    # Ускоро истичу.
    if expiring:
        console.print(
            f"[bold yellow]Expiring soon "
            f"({len(expiring)}):[/bold yellow]\n"
        )
        for cert in expiring[:5]:
            console.print(f"  [yellow]{cert.get('path')}[/yellow]")
            console.print(
                f"    [dim]Not after: {cert.get('not_after')}[/dim]"
            )
        if len(expiring) > 5:
            console.print(
                f"  [dim]... and {len(expiring) - 5} more[/dim]"
            )
        console.print()

    # Self-signed (не-стандардни).
    if self_signed:
        console.print(
            f"[bold yellow]Non-standard self-signed certificates "
            f"({len(self_signed)}):[/bold yellow]\n"
        )
        for cert in self_signed[:5]:
            subject = cert.get("subject", "")
            if len(subject) > 70:
                subject = subject[:67] + "..."
            console.print(
                f"  [yellow]{cert.get('path')}[/yellow]"
            )
            console.print(f"    [dim]Subject: {subject}[/dim]")
        if len(self_signed) > 5:
            console.print(
                f"  [dim]... and {len(self_signed) - 5} more[/dim]"
            )
        console.print()

    # Слаби кључеви.
    if weak:
        console.print(
            f"[bold red]Weak keys (< {MIN_RSA_BITS} bits) "
            f"({len(weak)}):[/bold red]\n"
        )
        for cert in weak[:5]:
            console.print(f"  [red]{cert.get('path')}[/red]")
            console.print(
                f"    [dim]{cert.get('key_type')} "
                f"{cert.get('key_bits')} bits[/dim]"
            )
        if len(weak) > 5:
            console.print(
                f"  [dim]... and {len(weak) - 5} more[/dim]"
            )
        console.print()


def _print_cert(cert: dict) -> None:
    """Приказује један сертификат."""
    path = cert.get("path", "?")
    subject = cert.get("subject", "")
    key_type = cert.get("key_type", "")
    key_bits = cert.get("key_bits", "")
    not_after = cert.get("not_after", "")

    # Скраћујемо.
    if len(subject) > 60:
        subject = subject[:57] + "..."

    # Име фајла.
    name = Path(path).name

    console.print(f"  [bold]{name}[/bold]")

    if subject:
        console.print(f"    Subject: {subject}")

    if key_type and key_bits:
        console.print(
            f"    Key:     {key_type} {key_bits} bits"
        )

    if not_after:
        console.print(f"    Expires: [dim]{not_after}[/dim]")


def _print_private_key(key: dict) -> None:
    """Приказује један приватан кључ."""
    path = key.get("path", "?")
    name = key.get("name", "?")
    key_type = key.get("key_type", "?")
    encrypted = key.get("encrypted", False)
    mode = key.get("mode", "")

    # Боја — црвено ако није шифрован.
    if encrypted:
        color = "green"
        enc_marker = "[green]encrypted[/green]"
    else:
        color = "yellow"
        enc_marker = "[yellow]NOT encrypted[/yellow]"

    console.print(
        f"  [{color}]{name}[/{color}]  "
        f"[dim]({key_type})[/dim]"
    )
    console.print(f"    Path:     [dim]{path}[/dim]")
    console.print(f"    Status:   {enc_marker}")

    if mode:
        console.print(f"    Mode:     {mode}")

    console.print()