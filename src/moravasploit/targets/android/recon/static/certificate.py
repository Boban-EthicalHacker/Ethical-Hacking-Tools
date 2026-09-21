# Модул за приказ сертификата којим је апликација потписана.
# Ово је важно за проверу да ли је апликација оригинална
# или је неко модификовао и поново потписао.
import hashlib

from rich.console import Console

from moravasploit.targets.android.recon.static._loader import load_apk

console = Console()


def run() -> None:
    """Приказује сертификат (или сертификате) којим је APK потписан."""
    result = load_apk()
    if result is None:
        return

    _, apk = result

    console.print("\n[bold cyan]Certificate[/bold cyan]\n")

    # Узимамо листу сертификата из APK-а.
    try:
        certificates = apk.get_certificates()
    except Exception as error:
        console.print(f"[red]Failed to read certificates:[/red] {error}\n")
        return

    if not certificates:
        console.print("  [dim]No certificates found.[/dim]\n")
        return

    console.print(f"[bold]Signers:[/bold] {len(certificates)}\n")

    for index, cert in enumerate(certificates, start=1):
        _print_certificate(index, cert)


def _print_certificate(index: int, cert) -> None:
    """Приказује детаље једног сертификата."""
    console.print(f"[bold]Certificate #{index}[/bold]\n")

    # Име субјекта (власник сертификата).
    subject = cert.subject.human_friendly
    console.print(f"[bold]Subject:[/bold]         {subject}")

    # Име издаваоца.
    issuer = cert.issuer.human_friendly
    console.print(f"[bold]Issuer:[/bold]          {issuer}")

    # Период важности.
    validity = cert["tbs_certificate"]["validity"]
    not_before = validity["not_before"].native
    not_after = validity["not_after"].native
    console.print(f"[bold]Valid from:[/bold]      {not_before}")
    console.print(f"[bold]Valid to:[/bold]        {not_after}")

    # Алгоритам потписа.
    console.print(f"[bold]Signature algo:[/bold]  {cert.signature_algo}")

    # Отисци. Рачунамо их из DER кодирања сертификата.
    der_bytes = cert.dump()

    sha1 = hashlib.sha1(der_bytes).hexdigest()
    sha256 = hashlib.sha256(der_bytes).hexdigest()

    console.print(f"[bold]SHA-1:[/bold]           {sha1}")
    console.print(f"[bold]SHA-256:[/bold]         {sha256}")

    console.print()