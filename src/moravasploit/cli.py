from rich.console import Console
from rich.panel import Panel

from moravasploit import __version__

console = Console()


def main() -> None:
    """Prikazuje pozdravnu poruku pri pokretanju."""
    text = (
        f"[bold cyan]MoravaSploit[/bold cyan] v{__version__}\n\n"
        "Open-source tool for authorized security testing\n"
        "of systems and networks.\n\n"
        "[bold]License:[/bold] PolyForm Noncommercial 1.0.0\n"
        "[bold]Development started:[/bold] 2026\n\n"
        "[yellow]Use only on systems and networks you own\n"
        "or have explicit written permission to test.[/yellow]"
    )
    console.print(Panel(text, border_style="cyan", title="MoravaSploit"))