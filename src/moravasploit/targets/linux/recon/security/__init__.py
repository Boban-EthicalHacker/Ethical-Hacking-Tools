# Модул за Linux / recon / security категорију.
# Приказује модуле за безбедносне контроле.
from rich.console import Console

from moravasploit.core.menu import ask_select
from moravasploit.core.session import save
from moravasploit.targets.linux.recon.security import (
    audit_rules,
    fail2ban,
    security_modules,
    selinux_apparmor,
    sshd_config,
    tls_certs,
)

console = Console()

MODULES: dict[str, tuple[str, object]] = {
    "selinux_apparmor": ("SELinux and AppArmor", selinux_apparmor.run),
    "fail2ban": ("Fail2ban", fail2ban.run),
    "audit_rules": ("Audit rules", audit_rules.run),
    "sshd_config": ("SSH server config", sshd_config.run),
    "tls_certs": ("TLS certificates", tls_certs.run),
    "security_modules": ("Kernel security", security_modules.run),
}


def menu() -> None:
    """Приказује мени модула за security категорију."""
    while True:
        console.print(
            "\n[bold]Linux / recon / security - choose module:[/bold]\n"
        )

        if not MODULES:
            console.print("  [dim]No modules yet.[/dim]\n")
            choice = ask_select([])
            if choice is None:
                return
            continue

        options = [
            (key, description) for key, (description, _) in MODULES.items()
        ]
        choice = ask_select(options)

        if choice is None:
            return

        _, run_function = MODULES[choice]
        result = run_function()
        saved_path = save(choice, result)

        if saved_path is not None:
            console.print(f"[dim]Saved to: {saved_path}[/dim]")