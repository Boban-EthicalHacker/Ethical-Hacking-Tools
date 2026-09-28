# Модул за Linux / recon категорију.
# Приказује мени подкатегорија за извиђање Linux система.
from rich.console import Console

from moravasploit.core.menu import ask_select

# Увозимо подменије за сваку подкатегорију.
from moravasploit.targets.linux.recon.system import menu as system_menu
from moravasploit.targets.linux.recon.users import menu as users_menu
from moravasploit.targets.linux.recon.filesystem import menu as filesystem_menu
from moravasploit.targets.linux.recon.network import menu as network_menu
from moravasploit.targets.linux.recon.services import menu as services_menu
from moravasploit.targets.linux.recon.software import menu as software_menu
from moravasploit.targets.linux.recon.security import menu as security_menu
from moravasploit.targets.linux.recon.credentials import menu as credentials_menu
from moravasploit.targets.linux.recon.logs import menu as logs_menu

console = Console()

# Речник подкатегорија.
# Кључ је интерно име, вредност је опис.
SUBCATEGORIES = {
    "system": "System information",
    "users": "Users and privileges",
    "filesystem": "Filesystem and permissions",
    "network": "Network configuration",
    "services": "Services and processes",
    "software": "Installed software",
    "security": "Security controls",
    "credentials": "Credentials and secrets",
    "logs": "Log files",
}

# Речник који повезује подкатегорију са њеном menu() функцијом.
SUBCATEGORY_MENUS = {
    "system": system_menu,
    "users": users_menu,
    "filesystem": filesystem_menu,
    "network": network_menu,
    "services": services_menu,
    "software": software_menu,
    "security": security_menu,
    "credentials": credentials_menu,
    "logs": logs_menu,
}


def menu() -> None:
    """Приказује мени подкатегорија за Linux / recon."""
    while True:
        console.print("\n[bold]Linux / recon - choose subcategory:[/bold]\n")

        options = [
            (key, name) for key, name in SUBCATEGORIES.items()
        ]

        choice = ask_select(options)

        if choice is None:
            return

        submenu = SUBCATEGORY_MENUS.get(choice)
        if submenu is not None:
            submenu()