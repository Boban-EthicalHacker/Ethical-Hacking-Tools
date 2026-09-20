# Помоћне функције за меније.
# Све меније у апликацији користе ову функцију за избор,
# да би понашање било исто свуда.
from rich.prompt import Prompt

from moravasploit.exceptions import ExitApp


def ask_choice(options: list[str]) -> str | None:
    """Пита корисника да изабере једну од опција.

    Аргументи:
        options: листа дозвољених кључева (без 'back' и 'exit').

    Враћа:
        Изабрани кључ, или None ако је корисник укуцао 'back'.

    Подиже:
        ExitApp: ако је корисник укуцао 'exit'.
    """
    # Дозвољени уноси су све опције + 'back' + 'exit'.
    choices = options + ["back", "exit"]

    # Питамо корисника. Подразумевано је 'back'.
    choice = Prompt.ask(">", choices=choices, default="back")

    # Ако је укуцао 'exit', подижемо изузетак за потпуни излаз.
    if choice == "exit":
        raise ExitApp()

    # Ако је укуцао 'back', враћамо None.
    if choice == "back":
        return None

    # Иначе враћамо изабрани кључ.
    return choice