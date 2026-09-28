# Помоћне функције за меније.
# Све меније у апликацији користе ове функције за избор,
# да би понашање било исто свуда.
import questionary
from rich.prompt import Prompt

from moravasploit.exceptions import ExitApp

# Стил за questionary меније.
# Без оквира, са стрелицом ❯ као показивачем.
MENU_STYLE = questionary.Style([
    ("qmark", "fg:cyan bold"),
    ("question", "bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan bold"),
    ("selected", "fg:green"),
    ("separator", "fg:gray"),
    ("instruction", "fg:gray"),
])


def ask_choice(options: list[str]) -> str | None:
    """Пита корисника да изабере једну од опција (нумерички унос).

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


def ask_select(options: list[tuple[str, str]]) -> str | None:
    """Пита корисника да изабере једну опцију.

    Корисник може да бира:
        - стрелицама горе/доле
        - притиском на кратак тастер (ако опција има)

    Кратки тастери:
        b — back
        e — exit

    Аргументи:
        options: листа (кључ, опис) туплова.

    Враћа:
        Изабрани кључ, или None ако је изабран 'back'.

    Подиже:
        ExitApp: ако је изабран 'exit'.
    """
    # Правимо листу избора за questionary.
    choices: list = [
        questionary.Choice(title=label, value=key)
        for key, label in options
    ]

    # Додајемо раздвајач, па 'back' и 'exit' са кратким тастерима.
    choices.append(questionary.Separator())
    choices.append(questionary.Choice(
        title="back",
        value="__back__",
        shortcut_key="b",
    ))
    choices.append(questionary.Choice(
        title="exit",
        value="__exit__",
        shortcut_key="e",
    ))

    # Приказујемо мени.
    # use_shortcuts=True омогућава да се притисне тастер
    # уместо да се стрелицама дође до опције.
    answer = questionary.select(
        "",
        choices=choices,
        qmark="",
        style=MENU_STYLE,
        pointer="❯",
        instruction="",
        use_shortcuts=True,
    ).ask()

    # Ако је корисник притиснуо Ctrl+C или Ctrl+D.
    if answer is None:
        return None

    if answer == "__exit__":
        raise ExitApp()

    if answer == "__back__":
        return None

    return answer
    """Пита корисника да изабере једну опцију (стрелице горе/доле).

    Аргументи:
        options: листа (кључ, опис) туплова.
                 Кључ се враћа, опис се приказује.

    Враћа:
        Изабрани кључ, или None ако је изабран 'back'.

    Подиже:
        ExitApp: ако је изабран 'exit'.
    """
    # Правимо листу избора за questionary.
    choices: list = [
        questionary.Choice(title=label, value=key)
        for key, label in options
    ]

    # Додајемо раздвајач, па 'back' и 'exit'.
    choices.append(questionary.Separator())
    choices.append(questionary.Choice(title="back", value="__back__"))
    choices.append(questionary.Choice(title="exit", value="__exit__"))

    # Приказујемо мени.
    # questionary захтева непразан "message", али га можемо
    # сакрити празним qmark-ом и празном инструкцијом.
    answer = questionary.select(
        "",
        choices=choices,
        qmark="",
        style=MENU_STYLE,
        pointer="❯",
        instruction="",
    ).ask()

    # Ако је корисник притиснуо Ctrl+C или Ctrl+D,
    # questionary враћа None.
    if answer is None:
        return None

    # Ако је изабран 'exit', подижемо изузетак.
    if answer == "__exit__":
        raise ExitApp()

    # Ако је изабран 'back', враћамо None.
    if answer == "__back__":
        return None

    # Иначе враћамо изабрани кључ.
    return answer