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
    """Пита корисника да изабере једну опцију (стрелице горе/доле).

    Корисник бира стрелицама горе/доле и потврђује са Enter.
    На дну менија су ставке 'back' и 'exit' — до њих се долази
    стрелицама, не тастерима.

    Аргументи:
        options: листа (кључ, опис) туплова.

    Враћа:
        Изабрани кључ, или None ако је изабран 'back'.

    Подиже:
        ExitApp: ако је изабран 'exit'.
    """
    # Правимо листу избора за questionary.
    # Не користимо use_shortcuts, тако да нема аутоматских
    # бројева или слова поред ставки.
    choices: list = [
        questionary.Choice(title=label, value=key)
        for key, label in options
    ]

    # Додајемо раздвајач, па 'back' и 'exit'.
    choices.append(questionary.Separator())
    choices.append(questionary.Choice(title="back", value="__back__"))
    choices.append(questionary.Choice(title="exit", value="__exit__"))

    # Приказујемо мени.
    # use_shortcuts=False — без аутоматских скраћеница.
    answer = questionary.select(
        "",
        choices=choices,
        qmark="",
        style=MENU_STYLE,
        pointer="❯",
        instruction="(Use arrow keys and Enter)",
        use_shortcuts=False,
    ).ask()

    # Ако је корисник притиснуо Ctrl+C или Ctrl+D.
    if answer is None:
        return None

    if answer == "__exit__":
        raise ExitApp()

    if answer == "__back__":
        return None

    return answer