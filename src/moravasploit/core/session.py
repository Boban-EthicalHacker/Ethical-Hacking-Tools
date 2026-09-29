# Управљање сесијом у MoravaSploit-у.
# Када корисник уђе у неки систем (Linux, Android, iOS...),
# покреће се нова сесија. Сесија је фолдер у коме се чувају
# сви резултати модула које корисник покрене.
#
# Пример структуре:
#   logs/
#   └── linux_2026-09-29_14-32-15/
#       ├── system_info.json
#       ├── kernel_info.json
#       └── users_groups.json
#
# Сесија се чува глобално у модулу, а модули је позивају
# преко функције save().
import json
from datetime import datetime
from pathlib import Path

# Глобална променљива — путања до текуће сесије.
# None значи да сесија није активна.
_current_session: Path | None = None

# Име фолдера где се чувају све сесије.
# Налази се у корену пројекта.
LOGS_DIR_NAME = "logs"

# Име фолдера сесије се прави од ових делова.
# Пример: "linux_2026-09-29_14-32-15"
SESSION_DATE_FORMAT = "%Y-%m-%d_%H-%M-%S"


def _project_root() -> Path:
    """Враћа путању до корена пројекта.

    Фајл је у src/moravasploit/core/session.py, тако да је
    потребно 4 нивоа навише да се дође до корена.
    """
    return Path(__file__).resolve().parent.parent.parent.parent


def _logs_dir() -> Path:
    """Враћа путању до logs/ фолдера у корену пројекта."""
    return _project_root() / LOGS_DIR_NAME


def start_session(target: str) -> Path:
    """Покреће нову сесију за дати систем.

    Прави фолдер у logs/ са именом типа:
        linux_2026-09-29_14-32-15

    Аргументи:
        target: име система (linux, android, ios, macos, windows).

    Враћа:
        Путању до новонаправљеног фолдера сесије.
    """
    global _current_session

    # Креирамо logs/ фолдер ако не постоји.
    logs_dir = _logs_dir()
    logs_dir.mkdir(exist_ok=True)

    # Правимо име сесије од имена система и времена.
    timestamp = datetime.now().strftime(SESSION_DATE_FORMAT)
    session_name = f"{target.lower()}_{timestamp}"

    # Пуна путања до фолдера сесије.
    session_path = logs_dir / session_name

    # Правимо фолдер.
    session_path.mkdir(exist_ok=True)

    # Памтимо га глобално.
    _current_session = session_path

    return session_path


def end_session() -> None:
    """Завршава текућу сесију.

    Не брише фолдер — само прекида праћење. Фолдер остаје
    на диску за касније прегледање.
    """
    global _current_session
    _current_session = None


def get_session_path() -> Path | None:
    """Враћа путању до текуће сесије или None."""
    return _current_session


def has_session() -> bool:
    """Проверава да ли је сесија активна."""
    return _current_session is not None


def save(module_name: str, data) -> Path | None:
    """Чува резултат модула као JSON у текућој сесији.

    Аргументи:
        module_name: име модула (користи се као име фајла).
        data: подаци за чување — најчешће речник или листа.

    Враћа:
        Путању до сачуваног фајла, или None ако сесија није активна.
    """
    # Ако нема активне сесије, не чувамо ништа.
    if _current_session is None:
        return None

    # Име фајла — додајемо .json.
    file_path = _current_session / f"{module_name}.json"

    # Припремамо податке за JSON.
    payload = {
        "module": module_name,
        "saved_at": datetime.now().isoformat(),
        "data": data,
    }

    # Уписујемо у фајл.
    # default=str омогућава да се датуми и слични типови
    # аутоматски конвертују у стринг.
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    except Exception:
        return None

    return file_path