# Модул за приказ инсталираних компајлера и интерпретера.
# Ово је важно за етичко хаковање јер:
#   - Са компајлером, нападач може да направи exploit на лицу места.
#   - Без компајлера, мора да користи готове бинарне фајлове.
#   - Ако видиш компајлер на продукцијском серверу, то је сумњиво.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Компајлери и интерпретери које тражимо.
# Формат: (име, команда_за_верзију, категорија, језик)
TOOLS = [
    # C и C++ компајлери (најважнији за exploit развој)
    ("gcc", ["gcc", "--version"], "compiler", "C"),
    ("g++", ["g++", "--version"], "compiler", "C++"),
    ("cc", ["cc", "--version"], "compiler", "C"),
    ("clang", ["clang", "--version"], "compiler", "C"),
    ("clang++", ["clang++", "--version"], "compiler", "C++"),
    ("tcc", ["tcc", "-v"], "compiler", "C"),

    # Rust
    ("rustc", ["rustc", "--version"], "compiler", "Rust"),
    ("cargo", ["cargo", "--version"], "compiler", "Rust"),

    # Go
    ("go", ["go", "version"], "compiler", "Go"),

    # Java
    ("javac", ["javac", "-version"], "compiler", "Java"),
    ("java", ["java", "-version"], "runtime", "Java"),

    # C# / .NET
    ("dotnet", ["dotnet", "--version"], "compiler", ".NET"),
    ("mcs", ["mcs", "--version"], "compiler", "C#"),
    ("mono", ["mono", "--version"], "runtime", "C#"),

    # Интерпретери
    ("python", ["python", "--version"], "interpreter", "Python"),
    ("python3", ["python3", "--version"], "interpreter", "Python"),
    ("python2", ["python2", "--version"], "interpreter", "Python 2"),
    ("perl", ["perl", "-v"], "interpreter", "Perl"),
    ("ruby", ["ruby", "--version"], "interpreter", "Ruby"),
    ("node", ["node", "--version"], "interpreter", "JavaScript"),
    ("php", ["php", "--version"], "interpreter", "PHP"),
    ("lua", ["lua", "-v"], "interpreter", "Lua"),
    ("awk", ["awk", "-W", "version"], "interpreter", "AWK"),
    ("tclsh", ["tclsh"], "interpreter", "Tcl"),

    # Специфични алати
    ("nasm", ["nasm", "-v"], "assembler", "Assembly"),
    ("as", ["as", "--version"], "assembler", "Assembly"),
    ("ld", ["ld", "--version"], "linker", "Assembly"),

    # Мрежни алати за пренос података (могу да буду корисни за exploit)
    ("nc", ["nc", "-h"], "network", "Netcat"),
    ("ncat", ["ncat", "--version"], "network", "Ncat"),
    ("socat", ["socat", "-V"], "network", "Socat"),
]


def run() -> dict:
    """Приказује инсталиране компајлере и интерпретере.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Compilers and interpreters[/bold cyan]\n")

    # Проналазимо доступне алате.
    available = []
    for tool in TOOLS:
        result = _check_tool(tool)
        if result:
            available.append(result)

    # Групишемо по категорији.
    by_category = _group_by_category(available)

    # Правимо резиме.
    summary = {
        "total": len(available),
        "by_category": {
            cat: len(items) for cat, items in by_category.items()
        },
    }

    data = {
        "tools": available,
        "by_category": by_category,
        "summary": summary,
    }

    _print_data(data)

    return data


def _check_tool(tool: tuple) -> dict | None:
    """Проверава један алат."""
    name, cmd, category, language = tool

    # Проверавамо да ли команда постоји.
    executable = shutil.which(cmd[0])
    if not executable:
        return None

    # Покрећемо команду да видимо верзију.
    version = _get_version(cmd)

    return {
        "name": name,
        "path": executable,
        "category": category,
        "language": language,
        "version": version,
    }


def _get_version(cmd: list[str]) -> str | None:
    """Извлачи верзију из излаза команде.

    Многе команде исписују верзију на stderr уместо stdout,
    па проверавамо оба.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )

        # Узимамо прву не-празну линију из stdout или stderr.
        output = proc.stdout or proc.stderr

        if not output:
            return None

        for line in output.splitlines():
            line = line.strip()
            if line:
                # Скраћујемо.
                if len(line) > 100:
                    line = line[:97] + "..."
                return line

        return None

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None


def _group_by_category(tools: list[dict]) -> dict[str, list[dict]]:
    """Групише алате по категорији."""
    result: dict[str, list[dict]] = {}

    for tool in tools:
        cat = tool.get("category", "other")
        if cat not in result:
            result[cat] = []
        result[cat].append(tool)

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    by_category = data.get("by_category", {})
    summary = data.get("summary", {})

    if not by_category:
        console.print(
            "  [dim]No compilers or interpreters found.[/dim]\n"
        )
        return

    console.print(
        f"[bold]Total tools:[/bold]  {summary.get('total', 0)}\n"
    )

    # Категорије са бојама.
    category_order = [
        ("compiler", "Compilers", "bold red"),
        ("assembler", "Assemblers", "bold yellow"),
        ("linker", "Linkers", "yellow"),
        ("interpreter", "Interpreters", "green"),
        ("runtime", "Runtimes", "cyan"),
        ("network", "Network tools", "magenta"),
    ]

    for cat_key, cat_label, color in category_order:
        tools = by_category.get(cat_key, [])
        if not tools:
            continue

        console.print(
            f"[{color}]{cat_label} ({len(tools)}):[/{color}]\n"
        )

        for tool in sorted(tools, key=lambda x: x["name"]):
            _print_tool(tool)

        console.print()

    # Ако има категорија које нису у листи.
    known_cats = {c[0] for c in category_order}
    for cat_key, tools in by_category.items():
        if cat_key in known_cats:
            continue

        console.print(f"[dim]{cat_key.title()} ({len(tools)}):[/dim]\n")
        for tool in sorted(tools, key=lambda x: x["name"]):
            _print_tool(tool)
        console.print()


def _print_tool(tool: dict) -> None:
    """Приказује један алат."""
    name = tool.get("name", "?")
    language = tool.get("language", "")
    version = tool.get("version") or "(version unknown)"
    path = tool.get("path", "")

    # Скраћујемо верзију ако је дугачка.
    if len(version) > 60:
        version = version[:57] + "..."

    console.print(
        f"  [bold]{name:15s}[/bold]  "
        f"[dim]{language:15s}[/dim]  "
        f"{version}"
    )