# Модул за проналажење browser профила и њихових података.
# Browser профили садрже историју, колачиће, сачуване лозинке
# и session токене. Ово је злато за нападаче (session hijacking).
#
# ВАЖНО: Модул НЕ декриптује лозинке и НЕ извлачи session токене.
# Само прикупља метаподатке: које browser-е има, где су профили,
# колико уноса имају, да ли имају сачуване лозинке.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import sqlite3
from pathlib import Path

from rich.console import Console

console = Console()

# Познати browser-и и њихове путање (релативне од home).
BROWSERS = {
    "firefox": {
        "name": "Firefox",
        "paths": [
            ".mozilla/firefox",
            "snap/firefox/common/.mozilla/firefox",
            "flatpak/org.mozilla.firefox/.mozilla/firefox",
        ],
        "profile_marker": "prefs.js",
    },
    "chrome": {
        "name": "Google Chrome",
        "paths": [
            ".config/google-chrome",
            "snap/google-chrome/common/.config/google-chrome",
        ],
        "profile_marker": "Preferences",
    },
    "chromium": {
        "name": "Chromium",
        "paths": [
            ".config/chromium",
            "snap/chromium/common/.config/chromium",
        ],
        "profile_marker": "Preferences",
    },
    "brave": {
        "name": "Brave Browser",
        "paths": [
            ".config/BraveSoftware/Brave-Browser",
            "snap/brave/common/.config/BraveSoftware/Brave-Browser",
        ],
        "profile_marker": "Preferences",
    },
    "edge": {
        "name": "Microsoft Edge",
        "paths": [
            ".config/microsoft-edge",
            "snap/microsoft-edge/common/.config/microsoft-edge",
        ],
        "profile_marker": "Preferences",
    },
    "opera": {
        "name": "Opera",
        "paths": [
            ".config/opera",
            "snap/opera/common/.config/opera",
        ],
        "profile_marker": "Preferences",
    },
    "vivaldi": {
        "name": "Vivaldi",
        "paths": [
            ".config/vivaldi",
            "snap/vivaldi/common/.config/vivaldi",
        ],
        "profile_marker": "Preferences",
    },
    "tor-browser": {
        "name": "Tor Browser",
        "paths": [
            "tor-browser_en-US/Browser/TorBrowser/Data/Browser",
        ],
        "profile_marker": "prefs.js",
    },
}

# Фајлови у профилу који нас занимају.
PROFILE_FILES = {
    "history": {
        "firefox": "places.sqlite",
        "chromium": "History",
    },
    "cookies": {
        "firefox": "cookies.sqlite",
        "chromium": "Cookies",
    },
    "logins": {
        "firefox": "logins.json",
        "chromium": "Login Data",
    },
    "autofill": {
        "firefox": "formhistory.sqlite",
        "chromium": "Web Data",
    },
    "bookmarks": {
        "firefox": "places.sqlite",  # у истој бази као history
        "chromium": "Bookmarks",
    },
    "downloads": {
        "firefox": "places.sqlite",
        "chromium": "History",
    },
    "cache": {
        "firefox": "cache2",
        "chromium": "Cache",
    },
}

# Максимална дубина претраге.
MAX_DEPTH = 5


def run() -> dict:
    """Проналази browser профиле и њихове податке.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Browser data[/bold cyan]\n")

    # Проналазимо home директоријуме.
    homes = _get_home_dirs()

    # Проналазимо све browser профиле.
    browsers = []

    for username, home in homes:
        for browser_key, browser_info in BROWSERS.items():
            profiles = _find_browser_profiles(
                home, username, browser_key, browser_info
            )
            if profiles:
                browsers.append({
                    "browser": browser_key,
                    "name": browser_info["name"],
                    "user": username,
                    "profiles": profiles,
                })

    # Правимо резиме.
    total_profiles = sum(len(b["profiles"]) for b in browsers)
    total_findings = sum(
        sum(len(p.get("findings", [])) for p in b["profiles"])
        for b in browsers
    )

    summary = {
        "total_browsers": len(browsers),
        "total_profiles": total_profiles,
        "total_findings": total_findings,
    }

    data = {
        "browsers": browsers,
        "summary": summary,
    }

    _print_data(data)

    return data


def _get_home_dirs() -> list[tuple[str, Path]]:
    """Враћа листу (корисник, home) туплова."""
    homes = []

    root_home = Path("/root")
    if root_home.exists():
        homes.append(("root", root_home))

    home_base = Path("/home")
    if home_base.exists():
        try:
            for user_home in sorted(home_base.iterdir()):
                if user_home.is_dir():
                    homes.append((user_home.name, user_home))
        except (PermissionError, Exception):
            pass

    return homes


def _find_browser_profiles(
    home: Path,
    username: str,
    browser_key: str,
    browser_info: dict,
) -> list[dict]:
    """Проналази профиле за дати browser."""
    profiles = []

    for rel_path in browser_info["paths"]:
        base_path = home / rel_path

        if not base_path.exists() or not base_path.is_dir():
            continue

        # Firefox: base_path садржи профиле као подфолдере.
        # Chromium: base_path је већ профил (Default, Profile 1...).
        if browser_key == "firefox":
            found = _find_firefox_profiles(
                base_path, username, browser_key
            )
        else:
            found = _find_chromium_profiles(
                base_path, username, browser_key
            )

        profiles.extend(found)

    return profiles


def _find_firefox_profiles(
    base: Path, username: str, browser_key: str
) -> list[dict]:
    """Firefox чува профиле у подфолдерима (нпр. xxxx.default)."""
    profiles = []

    try:
        entries = sorted(base.iterdir())
    except (PermissionError, Exception):
        return profiles

    for entry in entries:
        if not entry.is_dir():
            continue

        # Профил има prefs.js.
        marker = entry / "prefs.js"
        if not marker.exists():
            continue

        profile = _analyze_profile(
            entry, username, browser_key, "firefox", entry.name
        )
        if profile:
            profiles.append(profile)

    return profiles


def _find_chromium_profiles(
    base: Path, username: str, browser_key: str
) -> list[dict]:
    """Chromium browser-и чувају профиле у Default, Profile 1..."""
    profiles = []

    # Профил може бити директно у base (Default) или у подфолдеру.
    try:
        entries = sorted(base.iterdir())
    except (PermissionError, Exception):
        return profiles

    for entry in entries:
        if not entry.is_dir():
            continue

        # Профил има Preferences фајл.
        marker = entry / "Preferences"
        if not marker.exists():
            continue

        profile = _analyze_profile(
            entry, username, browser_key, "chromium", entry.name
        )
        if profile:
            profiles.append(profile)

    return profiles


def _analyze_profile(
    profile_path: Path,
    username: str,
    browser_key: str,
    profile_type: str,
    profile_name: str,
) -> dict | None:
    """Анализира један профил."""
    findings = []

    # Прегледамо сваки познати тип фајла.
    # History.
    history_count = _count_history(profile_path, profile_type)
    if history_count > 0:
        findings.append({
            "type": "history",
            "count": history_count,
            "description": f"{history_count} page(s) in history",
        })

    # Cookies.
    cookies_count = _count_cookies(profile_path, profile_type)
    if cookies_count > 0:
        findings.append({
            "type": "cookies",
            "count": cookies_count,
            "description": f"{cookies_count} cookie(s)",
        })

    # Saved logins — само да ли постоје.
    logins = _check_logins(profile_path, profile_type)
    if logins:
        findings.append({
            "type": "logins",
            "count": logins.get("count", 0),
            "encrypted": logins.get("encrypted", False),
            "description": (
                f"{logins.get('count', 0)} saved login(s) "
                f"({'encrypted' if logins.get('encrypted') else 'unencrypted'})"
            ),
        })

    # Autofill.
    autofill_count = _count_autofill(profile_path, profile_type)
    if autofill_count > 0:
        findings.append({
            "type": "autofill",
            "count": autofill_count,
            "description": f"{autofill_count} autofill entry/entries",
        })

    # Downloads — само број.
    downloads_count = _count_downloads(profile_path, profile_type)
    if downloads_count > 0:
        findings.append({
            "type": "downloads",
            "count": downloads_count,
            "description": f"{downloads_count} download(s) in history",
        })

    return {
        "name": profile_name,
        "path": str(profile_path),
        "findings": findings,
    }


def _count_history(profile_path: Path, profile_type: str) -> int:
    """Броји уносе у историји."""
    if profile_type == "firefox":
        db_file = profile_path / "places.sqlite"
        if not db_file.exists():
            return 0

        return _count_sqlite_rows(
            db_file,
            "SELECT COUNT(*) FROM moz_places WHERE hidden = 0",
        )

    # Chromium.
    db_file = profile_path / "History"
    if not db_file.exists():
        return 0

    return _count_sqlite_rows(
        db_file,
        "SELECT COUNT(*) FROM urls",
    )


def _count_cookies(profile_path: Path, profile_type: str) -> int:
    """Броји колачиће."""
    if profile_type == "firefox":
        db_file = profile_path / "cookies.sqlite"
        if not db_file.exists():
            return 0

        return _count_sqlite_rows(
            db_file,
            "SELECT COUNT(*) FROM moz_cookies",
        )

    db_file = profile_path / "Cookies"
    if not db_file.exists():
        return 0

    return _count_sqlite_rows(
        db_file,
        "SELECT COUNT(*) FROM cookies",
    )


def _count_autofill(profile_path: Path, profile_type: str) -> int:
    """Броји autofill уносе."""
    if profile_type == "firefox":
        db_file = profile_path / "formhistory.sqlite"
        if not db_file.exists():
            return 0

        return _count_sqlite_rows(
            db_file,
            "SELECT COUNT(*) FROM moz_formhistory",
        )

    # Chromium користи Web Data базу.
    db_file = profile_path / "Web Data"
    if not db_file.exists():
        return 0

    return _count_sqlite_rows(
        db_file,
        "SELECT COUNT(*) FROM autofill",
    )


def _count_downloads(profile_path: Path, profile_type: str) -> int:
    """Броји преузимања."""
    if profile_type == "firefox":
        db_file = profile_path / "places.sqlite"
        if not db_file.exists():
            return 0

        return _count_sqlite_rows(
            db_file,
            "SELECT COUNT(*) FROM moz_annos WHERE anno_attribute_id IN "
            "(SELECT id FROM moz_anno_attributes WHERE name = "
            "'downloads/destinationFileURI')",
        )

    db_file = profile_path / "History"
    if not db_file.exists():
        return 0

    return _count_sqlite_rows(
        db_file,
        "SELECT COUNT(*) FROM downloads",
    )


def _check_logins(profile_path: Path, profile_type: str) -> dict | None:
    """Проверава да ли постоје сачуване лозинке.

    НЕ чита вредности — само број и да ли су енкриптоване.
    """
    if profile_type == "firefox":
        # Firefox чува у logins.json.
        logins_file = profile_path / "logins.json"
        if not logins_file.exists():
            return None

        try:
            import json
            content = logins_file.read_text(
                encoding="utf-8", errors="replace"
            )
            data = json.loads(content)

            # Firefox може имати key4.db за главни кључ.
            key_db = profile_path / "key4.db"
            has_key_db = key_db.exists()

            logins = data.get("logins", [])
            if not logins:
                return None

            return {
                "count": len(logins),
                "encrypted": has_key_db,
            }

        except Exception:
            return None

    # Chromium: Login Data SQLite база.
    db_file = profile_path / "Login Data"
    if not db_file.exists():
        return None

    count = _count_sqlite_rows(
        db_file,
        "SELECT COUNT(*) FROM logins",
    )

    if count == 0:
        return None

    # Chromium лозинке су увек енкриптоване (OS keyring).
    return {
        "count": count,
        "encrypted": True,
    }


def _count_sqlite_rows(db_file: Path, query: str) -> int:
    """Броји редове у SQLite бази.

    Користи read-only mode и immutable да избегнемо закључавање.
    """
    if not db_file.exists():
        return 0

    # Проверавамо да ли је фајл стварно SQLite.
    try:
        with open(db_file, "rb") as f:
            header = f.read(16)

        if not header.startswith(b"SQLite format 3"):
            return 0
    except (PermissionError, Exception):
        return 0

    # Отварамо read-only.
    try:
        # Користимо URI за immutable read-only приступ.
        uri = f"file:{db_file}?mode=ro&immutable=1"

        conn = sqlite3.connect(uri, uri=True, timeout=2)
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()

        if result:
            return int(result[0])

    except sqlite3.DatabaseError:
        # База може бити закључана или оштећена.
        return 0
    except sqlite3.OperationalError:
        # Табела не постоји.
        return 0
    except Exception:
        return 0

    return 0


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    browsers = data.get("browsers", [])
    summary = data.get("summary", {})

    console.print(
        f"[bold]Browsers found:[/bold]     "
        f"{summary.get('total_browsers', 0)}"
    )
    console.print(
        f"[bold]Profiles:[/bold]           "
        f"{summary.get('total_profiles', 0)}"
    )
    console.print(
        f"[bold]Total data sources:[/bold] "
        f"{summary.get('total_findings', 0)}"
    )
    console.print()

    if not browsers:
        console.print(
            "  [dim]No browser profiles found.[/dim]\n"
        )
        return

    for browser in browsers:
        _print_browser(browser)


def _print_browser(browser: dict) -> None:
    """Приказује један browser."""
    name = browser.get("name", "?")
    username = browser.get("user", "?")
    profiles = browser.get("profiles", [])

    console.print(
        f"[bold cyan]{name}[/bold cyan]  "
        f"[dim](user: {username}, {len(profiles)} profile(s))[/dim]\n"
    )

    for profile in profiles:
        _print_profile(profile)


def _print_profile(profile: dict) -> None:
    """Приказује један профил."""
    name = profile.get("name", "?")
    findings = profile.get("findings", [])

    console.print(f"  [bold]{name}[/bold]")

    if not findings:
        console.print("    [dim]No data found.[/dim]")
        console.print()
        return

    # Мапирање типа на боју.
    type_colors = {
        "history": "dim",
        "cookies": "yellow",
        "logins": "bold red",
        "autofill": "yellow",
        "downloads": "dim",
    }

    for finding in findings:
        ftype = finding.get("type", "?")
        description = finding.get("description", "")
        color = type_colors.get(ftype, "white")

        console.print(
            f"    [{color}]● {ftype:10s}[/{color}]  "
            f"{description}"
        )

    console.print()