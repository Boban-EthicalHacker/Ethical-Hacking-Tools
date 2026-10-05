# Модул за проналажење приватних SSH кључева на систему.
# Приватни кључеви су веома осетљиви — ако их нападач пронађе
# и нису шифровани, може да приступи серверима без лозинке.
#
# ВАЖНО: Модул НЕ чита садржај приватних кључева.
# Само прикупља метаподатке (тип, шифрованост, permissions).
#
# Модул враћа речник са подацима, који мени чува у JSON.
import os
import stat as stat_mod
from pathlib import Path

from rich.console import Console

console = Console()

# Типови приватних кључева које препознајемо.
KEY_TYPES = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "EC",
    "DSA PRIVATE KEY": "DSA",
    "OPENSSH PRIVATE KEY": "OpenSSH",
    "ENCRYPTED PRIVATE KEY": "Encrypted (PKCS#8)",
    "PRIVATE KEY": "PKCS#8",
    "PGP PRIVATE KEY BLOCK": "PGP",
    "SSH2 ENCRYPTED PRIVATE KEY": "SSH2 (encrypted)",
}

# Имена фајлова која обично садрже приватне кључеве.
COMMON_KEY_NAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_xmss",
    "identity",
    "ssh_host_rsa_key",
    "ssh_host_dsa_key",
    "ssh_host_ecdsa_key",
    "ssh_host_ed25519_key",
}

# Директоријуми које прескачемо (велики, небитни).
SKIP_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/lib/containers",
    "/mnt",
    "/media",
    "/var/lib/libvirt",
    "/usr/share",
    "/usr/lib",
    "/var/lib/dpkg",
    "/var/lib/apt",
    "/var/cache",
}

# Максимална дубина претраге.
MAX_DEPTH = 8

# Максимална величина фајла који читамо (приватни кључеви су мали).
MAX_FILE_SIZE = 50 * 1024  # 50 KB


def run() -> dict:
    """Проналази приватне SSH кључеве.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]SSH private keys[/bold cyan]\n")

    console.print(
        "[dim]Searching for private SSH keys. "
        "This may take a few seconds...[/dim]\n"
    )

    # Проналазимо приватне кључеве.
    keys = _find_private_keys()

    # Анализирамо.
    analysis = _analyze(keys)

    data = {
        "keys": keys,
        "analysis": analysis,
        "summary": {
            "total": len(keys),
            "unencrypted": analysis.get("unencrypted_count", 0),
            "encrypted": analysis.get("encrypted_count", 0),
            "weak_permissions": analysis.get("weak_permissions_count", 0),
        },
    }

    _print_data(data)

    return data


def _find_private_keys() -> list[dict]:
    """Претражује систем за приватним SSH кључевима."""
    keys = []

    for root, dirs, files in os.walk("/", topdown=True):
        # Прескачемо SKIP_DIRS.
        dirs[:] = [
            d for d in dirs
            if os.path.join(root, d) not in SKIP_DIRS
            and not os.path.join(root, d).startswith(
                tuple(f"{s}/" for s in SKIP_DIRS)
            )
        ]

        depth = root.count(os.sep)
        if depth > MAX_DEPTH:
            dirs[:] = []
            continue

        if not os.access(root, os.R_OK | os.X_OK):
            continue

        for file_name in files:
            path = os.path.join(root, file_name)

            # Прво проверавамо по имену — да ли је познат кључ.
            is_common_name = file_name in COMMON_KEY_NAMES

            # Ако није познато име, проверавамо да ли је у .ssh фолдеру.
            in_ssh_dir = ".ssh/" in path or ".ssh\\" in path

            if not is_common_name and not in_ssh_dir:
                # Идемо даље — можда је кључ са необичним именом.
                # Проверавамо само фајлове који личе на кључ.
                if not _looks_like_key_file(file_name):
                    continue

            key_info = _read_key_info(path, file_name)
            if key_info:
                keys.append(key_info)

    return keys


def _looks_like_key_file(name: str) -> bool:
    """Проверава да ли име фајла личи на кључ."""
    name_lower = name.lower()

    # Фајлови који садрже "key", "id_" или су у .ssh фолдеру.
    indicators = ("key", "id_", "private", "secret")
    for ind in indicators:
        if ind in name_lower:
            return True

    # PEM фајлови.
    if name_lower.endswith((".pem", ".key", ".ppk")):
        return True

    return False


def _read_key_info(path: str, name: str) -> dict | None:
    """Чита метаподатке о фајлу и проверава да ли је приватан кључ."""
    try:
        st = os.lstat(path)
    except (OSError, PermissionError):
        return None

    # Прескачемо симлинкове.
    if stat_mod.S_ISLNK(st.st_mode):
        return None

    # Прескачемо фолдере.
    if not stat_mod.S_ISREG(st.st_mode):
        return None

    # Прескачемо велике фајлове.
    if st.st_size > MAX_FILE_SIZE:
        return None

    # Читамо само прву линију да видимо да ли је кључ.
    key_type = _detect_key_type(path)
    if not key_type:
        return None

    # Проверавамо да ли је шифрован.
    encrypted = _is_encrypted(path)

    # Проверавамо permissions.
    mode = st.st_mode
    mode_str = stat_mod.filemode(mode)
    weak_permissions = _check_weak_permissions(mode)

    # Читамо власника.
    uid = st.st_uid
    gid = st.st_gid

    # Одређујемо да ли је системски кључ (host key).
    is_host_key = name.startswith("ssh_host_") or "/etc/ssh/" in path

    return {
        "path": path,
        "name": name,
        "key_type": key_type,
        "encrypted": encrypted,
        "mode": mode_str,
        "uid": uid,
        "gid": gid,
        "size_bytes": st.st_size,
        "is_host_key": is_host_key,
        "weak_permissions": weak_permissions,
    }


def _detect_key_type(path: str) -> str | None:
    """Препознаје тип приватног кључа.

    Чита само прву линију фајла.
    """
    try:
        with open(path, "rb") as f:
            # Читамо прву линију (обично мање од 100 бајтова).
            first_line = f.readline(200)
    except (PermissionError, OSError):
        return None

    # Декодирамо као текст.
    try:
        line = first_line.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

    # Приватни кључеви имају "-----BEGIN ... PRIVATE KEY-----".
    if "PRIVATE KEY" not in line and "PRIVATE KEY BLOCK" not in line:
        return None

    # Препознајемо тип.
    for marker, type_name in KEY_TYPES.items():
        if marker in line:
            return type_name

    # Непрепознат тип, али је приватан кључ.
    if "PRIVATE KEY" in line:
        return "Unknown private key"

    return None


def _is_encrypted(path: str) -> bool:
    """Проверава да ли је приватан кључ шифрован.

    Шифровани кључеви имају "ENCRYPTED" у првој линији,
    или "Proc-Type: 4,ENCRYPTED" у заглављу (стари PEM формат).
    """
    try:
        with open(path, "rb") as f:
            # Читамо првих 500 бајтова.
            header = f.read(500)
    except (PermissionError, OSError):
        return False

    try:
        text = header.decode("utf-8", errors="replace")
    except Exception:
        return False

    # Проверавамо маркере шифровања.
    if "ENCRYPTED" in text.upper():
        return True

    # Стари PEM формат: "Proc-Type: 4,ENCRYPTED".
    if "Proc-Type:" in text and "ENCRYPTED" in text:
        return True

    # Проверавамо и "DEK-Info" (сигнал да је шифрован).
    if "DEK-Info:" in text:
        return True

    return False


def _check_weak_permissions(mode: int) -> bool:
    """Проверава да ли фајл има слабе permissions.

    Приватни кључеви треба да имају 600 (само власник).
    Ако имају 644 или више, то је проблем.
    """
    # Узимамо permission битове.
    perms = mode & 0o777

    # Проверавамо да ли група или остали имају приступ.
    # Битно: 0o077 значи да група и остали немају ништа.
    if perms & 0o077:
        return True

    return False


def _analyze(keys: list[dict]) -> dict:
    """Анализира пронађене кључеве."""
    result = {
        "unencrypted": [],
        "encrypted": [],
        "weak_permissions": [],
        "host_keys": [],
        "unencrypted_count": 0,
        "encrypted_count": 0,
        "weak_permissions_count": 0,
        "host_keys_count": 0,
    }

    for key in keys:
        if key.get("encrypted"):
            result["encrypted"].append(key)
            result["encrypted_count"] += 1
        else:
            result["unencrypted"].append(key)
            result["unencrypted_count"] += 1

        if key.get("weak_permissions"):
            result["weak_permissions"].append(key)
            result["weak_permissions_count"] += 1

        if key.get("is_host_key"):
            result["host_keys"].append(key)
            result["host_keys_count"] += 1

    return result


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    keys = data.get("keys", [])
    analysis = data.get("analysis", {})
    summary = data.get("summary", {})

    console.print(
        f"[bold]Total private keys:[/bold]  {summary.get('total', 0)}"
    )
    console.print(
        f"  [yellow]Unencrypted:[/yellow]         "
        f"{summary.get('unencrypted', 0)}"
    )
    console.print(
        f"  [green]Encrypted:[/green]           "
        f"{summary.get('encrypted', 0)}"
    )

    if summary.get("weak_permissions", 0) > 0:
        console.print(
            f"  [bold red]Weak permissions:[/bold red]   "
            f"{summary['weak_permissions']}"
        )

    console.print()

    if not keys:
        console.print(
            "  [dim]No private SSH keys found.[/dim]\n"
        )
        return

    # Нешифровани прво (најопасније).
    unencrypted = analysis.get("unencrypted", [])
    if unencrypted:
        console.print(
            f"[bold red]Unencrypted keys ({len(unencrypted)}):[/bold red]\n"
        )
        for key in unencrypted:
            _print_key(key, "red")
        console.print()

    # Шифровани.
    encrypted = analysis.get("encrypted", [])
    if encrypted:
        console.print(
            f"[bold green]Encrypted keys ({len(encrypted)}):[/bold green]\n"
        )
        for key in encrypted:
            _print_key(key, "green")
        console.print()

    # Слаби permissions (ако има, поред осталих).
    weak = analysis.get("weak_permissions", [])
    if weak:
        console.print(
            f"[bold yellow]Weak permissions ({len(weak)}):[/bold yellow]\n"
        )
        for key in weak:
            console.print(
                f"  [yellow]{key['path']}[/yellow]  "
                f"[dim]mode: {key['mode']} "
                f"(should be 600)[/dim]"
            )
        console.print()


def _print_key(key: dict, color: str) -> None:
    """Приказује један приватан кључ."""
    path = key.get("path", "?")
    key_type = key.get("key_type", "?")
    mode = key.get("mode", "")
    size = key.get("size_bytes", 0)
    is_host = key.get("is_host_key", False)
    weak = key.get("weak_permissions", False)

    # Скраћујемо путању.
    display_path = path
    if len(display_path) > 70:
        display_path = "..." + display_path[-67:]

    # Ознака за host key.
    host_marker = ""
    if is_host:
        host_marker = " [dim](host key)[/dim]"

    # Ознака за слабе permissions.
    perm_marker = ""
    if weak:
        perm_marker = " [bold yellow](weak perms)[/bold yellow]"

    console.print(
        f"  [{color}]{display_path}[/{color}]{host_marker}{perm_marker}"
    )
    console.print(
        f"    Type:     {key_type}"
    )
    console.print(
        f"    Mode:     {mode}"
    )
    console.print(
        f"    Size:     {size} B"
    )
    console.print()