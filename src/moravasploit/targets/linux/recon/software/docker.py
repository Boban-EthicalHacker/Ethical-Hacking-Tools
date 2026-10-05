# Модул за приказ Docker контејнера, слика, мрежа и волумена.
# Docker контејнери често имају привилегован приступ или
# мапиране host директоријуме, што је велики безбедносни ризик.
# Ако корисник може да покрене Docker без sudo, то је еквивалент
# root приступа.
#
# Модул враћа речник са подацима, који мени чува у JSON.
import json
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Путања до Docker socket-а.
DOCKER_SOCKET = Path("/var/run/docker.sock")


def run() -> dict:
    """Приказује Docker ресурсе.

    Враћа речник са подацима за чување у JSON.
    """
    console.print("\n[bold cyan]Docker[/bold cyan]\n")

    # Проверавамо да ли је Docker инсталиран.
    if not shutil.which("docker"):
        console.print(
            "  [yellow]Docker is not installed.[/yellow]\n"
        )
        return _empty_result()

    # Проверавамо да ли имамо приступ Docker socket-у.
    socket_info = _check_socket_access()

    # Читамо контејнере.
    containers = _read_containers()

    # Читамо слике.
    images = _read_images()

    # Читамо мреже.
    networks = _read_networks()

    # Читамо volumes.
    volumes = _read_volumes()

    # Проналазимо безбедносно занимљиве контејнере.
    suspicious = _find_suspicious_containers(containers)

    data = {
        "socket": socket_info,
        "containers": containers,
        "images": images,
        "networks": networks,
        "volumes": volumes,
        "suspicious": suspicious,
        "summary": {
            "containers_total": len(containers),
            "containers_running": len([c for c in containers if c.get("state") == "running"]),
            "images": len(images),
            "networks": len(networks),
            "volumes": len(volumes),
            "suspicious_count": len(suspicious),
        },
    }

    _print_data(data)

    return data


def _empty_result() -> dict:
    """Враћа празан резултат."""
    return {
        "socket": {"exists": False, "accessible": False},
        "containers": [],
        "images": [],
        "networks": [],
        "volumes": [],
        "suspicious": [],
        "summary": {
            "containers_total": 0,
            "containers_running": 0,
            "images": 0,
            "networks": 0,
            "volumes": 0,
            "suspicious_count": 0,
        },
    }


def _check_socket_access() -> dict:
    """Проверава да ли имамо приступ Docker socket-у."""
    result = {
        "path": str(DOCKER_SOCKET),
        "exists": DOCKER_SOCKET.exists(),
        "accessible": False,
    }

    if not result["exists"]:
        return result

    # Проверавамо да ли можемо да извршимо docker ps.
    try:
        proc = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result["accessible"] = proc.returncode == 0

        if not result["accessible"] and proc.stderr:
            # Узимамо прву линију грешке.
            error = proc.stderr.strip().split("\n")[0]
            result["error"] = error[:200]

    except Exception:
        pass

    return result


def _run_docker_json(args: list[str]) -> list | dict | None:
    """Покреће docker команду са --format json."""
    try:
        proc = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    # Docker враћа JSON по линији (сваки објекат посебно).
    output = proc.stdout.strip()
    if not output:
        return []

    # Ако је један објекат, враћамо га као речник.
    if output.startswith("{"):
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass

    # Иначе враћамо листу.
    items = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return items


def _read_containers() -> list[dict]:
    """Чита Docker контејнере."""
    # Користимо docker ps -a са посебним форматом.
    fmt = (
        "{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|"
        "{{.Status}}|{{.Ports}}|{{.CreatedAt}}"
    )

    try:
        proc = subprocess.run(
            ["docker", "ps", "-a", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    containers = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("|")
        if len(parts) < 6:
            continue

        container_id = parts[0].strip()
        name = parts[1].strip()
        image = parts[2].strip()
        state = parts[3].strip()
        status = parts[4].strip()
        ports = parts[5].strip()
        created = parts[6].strip() if len(parts) > 6 else ""

        # Парсирамо портове — тражимо мапиране на 0.0.0.0.
        exposed = _parse_ports(ports)

        containers.append({
            "id": container_id[:12],
            "full_id": container_id,
            "name": name,
            "image": image,
            "state": state,
            "status": status,
            "ports": ports,
            "exposed_ports": exposed,
            "created": created,
        })

    return containers


def _parse_ports(ports: str) -> list[dict]:
    """Парсира port мапинге из docker ps.

    Пример: 0.0.0.0:8080->80/tcp, :::8080->80/tcp
    """
    result = []

    if not ports:
        return result

    # Раздвајамо по зарезу.
    for mapping in ports.split(","):
        mapping = mapping.strip()
        if "->" not in mapping:
            continue

        # Формат: host_ip:host_port->container_port/proto
        host_part, container_part = mapping.split("->", 1)

        # Парсирамо host део.
        if ":" in host_part:
            host_ip, host_port = host_part.rsplit(":", 1)
        else:
            host_ip = ""
            host_port = host_part

        # Парсирамо container део.
        if "/" in container_part:
            container_port, protocol = container_part.split("/", 1)
        else:
            container_port = container_part
            protocol = ""

        # Додајемо једино ако није дупликат.
        entry = {
            "host_ip": host_ip.strip("[]"),
            "host_port": host_port.strip("[]"),
            "container_port": container_port,
            "protocol": protocol,
        }

        if entry not in result:
            result.append(entry)

    return result


def _read_images() -> list[dict]:
    """Чита Docker слике."""
    fmt = "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"

    try:
        proc = subprocess.run(
            ["docker", "images", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    images = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("|")
        if len(parts) < 4:
            continue

        images.append({
            "id": parts[0].strip()[:12],
            "repository": parts[1].strip(),
            "tag": parts[2].strip(),
            "size": parts[3].strip(),
            "created": parts[4].strip() if len(parts) > 4 else "",
        })

    return images


def _read_networks() -> list[dict]:
    """Чита Docker мреже."""
    fmt = "{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}"

    try:
        proc = subprocess.run(
            ["docker", "network", "ls", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    networks = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("|")
        if len(parts) < 4:
            continue

        networks.append({
            "id": parts[0].strip()[:12],
            "name": parts[1].strip(),
            "driver": parts[2].strip(),
            "scope": parts[3].strip(),
        })

    return networks


def _read_volumes() -> list[dict]:
    """Чита Docker volumes."""
    fmt = "{{.Name}}|{{.Driver}}|{{.Mountpoint}}"

    try:
        proc = subprocess.run(
            ["docker", "volume", "ls", "--format", fmt],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    volumes = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("|")
        if len(parts) < 2:
            continue

        volumes.append({
            "name": parts[0].strip(),
            "driver": parts[1].strip(),
            "mountpoint": parts[2].strip() if len(parts) > 2 else "",
        })

    return volumes


def _find_suspicious_containers(containers: list[dict]) -> list[dict]:
    """Проналази безбедносно занимљиве контејнере."""
    suspicious = []

    for c in containers:
        reasons = []
        severity = "yellow"

        # Проверавамо да ли су портови изложени на 0.0.0.0.
        for port in c.get("exposed_ports", []):
            if port.get("host_ip") in ("0.0.0.0", "::"):
                reasons.append(
                    f"port {port['host_port']} exposed on all interfaces"
                )
                severity = "red"

        # Ако је контејнер привилегован... не можемо то видети из docker ps.
        # Али можемо видети из имена ако је нешто сумњиво.
        name_lower = c.get("name", "").lower()

        suspicious_names = ("backdoor", "reverse", "miner", "crypto")
        for sus in suspicious_names:
            if sus in name_lower:
                reasons.append(f"name contains '{sus}'")
                severity = "red"

        if reasons:
            suspicious.append({
                "name": c["name"],
                "image": c["image"],
                "state": c["state"],
                "reasons": reasons,
                "severity": severity,
            })

    return suspicious


def _print_data(data: dict) -> None:
    """Приказује податке на екран."""
    socket_info = data.get("socket", {})
    containers = data.get("containers", [])
    images = data.get("images", [])
    networks = data.get("networks", [])
    volumes = data.get("volumes", [])
    suspicious = data.get("suspicious", [])
    summary = data.get("summary", {})

    # Провера socket-а.
    if not socket_info.get("exists"):
        console.print(
            "  [dim]Docker socket not found. "
            "Docker is probably not running.[/dim]\n"
        )
        return

    if not socket_info.get("accessible"):
        console.print(
            "  [yellow]Cannot access Docker socket.[/yellow]\n"
        )
        if socket_info.get("error"):
            console.print(
                f"  [dim]{socket_info['error']}[/dim]\n"
            )
        console.print(
            "  [dim]You may need to run with sudo or be in the docker group.[/dim]\n"
        )
        return

    # Резиме.
    console.print(
        f"[bold]Containers:[/bold]     {summary.get('containers_total', 0)} "
        f"({summary.get('containers_running', 0)} running)"
    )
    console.print(f"[bold]Images:[/bold]         {summary.get('images', 0)}")
    console.print(f"[bold]Networks:[/bold]       {summary.get('networks', 0)}")
    console.print(f"[bold]Volumes:[/bold]        {summary.get('volumes', 0)}")

    if suspicious:
        console.print(
            f"[bold red]Suspicious:[/bold red]     "
            f"{summary.get('suspicious_count', 0)}"
        )

    console.print()

    # Сумњиви прво.
    if suspicious:
        console.print(
            f"[bold red]Suspicious containers ({len(suspicious)}):[/bold red]\n"
        )
        for item in suspicious:
            console.print(
                f"  [bold red]●[/bold red] "
                f"[yellow]{item['name']}[/yellow] "
                f"[dim]({item['image']})[/dim]"
            )
            for reason in item.get("reasons", []):
                console.print(f"    [dim]→ {reason}[/dim]")
        console.print()

    # Контејнери.
    if containers:
        console.print(f"[bold]Containers ({len(containers)}):[/bold]\n")

        for c in containers:
            _print_container(c)

        console.print()

    # Слике (првих 10).
    if images:
        console.print(f"[bold]Images ({len(images)}):[/bold]\n")

        limit = 10
        for img in images[:limit]:
            repo = img.get("repository", "?")
            tag = img.get("tag", "?")
            size = img.get("size", "?")
            console.print(
                f"  [bold]{repo}:{tag}[/bold]  "
                f"[dim]{size}[/dim]"
            )

        if len(images) > limit:
            console.print(
                f"  [dim]... and {len(images) - limit} more[/dim]"
            )
        console.print()


def _print_container(c: dict) -> None:
    """Приказује један контејнер."""
    name = c.get("name", "?")
    image = c.get("image", "?")
    state = c.get("state", "?")
    ports = c.get("ports", "")
    exposed = c.get("exposed_ports", [])

    # Боја за стање.
    if state == "running":
        color = "green"
    elif state == "exited":
        color = "dim"
    else:
        color = "yellow"

    console.print(
        f"  [bold]{name}[/bold]  "
        f"[{color}]{state}[/{color}]"
    )
    console.print(f"    Image: {image}")

    if exposed:
        # Издвајамо изложене портове.
        for port in exposed:
            host_ip = port.get("host_ip", "")
            host_port = port.get("host_port", "")
            container_port = port.get("container_port", "")
            protocol = port.get("protocol", "")

            if host_ip in ("0.0.0.0", "::"):
                color_port = "bold red"
                marker = " [bold red](public)[/bold red]"
            else:
                color_port = "dim"
                marker = ""

            console.print(
                f"    Port: [{color_port}]{host_ip}:{host_port}"
                f"→{container_port}/{protocol}[/{color_port}]{marker}"
            )
    elif ports:
        console.print(f"    Ports: [dim]{ports}[/dim]")

    console.print()