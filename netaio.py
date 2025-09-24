#!/usr/bin/env python3
"""NET AIO: all-in-one network CLI with a visual interface."""

from __future__ import annotations

import getpass
import ipaddress
import platform
import re
import secrets
import socket
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

try:
    import requests
    HAS_REQUESTS = True
except ModuleNotFoundError:
    requests = None  # type: ignore
    HAS_REQUESTS = False

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

console = Console()

ANIMATION_MESSAGES: Dict[str, str] = {
    "1": "Preparing network sweep",
    "2": "Initializing DNS resolution",
    "3": "Fetching IP information",
    "4": "Generating MAC addresses",
    "5": "Discovering subdomains",
    "6": "Tracing route",
    "7": "Running WHOIS lookup",
    "8": "Scanning ports",
}


MAX_SWEEP_HOSTS = 1024
MAX_PORT_SCAN = 4096


def show_transition(message: str, duration: float = 0.9) -> None:
    """Display a Rich spinner briefly before running an action."""
    with console.status(f"[bold cyan]{message}", spinner="dots"):
        time.sleep(duration)

COMMON_SUBDOMAINS: Sequence[str] = (
    "www",
    "mail",
    "ftp",
    "dev",
    "api",
    "test",
    "staging",
    "stage",
    "vpn",
    "admin",
    "portal",
    "intranet",
    "intra",
    "cdn",
    "static",
    "assets",
    "img",
    "media",
    "blog",
    "docs",
    "status",
    "app",
    "apps",
    "beta",
    "chat",
    "m",
    "mobile",
    "pay",
    "billing",
    "store",
    "shop",
    "auth",
    "secure",
    "sso",
    "support",
    "help",
    "news",
    "reports",
    "analytics",
    "edge",
    "firewall",
    "router",
    "gw",
    "gw1",
    "ns1",
    "ns2",
    "db",
    "db1",
    "files",
    "backup",
    "monitor",
)


@dataclass
class PingResult:
    ip: str
    reachable: bool
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None


def render_header() -> None:
    title = Text(" NET AIO CLI ", style="bold white on blue")
    subtitle = Text("Fast network utilities suite", style="bold cyan")
    console.print(Panel.fit(Text.assemble(title, "\n", subtitle), border_style="blue"))


def parse_ping_output(output: str) -> tuple[Optional[int], Optional[float]]:
    ttl_match = re.search(r"ttl[=|:](\d+)", output, re.IGNORECASE)
    ttl = int(ttl_match.group(1)) if ttl_match else None

    latency_match = re.search(r"time[=<]([\d\.]+) ?ms", output, re.IGNORECASE)
    if latency_match:
        latency = float(latency_match.group(1))
    elif "time<" in output.lower():
        latency = 0.5
    else:
        latency = None

    return ttl, latency


def run_ping(ip: str, timeout: float = 1.0) -> PingResult:
    """Run a single ping to determine reachability and collect metadata."""
    system = platform.system()
    if system == "Windows":
        command = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), ip]
    elif system == "Darwin":
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout * 1000))), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        started = time.perf_counter()
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        elapsed = (time.perf_counter() - started) * 1000
    except FileNotFoundError:
        console.print("[red]Command `ping` was not found on this system.")
        return PingResult(ip=ip, reachable=False)

    if completed.returncode != 0:
        return PingResult(ip=ip, reachable=False)

    ttl, latency = parse_ping_output(completed.stdout)
    if latency is None:
        latency = round(elapsed, 2)
    return PingResult(ip=ip, reachable=True, ttl=ttl, latency_ms=latency)


def ping_sweep() -> None:
    console.print("[bold cyan]Ping sweep /24 with latency and TTL")
    console.print(
        "Enter the network (e.g. 192.168.1.0/24 or 192.168.1):",
        style="dim",
    )
    network_input = console.input("[cyan]> [/] ").strip()

    if not network_input:
        console.print("[red]Empty input. Operation aborted.")
        return

    if "/" not in network_input:
        network_input = f"{network_input}/24"

    try:
        network = ipaddress.ip_network(network_input, strict=False)
    except ValueError as exc:
        console.print(f"[red]Invalid input: {exc}")
        return

    if network.version == 4 and network.prefixlen <= 30:
        host_count = max(network.num_addresses - 2, 0)
    else:
        host_count = network.num_addresses

    if host_count == 0:
        console.print("[yellow]No hosts available in the specified network.")
        return

    if host_count > MAX_SWEEP_HOSTS:
        console.print(
            f"[red]Network contains {host_count} hosts. Reduce the scope (limit: {MAX_SWEEP_HOSTS})."
        )
        return

    hosts = [str(host) for host in network.hosts()]

    results: List[PingResult] = []
    console.print(
        f"Scanning {len(hosts)} hosts in [bold]{network.with_prefixlen}[/]...",
        style="dim",
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Sweep in progress", total=len(hosts))
        max_workers = max(1, min(64, len(hosts)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(run_ping, host): host for host in hosts}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                progress.advance(task_id)

    reachable_results = [item for item in results if item.reachable]
    unreachable_count = len(results) - len(reachable_results)

    if reachable_results:
        table = Table(
            title="Reachable hosts",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("#", justify="center", style="cyan", no_wrap=True)
        table.add_column("IP address", style="green")
        table.add_column("Latency (ms)", justify="right", style="yellow")
        table.add_column("TTL", justify="center", style="magenta")

        for index, item in enumerate(
            sorted(reachable_results, key=lambda r: ipaddress.ip_address(r.ip)),
            start=1,
        ):
            latency = f"{item.latency_ms:.2f}" if item.latency_ms is not None else "-"
            ttl_display = str(item.ttl) if item.ttl is not None else "-"
            table.add_row(
                str(index),
                item.ip,
                latency,
                ttl_display,
            )
        console.print(table)
    else:
        console.print("[yellow]No reachable hosts found.")

    console.print(
        f"Unresponsive hosts: [bold]{unreachable_count}[/]",
        style="dim",
    )


def dns_resolver() -> None:
    console.print("[bold cyan]Resolve DNS")
    domain = console.input("[cyan]Enter the domain[/]: ").strip()

    if not domain:
        console.print("[red]You must enter a domain.")
        return

    try:
        addr_info = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        console.print(f"[red]Failed to resolve {domain}: {exc}.")
        return

    ipv4: List[str] = []
    ipv6: List[str] = []
    for _, _, _, _, sockaddr in addr_info:
        ip = sockaddr[0]
        if ":" in ip and ip not in ipv6:
            ipv6.append(ip)
        elif ip not in ipv4:
            ipv4.append(ip)

    table = Table(title=f"Results for {domain}", box=box.ROUNDED, show_lines=True)
    table.add_column("Type", justify="center", style="magenta")
    table.add_column("Address", style="green")

    for address in ipv4:
        table.add_row("A", address)
    for address in ipv6:
        table.add_row("AAAA", address)

    if not ipv4 and not ipv6:
        console.print("[yellow]No A or AAAA records found.")
        return

    console.print(table)


def describe_ip(ip_value: str) -> None:
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        console.print("[red]Invalid IP address.")
        return

    table = Table(title=f"General information for {ip_value}", box=box.ROUNDED, show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Version", str(ip_obj.version))
    table.add_row("Is private", str(ip_obj.is_private))
    table.add_row("Is global", str(ip_obj.is_global))
    table.add_row("Is loopback", str(ip_obj.is_loopback))
    table.add_row("Is multicast", str(ip_obj.is_multicast))
    table.add_row("Binary address", format(int(ip_obj), "b"))
    table.add_row("Integer", str(int(ip_obj)))

    console.print(table)

    if ip_obj.is_global:
        if not HAS_REQUESTS:
            console.print("[yellow]Module requests not available; skipping geolocation.")
            return
        geo = fetch_geolocation(ip_value)
        if geo:
            geo_table = Table(title="Approximate geolocation", box=box.ROUNDED, show_lines=True)
            geo_table.add_column("Field", style="cyan")
            geo_table.add_column("Value", style="green")
            for key, label in (
                ("country", "Country"),
                ("region", "Region"),
                ("city", "City"),
                ("org", "Organization"),
                ("timezone", "Timezone"),
            ):
                value = geo.get(key)
                if value:
                    geo_table.add_row(label, value)
            location = geo.get("loc")
            if location:
                geo_table.add_row("Coordinates", location)
            console.print(geo_table)
        else:
            console.print("[dim]Could not retrieve geolocation data (offline?).")
    else:
        console.print("[dim]IP is not global; skipping geolocation lookup.")


def describe_network(network_value: str) -> None:
    try:
        net = ipaddress.ip_network(network_value, strict=False)
    except ValueError:
        console.print("[red]Invalid network.")
        return

    hosts_count = net.num_addresses - 2 if net.prefixlen < net.max_prefixlen else 1

    table = Table(title=f"Information for {net.with_prefixlen}", box=box.ROUNDED, show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Network address", str(net.network_address))
    table.add_row("Broadcast", str(net.broadcast_address))
    table.add_row("Prefix", str(net.prefixlen))
    table.add_row("Usable hosts", str(max(hosts_count, 0)))
    table.add_row("Netmask", str(net.netmask))
    table.add_row("Wildcard", str(net.hostmask))

    console.print(table)


def ip_info_tool() -> None:
    console.print("[bold cyan]Information for IP")
    console.print(
        "Enter an IP (e.g. 8.8.8.8) or network (e.g. 10.0.0.0/24):",
        style="dim",
    )
    value = console.input("[cyan]> [/] ").strip()

    if not value:
        console.print("[red]You must enter a value.")
        return

    if "/" in value:
        describe_network(value)
    else:
        describe_ip(value)


def mac_generator() -> None:
    console.print("[bold cyan]MAC generator")
    console.print("How many addresses to generate? [default: 1]", style="dim")
    amount_raw = console.input("[cyan]> [/] ").strip()

    try:
        amount = int(amount_raw) if amount_raw else 1
        if amount <= 0:
            raise ValueError
    except ValueError:
        console.print("[red]Invalid amount. Must be a positive integer.")
        return

    console.print("Format (1) XX:XX:XX:XX:XX:XX, (2) Cisco XXXX.XXXX.XXXX", style="dim")
    format_choice = console.input("[cyan]Select format [1/2][/]: ").strip() or "1"

    macs = [generate_mac(format_choice) for _ in range(amount)]

    table = Table(title="Generated MAC addresses", box=box.ROUNDED, show_lines=True)
    table.add_column("#", justify="center", style="cyan", no_wrap=True)
    table.add_column("MAC", style="green")

    for idx, mac in enumerate(macs, start=1):
        table.add_row(str(idx), mac)

    console.print(table)


def generate_mac(format_choice: str) -> str:
    # MAC unicast administrada localmente.
    first_octet = secrets.randbelow(256) | 0x02
    first_octet &= 0xFE
    octets = [first_octet] + [secrets.randbelow(256) for _ in range(5)]

    if format_choice == "2":
        hex_pairs = [f"{octet:02X}" for octet in octets]
        cisco = "".join(hex_pairs)
        return ".".join(cisco[i : i + 4] for i in range(0, len(cisco), 4))

    return ":".join(f"{octet:02X}" for octet in octets)


def fetch_geolocation(ip_value: str) -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    url = f"https://ipinfo.io/{ip_value}/json"
    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    return data


def check_subdomain(domain: str, subdomain: str) -> Optional[tuple[str, List[str]]]:
    fqdn = f"{subdomain}.{domain}"
    try:
        info = socket.getaddrinfo(fqdn, None)
    except socket.gaierror:
        return None

    addresses = sorted({sockaddr[0] for *_, sockaddr in info})
    return fqdn, addresses


def subdomain_scanner() -> None:
    console.print("[bold cyan]Basic subdomain explorer")
    domain = console.input("[cyan]Target domain[/]: ").strip()
    if not domain:
        console.print("[red]You must provide a domain.")
        return

    console.print(
        f"Testing {len(COMMON_SUBDOMAINS)} common subdomains for {domain}...",
        style="dim",
    )

    findings: List[tuple[str, List[str]]] = []
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2.0)
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task_id = progress.add_task("Resolving entries", total=len(COMMON_SUBDOMAINS))
            max_workers = max(1, min(32, len(COMMON_SUBDOMAINS)))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(check_subdomain, domain, sub): sub for sub in COMMON_SUBDOMAINS
                }
                for future in as_completed(futures):
                    progress.advance(task_id)
                    result = future.result()
                    if result:
                        findings.append(result)
    finally:
        socket.setdefaulttimeout(previous_timeout)

    if not findings:
        console.print("[yellow]No resolvable subdomains found with the bundled list.")
        return

    table = Table(title=f"Subdomains found for {domain}", box=box.ROUNDED, show_lines=True)
    table.add_column("Subdomain", style="cyan")
    table.add_column("Addresses", style="green")

    for fqdn, addresses in sorted(findings, key=lambda item: item[0]):
        table.add_row(fqdn, "\n".join(addresses))

    console.print(table)


def traceroute_candidates(target: str) -> List[List[str]]:
    system = platform.system()
    candidates: List[List[str]] = []
    if system == "Windows":
        sequence = [["tracert", "-d", target], ["tracert", target]]
    else:
        sequence = []
        if shutil.which("mtr"):
            sequence.append(["mtr", "-r", "-c", "1", target])
        sequence.append(["traceroute", "-n", target])
        sequence.append(["tracepath", target])
    for command in sequence:
        if shutil.which(command[0]):
            candidates.append(command)
    return candidates


def traceroute_tool() -> None:
    console.print("[bold cyan]Traceroute / MTR")
    target = console.input("[cyan]Destination host or IP[/]: ").strip()
    if not target:
        console.print("[red]You must provide a target.")
        return

    commands = traceroute_candidates(target)
    if not commands:
        console.print("[red]No available command found (mtr/traceroute/tracert/tracepath).")
        return

    last_error: Optional[str] = None
    for command in commands:
        use_sudo = command[0] == "mtr" and platform.system() != "Windows"
        run_cmd = command
        input_data: Optional[str] = None

        if use_sudo:
            console.print("[yellow]mtr requires elevated privileges. The sudo password will be requested.[/]")
            try:
                password = getpass.getpass("Sudo password: ")
            except KeyboardInterrupt:
                console.print("[red]Operation cancelled by user.")
                return
            if not password:
                console.print("[red]No password provided. Skipping mtr execution.")
                continue
            run_cmd = ["sudo", "-S"] + command
            input_data = password + "\n"
            password = ""

        console.print(f"Running {' '.join(run_cmd)}", style="dim")
        try:
            completed = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                input=input_data,
                check=False,
            )
        except OSError as exc:
            last_error = str(exc)
            continue

        output = (completed.stdout or "") + (completed.stderr or "")
        output = output.strip()

        if completed.returncode == 0 and output:
            console.print(Panel.fit(output, title=f"Traceroute to {target}", border_style="blue"))
            return

        if use_sudo and completed.returncode != 0:
            console.print("[yellow]mtr with sudo failed. Attempting alternative...")
            if output:
                last_error = output
            continue

        if output:
            last_error = output

    if last_error:
        console.print(f"[red]Unable to run traceroute: {last_error}.")
    else:
        console.print("[red]No command produced usable output.")


def query_whois_server(server: str, query: str, timeout: float = 5.0) -> Optional[str]:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall(f"{query}\r\n".encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks: List[bytes] = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError:
        return None
    if not chunks:
        return None
    return b"".join(chunks).decode("utf-8", errors="replace")


def perform_whois_lookup(domain: str) -> Optional[str]:
    visited = set()
    server = "whois.iana.org"
    while server and server.lower() not in visited:
        visited.add(server.lower())
        response = query_whois_server(server, domain)
        if not response:
            return None
        refer = None
        for line in response.splitlines():
            lower = line.lower()
            if lower.startswith("refer:") or lower.startswith("whois server:"):
                refer = line.split(":", 1)[1].strip()
                break
        if refer and refer.lower() not in visited:
            server = refer
            continue
        return response
    return None


def whois_lookup() -> None:
    console.print("[bold cyan]Domain WHOIS")
    domain = console.input("[cyan]Domain to look up[/]: ").strip()
    if not domain:
        console.print("[red]You must provide a domain.")
        return
    output = None
    if shutil.which("whois"):
        try:
            completed = subprocess.run(["whois", domain], capture_output=True, text=True, check=False)
            output = completed.stdout.strip() or completed.stderr.strip()
        except OSError:
            output = None
    if not output:
        output = perform_whois_lookup(domain)
    if not output:
        console.print("[red]WHOIS information could not be retrieved (command or network unavailable).")
        return
    console.print(Panel.fit(output, title=f"WHOIS for {domain}", border_style="green"))


def parse_port_specification(spec: str) -> List[int]:
    if not spec:
        return list(range(1, 1025))
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            try:
                port = int(part)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def _prepare_sockaddr(base: Sequence[object], port: int) -> tuple:
    items = tuple(base)
    if len(items) == 2:
        host, _ = items
        return host, port
    if len(items) == 4:
        host, _, flowinfo, scopeid = items
        return host, port, flowinfo, scopeid
    return items


def scan_port(
    sockaddr: Sequence[object],
    family: int,
    socktype: int,
    proto: int,
    port: int,
    timeout: float = 1.0,
) -> bool:
    with socket.socket(family, socktype, proto) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(_prepare_sockaddr(sockaddr, port))
            return True
        except OSError:
            return False


def port_scanner() -> None:
    console.print("[bold cyan]Basic port scanner")
    target = console.input("[cyan]Target host or IP[/]: ").strip()
    if not target:
        console.print("[red]You must provide a target.")
        return
    try:
        addr_info = socket.getaddrinfo(
            target,
            None,
            proto=socket.IPPROTO_TCP,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        console.print(f"[red]Failed to resolve {target}: {exc}.")
        return
    endpoint = next((info for info in addr_info if info[1] == socket.SOCK_STREAM), None)
    if not endpoint:
        console.print(f"[red]No TCP endpoints found for {target}.")
        return
    family, socktype, proto, _, sockaddr = endpoint
    resolved_display = sockaddr[0]
    console.print(
        f"Resolved target: [bold]{target}[/] -> [bold]{resolved_display}[/]",
        style="dim",
    )
    console.print("Enter ports (e.g. 1-1024 or 22,80,443). Empty = 1-1024", style="dim")
    spec = console.input("[cyan]Ports[/]: ").strip()
    ports = parse_port_specification(spec)
    if not ports:
        console.print("[red]No valid ports provided.")
        return
    if len(ports) > MAX_PORT_SCAN:
        console.print(
            f"[red]Port selection expands to {len(ports)} entries. Limit: {MAX_PORT_SCAN}."
        )
        return
    open_ports: List[int] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning ports", total=len(ports))
        max_workers = max(1, min(128, len(ports)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_port, sockaddr, family, socktype, proto, port): port
                for port in ports
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass
                progress.advance(task_id)
    if open_ports:
        table = Table(title=f"Open ports on {target}", box=box.ROUNDED, show_lines=True)
        table.add_column("Port", justify="center", style="cyan")
        table.add_column("Service", style="green")
        for port in sorted(open_ports):
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "-"
            table.add_row(str(port), service)
        console.print(table)
    else:
        console.print("[yellow]No open ports detected in the scanned range.")





def build_menu_table() -> Table:
    table = Table(title="Select an option", box=box.ROUNDED, show_lines=True)
    table.add_column("Option", justify="center", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_row("1", "Ping sweep /24 with latency and TTL")
    table.add_row("2", "Resolve DNS")
    table.add_row("3", "IP / network information")
    table.add_row("4", "MAC generator")
    table.add_row("5", "Discover common subdomains")
    table.add_row("6", "Traceroute / MTR")
    table.add_row("7", "Domain WHOIS")
    table.add_row("8", "Port scan")
    table.add_row("0", "Exit")
    return table


def main() -> None:
    actions: Dict[str, Callable[[], None]] = {
        "1": ping_sweep,
        "2": dns_resolver,
        "3": ip_info_tool,
        "4": mac_generator,
        "5": subdomain_scanner,
        "6": traceroute_tool,
        "7": whois_lookup,
        "8": port_scanner,
    }

    while True:
        console.clear()
        render_header()
        console.print(build_menu_table())
        console.print("\nSelect an option and press Enter:", style="bold")
        choice = console.input("[cyan]> [/] ").strip()

        if choice == "0":
            console.print("[bold green]See you soon!")
            sys.exit(0)

        action = actions.get(choice)
        if action:
            console.rule(style="magenta")
            show_transition(ANIMATION_MESSAGES.get(choice, "Processing"))
            action()
        else:
            console.print("[red]Invalid option.")

        console.print("\nPress Enter to return to the menu...", style="dim")
        console.input()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Manual interruption. Exiting...")
        sys.exit(1)
