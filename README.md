# NET AIO CLI

Text-mode network utility suite built with Python and [Rich](https://github.com/Textualize/rich). It delivers a visual menu with ANSI animations plus a set of quick diagnostic tools for terminal workflows.

## Features

- **Ping sweep /24 with latency & TTL:** concurrent scan of a subnet to spot responsive hosts.
- **DNS resolver:** fetches A and AAAA records, grouped by IPv4/IPv6.
- **IP & network information:** leverages `ipaddress` for IP/subnet metadata and enriches with geolocation (via ipinfo.io) when available.
- **MAC address generator:** produces randomized MAC addresses (standard or Cisco-style) using locally administered identifiers.
- **Common subdomain discovery:** checks a bundled list of frequent subdomains via concurrent DNS resolution.
- **Traceroute / MTR:** prefers `mtr` (with sudo support on macOS/Linux); falls back to `traceroute`, `tracepath`, or `tracert` if needed.
- **Domain WHOIS:** integrates the `whois` CLI and includes a native WHOIS fallback hitting root servers.
- **Port scanner:** performs concurrent TCP connect scans (IPv4/IPv6) across a user-defined port range with smart limits.

## Requirements

- Python 3.9+
- Dependencies from `requirements.txt` (`rich`, `requests`).
- Optional external tools: `ping`, `mtr`, `traceroute`, `tracepath`, `tracert`, `whois`.

## Quick setup

- **Linux / macOS**

  ```bash
  ./setup_unix.sh
  ```

- **Windows (PowerShell, run as Administrator to install Python/WinMTR)**

  ```powershell
  powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
  ```

Both installers detect the platform, install Python automatically when missing, create/refresh a virtual environment, and validate dependencies. On macOS the script attempts to install `mtr` via Homebrew; on Linux it uses the detected package manager. On Windows the wizard prioritizes a local `python-installer.exe` (if present), otherwise downloads and installs Python 3.12.6 from python.org or uses `winget`/Chocolatey, and it installs WinMTR when available.

## Run the CLI

```bash
python3 netaio.py
```

Using a virtual environment?

```bash
source .venv/bin/activate  # Linux / macOS
.\.venv\Scripts\activate  # Windows
python netaio.py
```

## Usage notes

- Ping sweeps are capped at 1,024 hosts per run to keep resource usage predictable; trim the CIDR before scanning large networks.
- The port scanner accepts up to 4,096 ports per invocation and now resolves IPv4 or IPv6 targets automatically.
- Subdomain discovery applies a 2-second DNS timeout per host to avoid hanging on slow resolvers.

## Screenshots

<img width="2024" height="1340" alt="CleanShot 2025-09-24 at 11 36 27@2x" src="https://github.com/user-attachments/assets/25003752-4187-4356-8d5c-4dfd0984b703" />


## Contributing

1. Fork the repository and create a descriptive branch (`feature/new-tool`).
2. Run `./setup_unix.sh` (Linux/macOS) or `powershell -File .\setup_windows.ps1` to align the environment.
3. Add tests or examples when possible.
4. Open a Pull Request describing changes and how to test them.

## License

This project is distributed under the terms of the [MIT License](LICENSE).
