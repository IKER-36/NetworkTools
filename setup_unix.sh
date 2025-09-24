#!/usr/bin/env bash
# Linux/macOS setup helper for NET AIO CLI.

set -Eeuo pipefail

RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
VENV_DIR="${SCRIPT_DIR}/.venv"
PYTHON_BIN=""
OS_CHOICE=""
USING_VENV=0
REQUIREMENTS_LIST=()

trap 'printf "\n${RED}Installation cancelled by user.${RESET}\n"; exit 1' INT

print_banner() {
  printf "${BOLD}${CYAN}\n╔══════════════════════════════════════╗${RESET}\n"
  printf "${BOLD}${CYAN}║    NET AIO CLI • Easy Setup Wizard   ║${RESET}\n"
  printf "${BOLD}${CYAN}╚══════════════════════════════════════╝${RESET}\n"
  printf "${YELLOW}Step-by-step guidance with minimal fuss.${RESET}\n\n"
}

pause_for_user() {
  printf "${DIM}Press Enter to continue...${RESET}"
  read -r _
}

select_os() {
  printf "${BOLD}Which platform are you setting up?${RESET}\n"
  printf "  [1] Linux (Ubuntu, Debian, Fedora, etc.)\n"
  printf "  [2] macOS\n"
  printf "  [3] Windows (PowerShell / Git Bash)\n"
  printf "  [0] Quit\n"
  while :; do
    read -r -p "${CYAN}> ${RESET}" choice
    case "${choice}" in
      1) OS_CHOICE="linux"; break ;;
      2) OS_CHOICE="macos"; break ;;
      3) OS_CHOICE="windows"; break ;;
      0) printf "${MAGENTA}See you next time!${RESET}\n"; exit 0 ;;
      *) printf "${RED}Unrecognized option, please try again.${RESET}\n" ;;
    esac
  done
}

show_os_briefing() {
  case "${OS_CHOICE}" in
    linux)
      printf "${BLUE}\nLinux selected.${RESET}\n"
      printf "${DIM}We'll lean on python3 and pip3 from your package manager.${RESET}\n\n"
      ;;
    macos)
      printf "${BLUE}\nmacOS selected.${RESET}\n"
      printf "${DIM}Homebrew or Xcode Command Line Tools make life easier here.${RESET}\n\n"
      ;;
    windows)
      printf "${BLUE}\nWindows selected.${RESET}\n"
      printf "${DIM}Works from PowerShell, CMD, or Git Bash with the official Python installer.${RESET}\n\n"
      ;;
  esac
}

install_python_linux() {
  printf "${BOLD}Attempting to install Python automatically...${RESET}\n"
  if command -v apt-get >/dev/null 2>&1; then
    run_command_with_confirmation "Updating package index" sudo apt-get update || true
    if run_command_with_confirmation "Installing python3 and pip" sudo apt-get install -y python3 python3-pip; then
      return 0
    fi
  elif command -v dnf >/dev/null 2>&1; then
    if run_command_with_confirmation "Installing python3 and pip" sudo dnf install -y python3 python3-pip; then
      return 0
    fi
  elif command -v pacman >/dev/null 2>&1; then
    if run_command_with_confirmation "Installing python and pip" sudo pacman -S --noconfirm python python-pip; then
      return 0
    fi
  elif command -v zypper >/dev/null 2>&1; then
    if run_command_with_confirmation "Installing python3 and pip" sudo zypper install -y python3 python3-pip; then
      return 0
    fi
  else
    printf "${YELLOW}No supported package manager detected automatically.${RESET}\n"
  fi
  printf "${YELLOW}Install python3 and pip manually, then rerun this script.${RESET}\n"
  return 1
}

install_python_macos() {
  printf "${BOLD}Attempting to install Python automatically...${RESET}\n"
  if command -v brew >/dev/null 2>&1; then
    if run_command_with_confirmation "Installing Python via Homebrew" brew install python; then
      return 0
    fi
  else
    printf "${YELLOW}Homebrew was not detected. Install it from https://brew.sh/ first.${RESET}\n"
  fi
  printf "${YELLOW}If installation fails, download the official installer from https://www.python.org/downloads/.${RESET}\n"
  return 1
}

attempt_python_install() {
  case "${OS_CHOICE}" in
    linux)
      install_python_linux
      ;;
    macos)
      install_python_macos
      ;;
    windows)
      printf "${YELLOW}Automatic Python installation on Windows is handled by setup_windows.ps1. Use that script for a fully automated setup.${RESET}\n"
      return 1
      ;;
    *)
      printf "${YELLOW}Unsupported platform for automatic Python installation.${RESET}\n"
      return 1
      ;;
  esac
}

find_python() {
  local candidate
  local -a candidates=("$@")
  for candidate in "${candidates[@]}"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      PYTHON_BIN="${candidate}"
      return 0
    fi
  done
  return 1
}

resolve_python_command() {
  case "${OS_CHOICE}" in
    linux|macos)
      find_python python3 python
      ;;
    windows)
      find_python py python python3
      ;;
  esac

  if [[ -z "${PYTHON_BIN}" ]]; then
    printf "${YELLOW}\nPython interpreter not detected. Attempting automated installation...${RESET}\n"
    if attempt_python_install; then
      case "${OS_CHOICE}" in
        linux|macos)
          find_python python3 python
          ;;
        windows)
          find_python py python python3
          ;;
      esac
    fi
  fi

  if [[ -z "${PYTHON_BIN}" ]]; then
    printf "${RED}\nCould not find a Python interpreter automatically.${RESET}\n"
    case "${OS_CHOICE}" in
      linux)
        printf "${YELLOW}Install manually:${RESET} sudo apt install python3 python3-pip (or use your distro's package manager).\n"
        ;;
      macos)
        printf "${YELLOW}Install manually:${RESET} brew install python (or download from https://www.python.org/downloads/).\n"
        ;;
      windows)
        printf "${YELLOW}Use:${RESET} setup_windows.ps1 for automated setup, or download from https://www.python.org/downloads/windows/ and enable \"Add python.exe to PATH\".${RESET}\n"
        ;;
    esac
    return 1
  fi

  printf "${GREEN}✔ Python executable:${RESET} ${PYTHON_BIN}\n"
  printf "${DIM}Detected version: $(${PYTHON_BIN} -V 2>&1)${RESET}\n\n"
  return 0
}

python_in_venv_path() {
  if [[ "${OS_CHOICE}" == "windows" ]]; then
    printf "%s" "${VENV_DIR}/Scripts/python.exe"
  else
    printf "%s" "${VENV_DIR}/bin/python"
  fi
}

create_virtualenv() {
  local base_python="${PYTHON_BIN}"
  printf "${BOLD}Creating local virtual environment .venv${RESET}\n"
  if [[ -d "${VENV_DIR}" ]]; then
    printf "${YELLOW}.venv already exists, reusing it.${RESET}\n"
  else
    printf "${DIM}Running:${RESET} ${base_python} -m venv ${VENV_DIR}\n"
    if ! "${base_python}" -m venv "${VENV_DIR}"; then
      printf "${RED}Failed to create the virtual environment.${RESET}\n"
      return 1
    fi
  fi

  local new_python
  new_python="$(python_in_venv_path)"
  if [[ ! -x "${new_python}" ]]; then
    printf "${RED}Virtual environment python binary missing.${RESET}\n"
    return 1
  fi

  PYTHON_BIN="${new_python}"
  USING_VENV=1
  printf "${GREEN}✔ Using virtual environment:${RESET} ${VENV_DIR}\n"
  if [[ "${OS_CHOICE}" == "windows" ]]; then
    printf "${DIM}Activate later via:${RESET} ${VENV_DIR}\\Scripts\\activate.bat\n"
  else
    printf "${DIM}Activate later via:${RESET} source ${VENV_DIR}/bin/activate\n"
  fi
  printf "${DIM}Continuing dependency installation inside this environment.${RESET}\n\n"
  return 0
}

handle_externally_managed() {
  printf "${YELLOW}This Python looks externally managed (PEP 668).${RESET}\n"
  printf "${DIM}Switching to a local virtual environment avoids conflicts.${RESET}\n"
  printf "${BOLD}Create .venv automatically? [Y/n] ${RESET}"
  local answer
  read -r answer || answer=""
  if [[ ! "${answer}" =~ ^[Nn] ]]; then
    if create_virtualenv; then
      return 0
    fi
    printf "${RED}Unable to prepare the virtual environment automatically.${RESET}\n"
  fi

  printf "${MAGENTA}\nManual steps:${RESET}\n"
  printf " 1. ${BOLD}${PYTHON_BIN} -m venv .venv${RESET}\n"
  if [[ "${OS_CHOICE}" == "windows" ]]; then
    printf " 2. ${BOLD}.\\.venv\\Scripts\\activate${RESET}\n"
  else
    printf " 2. ${BOLD}source .venv/bin/activate${RESET}\n"
  fi
  printf " 3. Rerun this script.${RESET}\n"
  return 1
}

run_pip_task() {
  local label="$1"
  shift
  printf "${BOLD}%s${RESET}\n" "${label}"
  while :; do
    local -a cmd=("${PYTHON_BIN}" -m pip "$@")
    local tmp_log
    tmp_log="$(mktemp)"
    if "${cmd[@]}" > >(tee "${tmp_log}") 2> >(tee -a "${tmp_log}" >&2); then
      printf "${GREEN}✔ %s${RESET}\n" "${label}"
      rm -f "${tmp_log}"
      return 0
    else
      local status=$?
      local output
      output="$(<"${tmp_log}")"
      rm -f "${tmp_log}"
      if [[ "${output}" == *"externally-managed-environment"* ]]; then
        if handle_externally_managed; then
          continue
        fi
      fi
      printf "${RED}Command failed (exit code %d).${RESET}\n" "${status}"
      if [[ -n "${output}" ]]; then
        printf "%s\n" "${output}"
      fi
      exit 1
    fi
  done
}

ensure_pip() {
  if "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
    printf "${GREEN}✔ pip is already available.${RESET}\n"
    return 0
  fi

  printf "${YELLOW}pip not detected. Attempting automatic setup...${RESET}\n"
  if "${PYTHON_BIN}" -m ensurepip --upgrade >/dev/null 2>&1; then
    printf "${GREEN}✔ pip installed successfully.${RESET}\n"
    return 0
  fi

  printf "${RED}Could not install pip automatically.${RESET}\n"
  case "${OS_CHOICE}" in
    linux)
      printf "${YELLOW}Install pip manually:${RESET} sudo apt install python3-pip\n"
      ;;
    macos)
      printf "${YELLOW}Install pip manually:${RESET} brew reinstall python\n"
      printf "${DIM}Or run: ${PYTHON_BIN} -m ensurepip --default-pip${RESET}\n"
      ;;
    windows)
      printf "${YELLOW}Run in PowerShell:${RESET} ${PYTHON_BIN} -m ensurepip --default-pip\n"
      printf "${DIM}Then rerun this script.${RESET}\n"
      ;;
  esac
  return 1
}

read_requirements() {
  if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
    printf "${RED}Could not find requirements.txt at ${REQUIREMENTS_FILE}.${RESET}\n"
    exit 1
  fi
  REQUIREMENTS_LIST=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%%#*}"
    line="${line%$'\r'}"
    line="${line#${line%%[![:space:]]*}}"
    line="${line%${line##*[![:space:]]}}"
    if [[ -n "${line}" ]]; then
      REQUIREMENTS_LIST+=("${line}")
    fi
  done < "${REQUIREMENTS_FILE}"
}

extract_package_name() {
  local requirement="$1"
  requirement="${requirement%%#*}"
  requirement="${requirement%%;*}"
  requirement="${requirement#${requirement%%[![:space:]]*}}"
  requirement="${requirement%${requirement##*[![:space:]]}}"
  local base="${requirement%%[<>=!~ ]*}"
  base="${base%${base##*[![:space:]]}}"
  base="${base%%[*}"
  printf '%s' "${base}"
}

resolve_import_name() {
  local package="$1"
  case "${package}" in
    requests) printf 'requests' ;;
    rich) printf 'rich' ;;
    *) printf '%s' "${package//-/_}" ;;
  esac
}

requirement_status() {
  local requirement="$1"
  "${PYTHON_BIN}" - <<'PY' "$requirement"
import re
import sys
from importlib import metadata

req_str = sys.argv[1]
try:
    from pip._vendor.packaging.requirements import Requirement
except Exception:
    name = re.split(r'[<>=!~]', req_str, 1)[0].strip()
    if not name:
        sys.exit(3)
    try:
        metadata.version(name)
    except metadata.PackageNotFoundError:
        sys.exit(2)
    else:
        sys.exit(0)

req = Requirement(req_str)
name = req.name
try:
    version = metadata.version(name)
except metadata.PackageNotFoundError:
    sys.exit(2)

if req.specifier and not req.specifier.contains(version, prereleases=True):
    sys.exit(1)
sys.exit(0)
PY
  return $?
}

get_installed_version() {
  local package="$1"
  "${PYTHON_BIN}" - <<'PY' "$package"
import sys
from importlib import metadata

name = sys.argv[1]
try:
    print(metadata.version(name))
except metadata.PackageNotFoundError:
    sys.exit(1)
PY
}

verify_import() {
  local module="$1"
  "${PYTHON_BIN}" - <<'PY' "$module"
import importlib
import sys

module = sys.argv[1]
try:
    importlib.import_module(module)
except Exception:
    sys.exit(1)
sys.exit(0)
PY
}

install_single_requirement() {
  local requirement="$1"
  local package
  package="$(extract_package_name "${requirement}")"
  if [[ -z "${package}" ]]; then
    printf "${YELLOW}Empty or skipped dependency entry: %s${RESET}
" "${requirement}"
    return
  fi

  local module
  module="$(resolve_import_name "${package}")"

  printf "${CYAN}→ Checking ${package}${RESET} ${DIM}(${requirement})${RESET}
"

  requirement_status "${requirement}"
  local status=$?
  if [[ ${status} -gt 2 ]]; then
    status=2
  fi

  if [[ ${status} -eq 0 ]]; then
    local version
    if version="$(get_installed_version "${package}" 2>/dev/null)"; then
      printf "    ${GREEN}✔ Already installed (version ${version}).${RESET}
"
    else
      printf "    ${GREEN}✔ Already installed.${RESET}
"
    fi
    if verify_import "${module}"; then
      printf "    ${GREEN}↳ Import check succeeded (${module}).${RESET}
"
    else
      printf "    ${YELLOW}↳ Installed, but import failed for ${module}.${RESET}
"
    fi
    return
  fi

  if [[ ${status} -eq 2 ]]; then
    printf "    ${YELLOW}• Not installed. Installing...${RESET}
"
  else
    printf "    ${YELLOW}• Version missing or incompatible. Updating...${RESET}
"
  fi

  run_pip_task "Installing ${package}" install --disable-pip-version-check --upgrade "${requirement}"

  requirement_status "${requirement}"
  local post_status=$?
  if [[ ${post_status} -ne 0 ]]; then
    printf "    ${RED}✖ Could not validate installation of ${package}.${RESET}
"
    exit 1
  fi

  local version
  if version="$(get_installed_version "${package}" 2>/dev/null)"; then
    printf "    ${GREEN}✔ Installation verified (version ${version}).${RESET}
"
  else
    printf "    ${GREEN}✔ Installation completed.${RESET}
"
  fi

  if verify_import "${module}"; then
    printf "    ${GREEN}↳ Import check succeeded (${module}).${RESET}
"
  else
    printf "    ${YELLOW}↳ Installed, but import failed for ${module}.${RESET}
"
  fi
}

confirm_proceed() {
  printf "${BOLD}Continue with dependency installation? [Y/n] ${RESET}"
  read -r answer
  if [[ "${answer}" =~ ^[Nn] ]]; then
    printf "${MAGENTA}Operation cancelled. No changes made.${RESET}
"
    exit 0
  fi
}

run_pip_install() {
  read_requirements

  run_pip_task "Step 1/2: Upgrading pip..." install --upgrade pip
  printf "
${BOLD}Step 2/2:${RESET} Checking dependencies one by one...
"

  if [[ ${#REQUIREMENTS_LIST[@]} -eq 0 ]]; then
    printf "${YELLOW}No dependencies found in requirements.txt.${RESET}
"
    return
  fi

  local total=${#REQUIREMENTS_LIST[@]}
  local index=1
  for requirement in "${REQUIREMENTS_LIST[@]}"; do
    printf "${DIM}[%d/%d]${RESET}
" "${index}" "${total}"
    install_single_requirement "${requirement}"
    if [[ ${index} -lt ${total} ]]; then
      printf "
"
    fi
    index=$((index + 1))
  done
}

run_command_with_confirmation() {
  local description="$1"
  shift
  local -a command=("$@")
  printf "  ${BOLD}%s${RESET}
" "${description}"
  printf "    ${DIM}%s${RESET}
" "${command[*]}"
  printf "  Do you want to run it now? [Y/n] "
  read -r answer
  if [[ ! "${answer}" =~ ^[Nn] ]]; then
    if "${command[@]}"; then
      printf "    ${GREEN}✔ Command executed successfully.${RESET}
"
      return 0
    fi
    printf "    ${RED}✖ Command reported an error.${RESET}
"
    return 1
  fi
  printf "  ${YELLOW}Command skipped by user.${RESET}
"
  return 1
}

check_mtr_available() {
  command -v mtr >/dev/null 2>&1
}

install_mtr_linux() {
  if check_mtr_available; then
    printf "${GREEN}✔ mtr already present.${RESET}
"
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    printf "Attempting to install mtr using apt-get (sudo required).
"
    run_command_with_confirmation "Updating package index" sudo apt-get update || true
    if run_command_with_confirmation "Installing mtr" sudo apt-get install -y mtr; then
      return 0
    fi
  elif command -v dnf >/dev/null 2>&1; then
    printf "Attempting to install mtr using dnf (sudo required).
"
    if run_command_with_confirmation "Installing mtr" sudo dnf install -y mtr; then
      return 0
    fi
  elif command -v pacman >/dev/null 2>&1; then
    printf "Attempting to install mtr using pacman (sudo required).
"
    if run_command_with_confirmation "Installing mtr" sudo pacman -S --noconfirm mtr; then
      return 0
    fi
  elif command -v zypper >/dev/null 2>&1; then
    printf "Attempting to install mtr using zypper (sudo required).
"
    if run_command_with_confirmation "Installing mtr" sudo zypper install -y mtr; then
      return 0
    fi
  else
    printf "${YELLOW}No supported package manager detected automatically.${RESET}
"
  fi

  printf "${YELLOW}Install mtr manually (e.g. sudo apt install mtr).${RESET}
"
  return 1
}

install_mtr_macos() {
  if check_mtr_available; then
    printf "${GREEN}✔ mtr already present.${RESET}
"
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    printf "Attempting to install mtr with Homebrew.
"
    if run_command_with_confirmation "Installing mtr" brew install mtr; then
      printf "${DIM}If necessary, link with: brew link mtr${RESET}
"
      printf "${DIM}Run mtr with sudo: sudo mtr <host>${RESET}
"
      printf "${DIM}To avoid sudo: sudo chown root:wheel $(brew --prefix)/Cellar/mtr/*/sbin/mtr && sudo chmod u+s $(brew --prefix)/Cellar/mtr/*/sbin/mtr${RESET}
"
      return 0
    fi
  else
    printf "${YELLOW}Homebrew not available. Install it from https://brew.sh then run 'brew install mtr'.${RESET}
"
  fi
  printf "${YELLOW}You can also install mtr via MacPorts (sudo port install mtr).${RESET}
"
  return 1
}

install_mtr_windows() {
  if check_mtr_available; then
    printf "${GREEN}✔ mtr already present.${RESET}
"
    return 0
  fi
  if command -v choco >/dev/null 2>&1; then
    printf "Attempting to install WinMTR via Chocolatey.
"
    if run_command_with_confirmation "Installing WinMTR" choco install winmtr --yes; then
      printf "${GREEN}✔ WinMTR installed. Launch it as 'winmtr'.${RESET}
"
      return 0
    fi
  elif command -v winget >/dev/null 2>&1; then
    printf "Attempting to install WinMTR via winget.
"
    if run_command_with_confirmation "Installing WinMTR" winget install --id WinMTR.WinMTR -e --accept-package-agreements --accept-source-agreements; then
      printf "${GREEN}✔ WinMTR installed. Launch it as 'WinMTR'.${RESET}
"
      return 0
    fi
  else
    printf "${YELLOW}Neither Chocolatey nor winget detected. Download WinMTR manually: https://github.com/White-Tesla/WinMTR${RESET}
"
  fi
  return 1
}

install_mtr_cli() {
  printf "
${BOLD}Extra step:${RESET} Checking for mtr/WinMTR availability...
"
  case "${OS_CHOICE}" in
    linux)
      install_mtr_linux
      ;;
    macos)
      install_mtr_macos
      ;;
    windows)
      install_mtr_windows
      ;;
    *)
      printf "${YELLOW}Unsupported OS for automatic mtr installation.${RESET}
"
      ;;
  esac

  if check_mtr_available; then
    printf "${GREEN}✔ mtr command available after verification.${RESET}
"
  else
    printf "${YELLOW}mtr is still unavailable. NET AIO will fall back to traceroute/tracert.${RESET}
"
  fi
}

wrap_up() {
  printf "
${BOLD}${CYAN}All set.${RESET}
"
  printf "${GREEN}You can now run:${RESET} ${PYTHON_BIN} ${SCRIPT_DIR}/netaio.py
"
  if [[ "${USING_VENV}" -eq 1 ]]; then
    if [[ "${OS_CHOICE}" == "windows" ]]; then
      printf "${DIM}Activate the environment later with:${RESET} .\.venv\Scripts\activate${RESET}
"
    else
      printf "${DIM}Activate the environment later with:${RESET} source .venv/bin/activate${RESET}
"
    fi
  else
    printf "${DIM}Tip:${RESET} use python -m venv .venv to keep dependencies isolated.${RESET}
"
  fi
}

main() {
  print_banner
  pause_for_user
  select_os
  show_os_briefing

  if ! resolve_python_command; then
    exit 1
  fi

  if ! ensure_pip; then
    exit 1
  fi

  confirm_proceed
  run_pip_install
  install_mtr_cli
  wrap_up
}

main "$@"
