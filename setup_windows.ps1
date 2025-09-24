[CmdletBinding()]
param()

<#
    Windows setup helper for NET AIO CLI. Automates Python/.venv provisioning.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section($Message) {
    Write-Host "`n$Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host $Message -ForegroundColor Green
}

function Write-WarningLine($Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Write-ErrorLine($Message) {
    Write-Host $Message -ForegroundColor Red
}

function Test-IsAdministrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-PythonPath {
    $candidates = @("python.exe", "python3.exe", "py.exe")
    foreach ($name in $candidates) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            if ($name -eq 'py.exe') {
                try {
                    $path = & $cmd.Path -3 -c "import sys; print(sys.executable)"
                    if ($LASTEXITCODE -eq 0 -and $path) {
                        return $path.Trim()
                    }
                } catch {
                    continue
                }
            } else {
                try {
                    & $cmd.Path --version > $null 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        return $cmd.Path
                    }
                } catch {
                    continue
                }
            }
        }
    }
    $searchRoots = @()
    if ($env:LOCALAPPDATA) {
        $searchRoots += Join-Path $env:LOCALAPPDATA 'Programs\Python'
    }
    if ($env:ProgramFiles) {
        $searchRoots += Join-Path $env:ProgramFiles 'Python'
    }
    if ($env:ProgramFilesx86) {
        $searchRoots += Join-Path $env:ProgramFilesx86 'Python'
    }
    $searchRoots = $searchRoots | Where-Object { $_ -and (Test-Path $_) }
    foreach ($root in $searchRoots) {
        $pythonExe = Get-ChildItem -Path $root -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($pythonExe) {
            try {
                & $pythonExe.FullName --version > $null 2>&1
                if ($LASTEXITCODE -eq 0) {
                    return $pythonExe.FullName
                }
            } catch {
                continue
            }
        }
    }
    return $null
}

function Install-Python {
    Write-Section "Python not detected. Installing Python 3..."
    if (-not (Test-IsAdministrator)) {
        Write-WarningLine "Run PowerShell as Administrator to allow Python installation."
        throw "Administrator privileges required to install Python automatically."
    }

    if ($script:LocalPythonInstaller -and (Test-Path $script:LocalPythonInstaller)) {
        Write-Section "Using bundled installer: $($script:LocalPythonInstaller)"
        $arguments = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'
        try {
            $process = Start-Process -FilePath $script:LocalPythonInstaller -ArgumentList $arguments -Wait -PassThru -Verb RunAs
        } catch {
            Write-WarningLine "Failed to launch bundled installer: $_"
            $process = $null
        }
        if ($process -and $process.ExitCode -eq 0) {
            Write-Success "Python installed from bundled executable."
            return $true
        }
        Write-WarningLine "Bundled installer did not complete successfully (exit code $($process?.ExitCode)). Falling back to package managers..."
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Python installed via winget."
            return $true
        }
        Write-WarningLine "winget installation failed (exit $LASTEXITCODE)."
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        & choco install python --yes
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Python installed via Chocolatey."
            return $true
        }
        Write-WarningLine "Chocolatey installation failed (exit $LASTEXITCODE)."
    } elseif ($script:PythonDownloadUrl) {
        try {
            Write-Section "Downloading Python from $($script:PythonDownloadUrl)"
            $downloadPath = Join-Path ([IO.Path]::GetTempPath()) 'python-installer.exe'
            Invoke-WebRequest -Uri $script:PythonDownloadUrl -OutFile $downloadPath -UseBasicParsing
            Write-Section "Running downloaded installer"
            $arguments = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'
            $process = Start-Process -FilePath $downloadPath -ArgumentList $arguments -Wait -PassThru -Verb RunAs
            if ($process.ExitCode -eq 0) {
                Write-Success "Python installed from downloaded executable."
                return $true
            }
            Write-WarningLine "Downloaded installer exited with code $($process.ExitCode)."
        } catch {
            Write-WarningLine "Failed to download or install Python automatically: $_"
        }
    } else {
        Write-WarningLine "winget/Chocolatey not found. Install Python manually from https://www.python.org/downloads/windows/."
        return $false
    }
    return $false
}

function Ensure-Pip($Python) {
    Write-Section "Ensuring pip is available"
    & $Python -m ensurepip --upgrade
    if ($LASTEXITCODE -ne 0) {
        throw "ensurepip failed with exit code $LASTEXITCODE"
    }
}

function Ensure-Venv($Python, $VenvPath) {
    $venvPython = Join-Path $VenvPath 'Scripts\python.exe'
    if (Test-Path $VenvPath) {
        if (-not (Test-Path $venvPython)) {
            Write-WarningLine "Existing virtual environment looks corrupted. Recreating..."
            Remove-Item $VenvPath -Recurse -Force
        } else {
            Write-Section "Reusing existing virtual environment at $VenvPath"
            return $venvPython
        }
    }

    Write-Section "Creating virtual environment at $VenvPath"
    & $Python -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) {
        throw "venv creation failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path $venvPython)) {
        throw "Virtual environment python binary not found at $venvPython"
    }
    return $venvPython
}

function Install-Requirements($Python, $RequirementsFile) {
    Write-Section "Upgrading pip"
    & $Python -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "pip upgrade failed with exit code $LASTEXITCODE"
    }
    Write-Section "Installing project dependencies"
    & $Python -m pip install --disable-pip-version-check --upgrade -r $RequirementsFile
    if ($LASTEXITCODE -ne 0) {
        throw "requirements installation failed with exit code $LASTEXITCODE"
    }
    Write-Success "Dependencies ready."
}

function Ensure-WinMTR {
    if (Get-Command mtr -ErrorAction SilentlyContinue) {
        return
    }
    if (Get-Command winmtr -ErrorAction SilentlyContinue) {
        return
    }
    Write-Section "Optional: Installing WinMTR"
    if (-not (Test-IsAdministrator)) {
        Write-WarningLine "Run PowerShell as Administrator to install WinMTR automatically."
        return
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install --id WinMTR.WinMTR -e --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -eq 0) {
            Write-Success "WinMTR installed via winget."
            return
        }
        Write-WarningLine "winget WinMTR installation failed (exit $LASTEXITCODE)."
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        & choco install winmtr --yes
        if ($LASTEXITCODE -eq 0) {
            Write-Success "WinMTR installed via Chocolatey."
            return
        }
        Write-WarningLine "Chocolatey WinMTR installation failed (exit $LASTEXITCODE)."
    } else {
        Write-WarningLine "Install WinMTR manually from https://github.com/White-Tesla/WinMTR if needed."
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
$script:LocalPythonInstaller = Join-Path $ScriptDir 'python-installer.exe'
$script:PythonDownloadUrl = 'https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe'
$RequirementsFile = Join-Path $ScriptDir 'requirements.txt'
$VenvPath = Join-Path $ScriptDir '.venv'

Write-Section 'NET AIO CLI • Windows Setup Wizard'
if (-not (Test-IsAdministrator)) {
    Write-WarningLine "Tip: run PowerShell as Administrator to allow automatic installations (Python, WinMTR)."
}

$pythonPath = Resolve-PythonPath
if (-not $pythonPath) {
    if (Install-Python) {
        $pythonPath = Resolve-PythonPath
    }
}
if (-not $pythonPath) {
    throw "Python is still unavailable. Install it manually and rerun the script."
}
Write-Section "Using Python at $pythonPath"

Ensure-Pip -Python $pythonPath
$pythonPath = Ensure-Venv -Python $pythonPath -VenvPath $VenvPath
Write-Section "Active environment: $VenvPath"

Install-Requirements -Python $pythonPath -RequirementsFile $RequirementsFile
Ensure-WinMTR

Write-Success "All set! Activate the environment with:`n  .\\.venv\\Scripts\\Activate.ps1`nThen run:  python netaio.py"
