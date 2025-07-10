# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

param (
    [string]$resourcesDirOverride
)

$ErrorActionPreference = "Stop"

# Resolve script and project structure
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$dockerDir = $scriptPath
$scriptsDir = Resolve-Path "$dockerDir\.."

# Set resources directory
$resourcesDir = if ($resourcesDirOverride) {
    Resolve-Path $resourcesDirOverride
} else {
    Join-Path $dockerDir ".resources"
}

# Create .resources directory
New-Item -ItemType Directory -Force -Path $resourcesDir | Out-Null

# =======================
# === Dependency Logic ===
# =======================

function Run-Log {
    param([ScriptBlock]$Command, [string]$Name)
    $logfile = "$Name.log"
    "" | Out-File $logfile
    Get-Date | Out-File $logfile -Append
    & $Command | Out-File $logfile -Append
    Get-Date | Out-File $logfile -Append
}

function Get-SimAVR {
    Invoke-WebRequest -Uri "https://github.com/buserror/simavr/archive/v1.6.tar.gz" -OutFile "simavr-v1.6.tar.gz"
    tar -xf "simavr-v1.6.tar.gz"
    Push-Location "simavr-1.6"
    git apply "$dockerDir\simavr.patch"
    Pop-Location
}

function Get-MSP430-GCC {
    Invoke-WebRequest -Uri "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/8_2_0_0/exports/msp430-gcc-8.2.0.52_linux64.tar.bz2" -OutFile "msp430-gcc.tar.bz2"
    Invoke-WebRequest -Uri "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/8_2_0_0/exports/msp430-gcc-support-files-1.207.zip" -OutFile "support.zip"
    tar -xf "msp430-gcc.tar.bz2"
    Expand-Archive -Path "support.zip" -DestinationPath "."
    Copy-Item -Recurse -Path "msp430-gcc-support-files" -Destination "msp430-gcc-8.2.0.52_linux64\support-files"
}

function Get-MSPDebug {
    Invoke-WebRequest -Uri "https://github.com/dlbeer/mspdebug/archive/v0.25.tar.gz" -OutFile "mspdebug.tar.gz"
    tar -xf "mspdebug.tar.gz"
}

function Get-Avrora {
    Write-Host "⚠️ Skipping Avrora: CVS not supported in PowerShell. Download manually if needed."
}

function Get-JLink {
    $url = "https://www.segger.com/downloads/jlink/JLink_Linux_x86_64.deb"
    Invoke-WebRequest -Uri $url -Method Post -Body @{
        accept_license_agreement = "accepted"
        non_emb_ctr = "confirmed"
        submit = "Download software"
    } -OutFile "JLink_Linux_x86_64.deb"
}

function Get-nRF-Tools {
    $url = "https://www.nordicsemi.com/-/media/Software-and-other-downloads/Desktop-software/nRF-command-line-tools/sw/Versions-10-x-x/nRFCommandLineTools1021Linuxamd64tar.gz"
    Invoke-WebRequest -Uri $url -OutFile "nRFCommandLineTools.tar.gz"
    tar -xf "nRFCommandLineTools.tar.gz" "nRF-Command-Line-Tools_10_2_1_Linux-amd64.deb"
}

function Get-OpenSTLink {
    $url = "https://github.com/texane/stlink/archive/v1.5.1.tar.gz"
    Invoke-WebRequest -Uri $url -OutFile "stlink.tar.gz"
    tar -xf "stlink.tar.gz"
}

# ================
# === Download ===
# ================

Push-Location $resourcesDir

$downloads = @(
    @{ Name = "get-simavr"; Function = { Get-SimAVR } },
    @{ Name = "get-msp430-gcc"; Function = { Get-MSP430-GCC } },
    @{ Name = "get-mspdebug"; Function = { Get-MSPDebug } },
    @{ Name = "get-avrora"; Function = { Get-Avrora } },
    @{ Name = "get-jlink"; Function = { Get-JLink } },
    @{ Name = "get-nRF-tools"; Function = { Get-nRF-Tools } },
    @{ Name = "get-open-stlink"; Function = { Get-OpenSTLink } }
)

foreach ($dl in $downloads) {
    Start-Job -ScriptBlock $dl.Function -Name $dl.Name
}

Get-Job | Wait-Job | ForEach-Object {
    if ($_.State -ne "Completed") {
        Write-Host "❌ Job '$($_.Name)' failed. Showing log:"
        Get-Content "$($_.Name).log"
        Exit 1
    }
}

# ================
# === Archive ===
# ================

$dependencies = @(
    "avrora",
    "simavr-1.6",
    "msp430-gcc-8.2.0.52_linux64",
    "mspdebug-0.25",
    "JLink_Linux_x86_64.deb",
    "nRF-Command-Line-Tools_10_2_1_Linux-amd64.deb",
    "stlink-1.5.1"
)

tar -czf dependencies.tar.gz $dependencies

Pop-Location

# ========================
# === Docker Build (Optional) ===
# ========================

# Uncomment if needed
# $version = & "$scriptsDir\version.sh"
# $dockerBuildOptions = @(
#     "--force-rm"
#     "--tag=felics-ae:$version"
#     "--file", "$dockerDir\Dockerfile"
#     "$dockerDir"
# )
# & "$scriptsDir\felics-archive" $resourcesDir
# docker build @dockerBuildOptions
