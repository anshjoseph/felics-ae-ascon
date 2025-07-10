# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

param(
    [Parameter(Mandatory=$true)]
    [string]$ResourcesDir
)

# Enable strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Get script directory
$dockerDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Function to run commands in background with logging
function Run-BackgroundTask {
    param(
        [string]$TaskName,
        [scriptblock]$ScriptBlock
    )
    
    $logFile = Join-Path $ResourcesDir "$TaskName.log"
    
    Start-Job -Name $TaskName -ScriptBlock {
        param($logFile, $scriptBlock, $resourcesDir, $dockerDir)
        
        # Redirect output to log file
        $transcript = Start-Transcript -Path $logFile -Append
        
        try {
            Write-Host "$(Get-Date): Starting $using:TaskName"
            & $scriptBlock
            Write-Host "$(Get-Date): Completed $using:TaskName"
        }
        catch {
            Write-Error "$(Get-Date): Error in $using:TaskName - $_"
            throw
        }
        finally {
            Stop-Transcript
        }
    } -ArgumentList $logFile, $ScriptBlock, $ResourcesDir, $dockerDir
}

# Function to download simavr
function Get-Simavr {
    Set-Location $ResourcesDir
    
    $url = "https://github.com/buserror/simavr/archive/v1.6.tar.gz"
    $fileName = "simavr-v1.6.tar.gz"
    
    Write-Host "Downloading simavr..."
    Invoke-WebRequest -Uri $url -OutFile $fileName
    
    # Extract tar.gz (requires tar command available in Windows 10+)
    if (Get-Command tar -ErrorAction SilentlyContinue) {
        tar -xf $fileName
    } else {
        # Fallback: Use .NET compression if tar is not available
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($fileName, ".")
    }
    
    # Apply patch if it exists
    $patchFile = Join-Path $dockerDir "simavr.patch"
    if (Test-Path $patchFile) {
        Set-Location "simavr-1.6"
        # Note: patch command may not be available on Windows
        # You might need to install Git for Windows or use WSL
        if (Get-Command patch -ErrorAction SilentlyContinue) {
            Get-Content $patchFile | patch -p1
        } else {
            Write-Warning "patch command not found. Manual patching may be required."
        }
        Set-Location ..
    }
}

# Function to download MSP430 GCC
function Get-Msp430Gcc {
    Set-Location $ResourcesDir
    
    Write-Host "Downloading MSP430 GCC..."
    $gccUrl = "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/8_2_0_0/exports/msp430-gcc-8.2.0.52_linux64.tar.bz2"
    $supportUrl = "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/8_2_0_0/exports/msp430-gcc-support-files-1.207.zip"
    
    Invoke-WebRequest -Uri $gccUrl -OutFile "msp430-gcc-8.2.0.52_linux64.tar.bz2"
    Invoke-WebRequest -Uri $supportUrl -OutFile "msp430-gcc-support-files-1.207.zip"
    
    # Extract files
    if (Get-Command tar -ErrorAction SilentlyContinue) {
        tar -xf "msp430-gcc-8.2.0.52_linux64.tar.bz2"
    }
    
    Expand-Archive -Path "msp430-gcc-support-files-1.207.zip" -DestinationPath "."
    
    # Copy support files
    if (Test-Path "msp430-gcc-8.2.0.52_linux64") {
        Copy-Item -Recurse "msp430-gcc-support-files" "msp430-gcc-8.2.0.52_linux64/support-files"
    }
}

# Function to download mspdebug
function Get-MspDebug {
    Set-Location $ResourcesDir
    
    Write-Host "Downloading mspdebug..."
    $url = "https://github.com/dlbeer/mspdebug/archive/v0.25.tar.gz"
    Invoke-WebRequest -Uri $url -OutFile "mspdebug.tar.gz"
    
    if (Get-Command tar -ErrorAction SilentlyContinue) {
        tar -xf "mspdebug.tar.gz"
    }
}

# Function to download Avrora (Note: CVS might not work on Windows)
function Get-Avrora {
    Set-Location $ResourcesDir
    
    Write-Host "Downloading Avrora..."
    # CVS checkout might not work on Windows, so we'll skip this or use alternative
    Write-Warning "CVS checkout for Avrora may not work on Windows. Consider manual download."
    
    # Download the patch file
    $patchUrl = "https://www.cryptolux.org/images/4/4e/FELICS_Avrora_patch.txt"
    Invoke-WebRequest -Uri $patchUrl -OutFile "FELICS_Avrora_patch.txt"
    
    # Create a placeholder directory
    New-Item -ItemType Directory -Name "avrora" -Force | Out-Null
}

# Function to download J-Link
function Get-JLink {
    Set-Location $ResourcesDir
    
    Write-Host "Downloading J-Link..."
    $url = "https://www.segger.com/downloads/jlink/JLink_Linux_x86_64.deb"
    
    # Create form data for POST request
    $formData = @{
        'accept_license_agreement' = 'accepted'
        'non_emb_ctr' = 'confirmed'
        'submit' = 'Download+software'
    }
    
    try {
        Invoke-WebRequest -Uri $url -Method Post -Body $formData -OutFile "JLink_Linux_x86_64.deb"
    }
    catch {
        Write-Warning "Failed to download J-Link automatically. Manual download may be required."
    }
}

# Function to download nRF tools
function Get-NrfTools {
    Set-Location $ResourcesDir
    
    Write-Host "Downloading nRF tools..."
    $url = "https://www.nordicsemi.com/-/media/Software-and-other-downloads/Desktop-software/nRF-command-line-tools/sw/Versions-10-x-x/nRFCommandLineTools1021Linuxamd64tar.gz"
    
    Invoke-WebRequest -Uri $url -OutFile "nRFCommandLineTools1021Linuxamd64tar.gz"
    
    if (Get-Command tar -ErrorAction SilentlyContinue) {
        tar -xf "nRFCommandLineTools1021Linuxamd64tar.gz" "./nRF-Command-Line-Tools_10_2_1_Linux-amd64.deb"
    }
}

# Function to download open-stlink
function Get-OpenStlink {
    Set-Location $ResourcesDir
    
    Write-Host "Downloading open-stlink..."
    $url = "https://github.com/texane/stlink/archive/v1.5.1.tar.gz"
    
    Invoke-WebRequest -Uri $url -OutFile "v1.5.1.tar.gz"
    
    if (Get-Command tar -ErrorAction SilentlyContinue) {
        tar -xf "v1.5.1.tar.gz"
    }
}

# Main execution
Write-Host "Starting dependency downloads..."

# Create resources directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $ResourcesDir | Out-Null

# Start background jobs for each download
$jobs = @()
$jobs += Run-BackgroundTask "simavr" { Get-Simavr }
$jobs += Run-BackgroundTask "msp430-gcc" { Get-Msp430Gcc }
$jobs += Run-BackgroundTask "mspdebug" { Get-MspDebug }
$jobs += Run-BackgroundTask "avrora" { Get-Avrora }
$jobs += Run-BackgroundTask "jlink" { Get-JLink }
$jobs += Run-BackgroundTask "nrf-tools" { Get-NrfTools }
$jobs += Run-BackgroundTask "open-stlink" { Get-OpenStlink }

# Wait for all jobs to complete
Write-Host "Waiting for downloads to complete..."
$jobs | Wait-Job | Out-Null

# Check for any failed jobs
$failedJobs = $jobs | Where-Object { $_.State -eq "Failed" }
if ($failedJobs) {
    Write-Host "Failed jobs:"
    $failedJobs | ForEach-Object {
        Write-Host "  $($_.Name): $($_.JobStateInfo.Reason)"
        Receive-Job $_ -ErrorAction SilentlyContinue
    }
    
    # Show log files
    Get-ChildItem -Path $ResourcesDir -Filter "*.log" | ForEach-Object {
        Write-Host "`nLog file: $($_.Name)"
        Get-Content $_.FullName | Select-Object -Last 20
    }
    
    Write-Error "Some downloads failed. Check the log files for details."
}

# Clean up jobs
$jobs | Remove-Job -Force

# Create dependencies archive
Set-Location $ResourcesDir

$dependencies = @(
    "avrora",
    "simavr-1.6",
    "msp430-gcc-8.2.0.52_linux64",
    "mspdebug-0.25",
    "JLink_Linux_x86_64.deb",
    "nRF-Command-Line-Tools_10_2_1_Linux-amd64.deb",
    "stlink-1.5.1"
)

# Filter to only include directories/files that actually exist
$existingDeps = $dependencies | Where-Object { Test-Path $_ }

if ($existingDeps.Count -gt 0) {
    Write-Host "Creating dependencies archive..."
    
    if (Get-Command tar -ErrorAction SilentlyContinue) {
        # Use tar if available (Windows 10+)
        tar -czf "dependencies.tar.gz" @existingDeps
    } else {
        # Fallback: Create a zip file instead
        Write-Warning "tar command not available. Creating dependencies.zip instead of dependencies.tar.gz"
        Compress-Archive -Path $existingDeps -DestinationPath "dependencies.zip" -Force
    }
    
    Write-Host "Dependencies archive created successfully."
} else {
    Write-Warning "No dependencies were successfully downloaded."
}

Write-Host "Dependency download process completed."