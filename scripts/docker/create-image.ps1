# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

# Enable strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Get script directory
$dockerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptsDir = Split-Path -Parent $dockerDir

# Create resources directory
$resourcesDir = Join-Path $dockerDir ".resources"
New-Item -ItemType Directory -Force -Path $resourcesDir | Out-Null

# Download dependencies
$downloadScript = Join-Path $dockerDir "download-dependencies.ps1"
& $downloadScript $resourcesDir

# Get version
$versionScript = Join-Path $scriptsDir "version.ps1"
if (Test-Path $versionScript) {
    $version = & $versionScript
} else {
    # Fallback if version script doesn't exist
    $version = "latest"
}

# Build Docker image
$dockerFile = Join-Path $dockerDir "Dockerfile"
$tag = "felics-ae:$version"

Write-Host "Building Docker image with tag: $tag"

# Create felics archive
$felicsArchiveScript = Join-Path $scriptsDir "felics-archive.ps1"
if (Test-Path $felicsArchiveScript) {
    & $felicsArchiveScript $resourcesDir
}

# Build Docker image
$dockerArgs = @(
    "build"
    "--force-rm"
    "--tag=$tag"
    "--file=$dockerFile"
    $dockerDir
)

Write-Host "Running: docker $($dockerArgs -join ' ')"
& docker @dockerArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}