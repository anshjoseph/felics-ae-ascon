# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

$ErrorActionPreference = "Stop"

# Resolve current script directory
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$dockerDir = $scriptPath
$scriptsDir = Resolve-Path "$dockerDir\.."

# Define resources directory path
$resourcesDir = Join-Path $dockerDir ".resources"

# Create the .resources directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $resourcesDir | Out-Null

# Run the PowerShell dependencies script with resource dir as argument
Write-Host "▶ Running download-dependencies.ps1..."
& "$dockerDir\download-dependencies.ps1" -resourcesDir $resourcesDir

# Optional: Uncomment below when you want to tag and build Docker image
# -----------------------------------------------
# $version = & "$scriptsDir\version.sh"

# $dockerBuildOptions = @(
#     "--force-rm"
#     "--tag=felics-ae:$version"
#     "--file", "$dockerDir\Dockerfile"
#     "$dockerDir"
# )

# Archive dependencies before build
# & "$scriptsDir\felics-archive" $resourcesDir

# Build Docker image
# docker build @dockerBuildOptions
