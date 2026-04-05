# BitMono Sample Generation Script
#
# Prerequisites:
#   - Windows with .NET Framework 4.8 SDK
#   - .NET SDK 6.0+ (script will install .NET 10 SDK if needed)
#   - Git (for cloning BitMono)
#
# Usage:
#   .\generate.ps1 -TestAppPath "C:\path\to\TestApp.csproj" -OutputDir "C:\path\to\output" -ConfigDir "C:\path\to\configs"
#
# This script:
#   1. Ensures .NET 10 SDK is available (BitMono 0.39.0+ targets net10.0)
#   2. Clones and builds BitMono from source
#   3. Builds TestApp for net48
#   4. Generates all obfuscated variants using .json configs from ConfigDir

param(
    [Parameter(Mandatory=$true)]
    [string]$TestAppPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [Parameter(Mandatory=$true)]
    [string]$ConfigDir,

    [string]$BitMonoRepo = "https://github.com/sunnamed434/BitMono.git",
    [string]$BitMonoDir = "$env:TEMP\BitMono",
    [string]$GitRef = "0.39.0"
)

$ErrorActionPreference = "Stop"

# --- Step 0: Ensure .NET 10 SDK is installed (BitMono 0.39.0+ requires it) ---
$hasNet10 = dotnet --list-sdks 2>$null | Where-Object { $_ -match '^10\.' }
if (-not $hasNet10) {
    Write-Host "Installing .NET 10 SDK (required by BitMono $GitRef)..."
    $installScript = Join-Path $env:TEMP "dotnet-install.ps1"
    Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile $installScript
    & $installScript -Channel 10.0 -InstallDir "C:\Program Files\dotnet"
    # Verify
    $hasNet10 = dotnet --list-sdks 2>$null | Where-Object { $_ -match '^10\.' }
    if (-not $hasNet10) {
        throw ".NET 10 SDK installation failed"
    }
    Write-Host ".NET 10 SDK installed successfully."
} else {
    Write-Host ".NET 10 SDK already available."
}

# --- Step 1: Clone and build BitMono ---
if (-not (Test-Path $BitMonoDir)) {
    Write-Host "Cloning BitMono..."
    git clone $BitMonoRepo $BitMonoDir
}

Write-Host "Checking out BitMono $GitRef..."
Push-Location $BitMonoDir
git checkout $GitRef
Pop-Location

Write-Host "Building BitMono CLI..."
Push-Location $BitMonoDir
dotnet build src/BitMono.CLI/BitMono.CLI.csproj -c Release
Pop-Location

# Find the built CLI executable
$bitmonoCli = Get-ChildItem "$BitMonoDir\src\BitMono.CLI\bin\Release" -Recurse -Filter "BitMono.CLI.exe" | Select-Object -First 1
if (-not $bitmonoCli) {
    $bitmonoCli = Get-ChildItem "$BitMonoDir\src\BitMono.CLI\bin\Release" -Recurse -Filter "BitMono.CLI.dll" | Select-Object -First 1
}
if (-not $bitmonoCli) {
    throw "Could not find BitMono.CLI after build"
}
$bitmonoCliPath = $bitmonoCli.FullName
Write-Host "Using BitMono CLI: $bitmonoCliPath"

# --- Step 2: Build TestApp ---
Write-Host "Building TestApp..."
$testAppDir = Split-Path $TestAppPath
Push-Location $testAppDir
dotnet build (Split-Path $TestAppPath -Leaf) -c Release
Pop-Location

$inputExe = Join-Path $testAppDir "bin\Release\net48\TestApp.exe"
if (-not (Test-Path $inputExe)) {
    throw "TestApp build output not found at $inputExe"
}

# --- Step 3: Create output directory and copy original ---
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
Copy-Item $inputExe "$OutputDir\original.exe"

# --- Step 4: Generate variants ---
# Auto-discover all .json configs in ConfigDir; output name = config stem + .exe
$configs = Get-ChildItem $ConfigDir -Filter "*.json"
if ($configs.Count -eq 0) {
    throw "No .json config files found in $ConfigDir"
}

function Invoke-BitMono {
    param([string]$ConfigPath, [string]$OutputName)

    Write-Host "Generating $OutputName from $(Split-Path $ConfigPath -Leaf)..."

    # Create a temporary working directory for this variant
    $variantDir = Join-Path $env:TEMP "bitmono_work_$([System.IO.Path]::GetFileNameWithoutExtension($OutputName))"
    if (Test-Path $variantDir) { Remove-Item $variantDir -Recurse -Force }
    New-Item -ItemType Directory -Path $variantDir | Out-Null

    # Copy input file
    Copy-Item $inputExe "$variantDir\TestApp.exe"

    # Run BitMono CLI: --protections-file for config, -o for output dir
    $variantOut = "$variantDir\output"
    if ($bitmonoCliPath -match '\.dll$') {
        & dotnet $bitmonoCliPath --file "$variantDir\TestApp.exe" --protections-file $ConfigPath -o $variantOut
    } else {
        & $bitmonoCliPath --file "$variantDir\TestApp.exe" --protections-file $ConfigPath -o $variantOut
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "BitMono failed for $OutputName (exit code $LASTEXITCODE)"
        Remove-Item $variantDir -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    # Find the output file (BitMono names it TestApp_bitmono.exe or TestApp.exe in output/)
    $outputExe = Get-ChildItem "$variantOut" -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($outputExe) {
        Copy-Item $outputExe.FullName "$OutputDir\$OutputName"
        Write-Host "  -> $OutputName OK"
    } else {
        Write-Warning "Could not find BitMono output for $OutputName"
        Write-Host "  Files in work dir:"
        Get-ChildItem $variantDir -Recurse | ForEach-Object { Write-Host "    $($_.FullName)" }
    }

    Remove-Item $variantDir -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($config in $configs) {
    $outputName = $config.BaseName + ".exe"
    Invoke-BitMono -ConfigPath $config.FullName -OutputName $outputName
}

# --- Step 5: Verify ---
$count = (Get-ChildItem "$OutputDir\*.exe").Count
Write-Host "`nGenerated $count samples in $OutputDir"
Get-ChildItem "$OutputDir\*.exe" | Format-Table Name, Length
