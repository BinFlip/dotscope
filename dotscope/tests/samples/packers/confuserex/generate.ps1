# ConfuserEx Sample Generation Script
#
# Prerequisites:
#   - Windows with .NET Framework 4.8 SDK
#   - .NET SDK 6.0+ (for building ConfuserEx from source)
#   - Git (for cloning ConfuserEx)
#
# Usage:
#   .\generate.ps1 -TestAppPath "C:\path\to\TestApp.csproj" -OutputDir "C:\path\to\output" -ConfigDir "C:\path\to\configs"
#
# This script:
#   1. Clones and builds ConfuserEx from source
#   2. Builds TestApp for net48
#   3. Generates all obfuscated variants using .crproj configs from ConfigDir

param(
    [Parameter(Mandatory=$true)]
    [string]$TestAppPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [Parameter(Mandatory=$true)]
    [string]$ConfigDir,

    [string]$ConfuserExRepo = "https://github.com/mkaring/ConfuserEx.git",
    [string]$ConfuserExDir = "$env:TEMP\ConfuserEx",
    [string]$GitRef = "v1.6.0"
)

$ErrorActionPreference = "Stop"

# --- Step 1: Clone and build ConfuserEx ---
if (-not (Test-Path $ConfuserExDir)) {
    Write-Host "Cloning ConfuserEx..."
    git clone $ConfuserExRepo $ConfuserExDir
}

Write-Host "Checking out ConfuserEx $GitRef..."
Push-Location $ConfuserExDir
git checkout $GitRef
Pop-Location

Write-Host "Building ConfuserEx..."
Push-Location $ConfuserExDir
dotnet build Confuser.CLI/Confuser.CLI.csproj -c Release
Pop-Location

# Find the built CLI executable
$confuserCli = Get-ChildItem "$ConfuserExDir\Confuser.CLI\bin\Release" -Recurse -Filter "Confuser.CLI.exe" | Select-Object -First 1
if (-not $confuserCli) {
    $confuserCli = Get-ChildItem "$ConfuserExDir\Confuser.CLI\bin\Release" -Recurse -Filter "Confuser.CLI.dll" | Select-Object -First 1
}
if (-not $confuserCli) {
    throw "Could not find Confuser.CLI after build"
}
$confuserCliPath = $confuserCli.FullName
Write-Host "Using ConfuserEx CLI: $confuserCliPath"

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

# --- Step 3: Create output directory and set up work area ---
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Create a temporary work directory for ConfuserEx (it needs the input and config in the same dir)
$workDir = Join-Path $env:TEMP "confuserex_work"
if (Test-Path $workDir) { Remove-Item $workDir -Recurse -Force }
New-Item -ItemType Directory -Path $workDir | Out-Null

# Copy TestApp.exe to work directory
Copy-Item $inputExe "$workDir\TestApp.exe"

# Copy original.exe to output
Copy-Item $inputExe "$OutputDir\original.exe"

# --- Step 4: Generate variants ---
# Auto-discover all .crproj configs in ConfigDir; output name = config stem + .exe
$configs = Get-ChildItem $ConfigDir -Filter "*.crproj"
if ($configs.Count -eq 0) {
    throw "No .crproj files found in $ConfigDir"
}

function Invoke-ConfuserEx {
    param([string]$CrprojPath, [string]$OutputName)

    Write-Host "Generating $OutputName from $(Split-Path $CrprojPath -Leaf)..."

    # Copy .crproj to work directory
    Copy-Item $CrprojPath "$workDir\config.crproj"

    # Clean protected output directory
    $protectedDir = "$workDir\protected"
    if (Test-Path $protectedDir) { Remove-Item $protectedDir -Recurse -Force }

    # Run ConfuserEx
    if ($confuserCliPath -match '\.dll$') {
        & dotnet $confuserCliPath "$workDir\config.crproj"
    } else {
        & $confuserCliPath "$workDir\config.crproj"
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "ConfuserEx failed for $OutputName (exit code $LASTEXITCODE)"
        return
    }

    # Copy protected output to final location
    $protectedExe = "$protectedDir\TestApp.exe"
    if (Test-Path $protectedExe) {
        Copy-Item $protectedExe "$OutputDir\$OutputName"
        Write-Host "  -> $OutputName OK"
    } else {
        Write-Warning "Protected output not found at $protectedExe"
    }
}

foreach ($config in $configs) {
    $outputName = $config.BaseName + ".exe"
    Invoke-ConfuserEx -CrprojPath $config.FullName -OutputName $outputName
}

# --- Step 5: Cleanup and verify ---
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue

$count = (Get-ChildItem "$OutputDir\*.exe").Count
Write-Host "`nGenerated $count samples in $OutputDir"
Get-ChildItem "$OutputDir\*.exe" | Format-Table Name, Length
