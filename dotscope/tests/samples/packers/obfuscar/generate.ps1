# Obfuscar Sample Generation Script
#
# Prerequisites:
#   - Windows with .NET Framework 4.8 SDK
#   - .NET SDK 6.0+ (for dotnet tool install)
#
# Usage:
#   .\generate.ps1 -TestAppPath "C:\path\to\TestApp.csproj" -OutputDir "C:\path\to\output" -ConfigDir "C:\path\to\configs"
#
# This script:
#   1. Installs Obfuscar as a global dotnet tool
#   2. Builds TestApp for net48
#   3. Generates all obfuscated variants using .xml configs from ConfigDir

param(
    [Parameter(Mandatory=$true)]
    [string]$TestAppPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [Parameter(Mandatory=$true)]
    [string]$ConfigDir,

    [string]$ToolVersion = "2.2.50"
)

$ErrorActionPreference = "Stop"

# --- Step 1: Install Obfuscar ---
Write-Host "Installing Obfuscar $ToolVersion..."
dotnet tool install -g Obfuscar.GlobalTool --version $ToolVersion 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Obfuscar already installed, updating to $ToolVersion..."
    dotnet tool update -g Obfuscar.GlobalTool --version $ToolVersion
}

# Verify obfuscar.console is available
$obfuscarPath = Get-Command "obfuscar.console" -ErrorAction SilentlyContinue
if (-not $obfuscarPath) {
    # Try the typical global tools path
    $toolsPath = Join-Path $env:USERPROFILE ".dotnet\tools"
    $env:PATH = "$toolsPath;$env:PATH"
    $obfuscarPath = Get-Command "obfuscar.console" -ErrorAction SilentlyContinue
}
if (-not $obfuscarPath) {
    throw "obfuscar.console not found. Ensure Obfuscar.GlobalTool is installed."
}
Write-Host "Using Obfuscar: $($obfuscarPath.Source)"

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

# Create a temporary work directory (Obfuscar configs reference InPath relative paths)
$workDir = Join-Path $env:TEMP "obfuscar_work"
if (Test-Path $workDir) { Remove-Item $workDir -Recurse -Force }
New-Item -ItemType Directory -Path $workDir | Out-Null

# Copy TestApp.exe to work directory (configs reference $(InPath)/TestApp.exe)
Copy-Item $inputExe "$workDir\TestApp.exe"

# Copy original.exe to output
Copy-Item $inputExe "$OutputDir\original.exe"

# --- Step 4: Generate variants ---
# Auto-discover all .xml configs in ConfigDir
$configs = Get-ChildItem $ConfigDir -Filter "*.xml"
if ($configs.Count -eq 0) {
    throw "No .xml config files found in $ConfigDir"
}

# Parse OutPath from each config to know where the output lands
function Get-OutPath {
    param([string]$ConfigPath)
    $content = Get-Content $ConfigPath -Raw
    if ($content -match 'name="OutPath"\s+value="([^"]+)"') {
        return $Matches[1]
    }
    return "./output"
}

function Invoke-Obfuscar {
    param([string]$ConfigPath, [string]$OutputName)

    Write-Host "Generating $OutputName from $(Split-Path $ConfigPath -Leaf)..."

    # Read the config and adjust paths to use the work directory
    $configContent = Get-Content $ConfigPath -Raw
    $configContent = $configContent -replace 'value="\."', "value=`"$($workDir -replace '\\', '\\')`""
    $configContent = $configContent -replace "value=`"\./", "value=`"$($workDir -replace '\\', '\\')/"

    # Write adjusted config to work dir
    $workConfig = "$workDir\config.xml"
    Set-Content $workConfig $configContent

    # Determine output subdirectory from config
    $outSubDir = Get-OutPath $ConfigPath
    # Normalize: strip leading ./ and replace forward slashes
    $outSubDir = $outSubDir -replace '^\.\/', '' -replace '^\.\\'  , ''
    $outputSubPath = Join-Path $workDir $outSubDir

    # Clean output subdirectory
    if (Test-Path $outputSubPath) { Remove-Item $outputSubPath -Recurse -Force }

    # Run Obfuscar
    & obfuscar.console $workConfig

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Obfuscar failed for $OutputName (exit code $LASTEXITCODE)"
        return
    }

    # Find output
    $protectedExe = Join-Path $outputSubPath "TestApp.exe"
    if (Test-Path $protectedExe) {
        Copy-Item $protectedExe "$OutputDir\$OutputName"
        Write-Host "  -> $OutputName OK"
    } else {
        Write-Warning "Obfuscar output not found at $protectedExe"
        Write-Host "  Files in output dir:"
        if (Test-Path $outputSubPath) {
            Get-ChildItem $outputSubPath | ForEach-Object { Write-Host "    $($_.Name)" }
        }
    }
}

foreach ($config in $configs) {
    $outputName = $config.BaseName + ".exe"
    Invoke-Obfuscar -ConfigPath $config.FullName -OutputName $outputName
}

# --- Step 5: Cleanup and verify ---
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue

$count = (Get-ChildItem "$OutputDir\*.exe").Count
Write-Host "`nGenerated $count samples in $OutputDir"
Get-ChildItem "$OutputDir\*.exe" | Format-Table Name, Length
