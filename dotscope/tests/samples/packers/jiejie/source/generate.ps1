# JIEJIE.NET Sample Generation Script
#
# Prerequisites:
#   - Windows with .NET Framework 4.8 SDK (ildasm.exe + ilasm.exe)
#   - .NET SDK 7.0+ (for building JIEJIE.NET from source)
#   - Git (for cloning JIEJIE.NET)
#
# Usage:
#   .\generate.ps1 -TestAppPath "C:\path\to\TestApp.csproj" -OutputDir "C:\path\to\output"
#
# This script:
#   1. Clones and builds JIEJIE.NET from source (patched for headless operation)
#   2. Builds TestApp for net48
#   3. Generates all obfuscated variants

param(
    [Parameter(Mandatory=$true)]
    [string]$TestAppPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [string]$JiejieRepo = "https://github.com/dcsoft-yyf/JIEJIE.NET.git",
    [string]$JiejieDir = "$env:TEMP\JIEJIE.NET",
    [string]$GitRef = "d28aa56f68665c461fa919e3a1c7cec1a19706ad"  # 2026-01-05 latest master
)

$ErrorActionPreference = "Stop"

# --- Step 1: Clone and patch JIEJIE.NET ---
if (-not (Test-Path $JiejieDir)) {
    Write-Host "Cloning JIEJIE.NET..."
    git clone $JiejieRepo $JiejieDir
}

Write-Host "Checking out JIEJIE.NET $GitRef..."
Push-Location $JiejieDir
git checkout $GitRef
Pop-Location

$engineDir = "$JiejieDir\source\JIEJIEEngine"
$myConsole = "$engineDir\MyConsole.cs"
$engineCs  = "$engineDir\DCJieJieNetEngine.cs"

# Patch MyConsole.cs: wrap all Console property accesses in try/catch for headless operation
Write-Host "Patching MyConsole.cs for headless operation..."
$sedExe = "C:\Program Files\Git\usr\bin\sed.exe"
& $sedExe -i 's/return Console\.CursorLeft;/try { return Console.CursorLeft; } catch { return 0; }/' $myConsole
& $sedExe -i 's/Console\.CursorLeft = value;/try { Console.CursorLeft = value; } catch { }/' $myConsole
& $sedExe -i 's/return Console\.CursorTop;/try { return Console.CursorTop; } catch { return 0; }/' $myConsole
& $sedExe -i 's/Console\.CursorTop = value;/try { Console.CursorTop = value; } catch { }/' $myConsole
& $sedExe -i 's/return Console\.Title;/try { return Console.Title; } catch { return string.Empty; }/' $myConsole
& $sedExe -i 's/Console\.Title = value;/try { Console.Title = value; } catch { }/' $myConsole
& $sedExe -i 's/return Console\.BackgroundColor;/try { return Console.BackgroundColor; } catch { return ConsoleColor.Black; }/' $myConsole
& $sedExe -i 's/Console\.BackgroundColor = value;/try { Console.BackgroundColor = value; } catch { }/' $myConsole
& $sedExe -i 's/return Console\.ForegroundColor;/try { return Console.ForegroundColor; } catch { return ConsoleColor.Gray; }/' $myConsole
& $sedExe -i 's/Console\.ForegroundColor = value;/try { Console.ForegroundColor = value; } catch { }/' $myConsole
& $sedExe -i 's/Console\.ResetColor();/try { Console.ResetColor(); } catch { }/' $myConsole
& $sedExe -i 's/return Console\.KeyAvailable;/try { return Console.KeyAvailable; } catch { return false; }/' $myConsole

# Patch DCJieJieNetEngine.cs: allow mscorlib assemblies in .NET Core mode
Write-Host "Patching DCJieJieNetEngine.cs for mscorlib support..."
$content = [System.IO.File]::ReadAllText($engineCs)
$content = $content -replace 'if\(\s*asmName\s*==\s*"mscorlib"\)', 'if( false /*mscorlib patch*/)'
[System.IO.File]::WriteAllText($engineCs, $content)

# Build JIEJIE.NET
Write-Host "Building JIEJIE.NET..."
Push-Location "$JiejieDir\source"
dotnet build JIEJIENETForCore.Console.csproj -c Release
Pop-Location

$jiejieExe = "$JiejieDir\source\bin_JIEJIENETForCore.Console\netcoreapp3.1\JIEJIENETForCore.Console.dll"

# --- Step 2: Build TestApp ---
Write-Host "Building TestApp..."
$testAppDir = Split-Path $TestAppPath
Push-Location $testAppDir
dotnet build (Split-Path $TestAppPath -Leaf) -c Release
Pop-Location

$inputExe = Join-Path $testAppDir "bin\Release\net48\TestApp.exe"

# --- Step 3: Create output directory and copy original ---
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
Copy-Item $inputExe "$OutputDir\original.exe"

# --- Step 4: Generate variants ---
function Invoke-Jiejie {
    param([string]$OutputName, [string]$Switches)
    Write-Host "Generating $OutputName..."
    $args = @(
        "--roll-forward", "LatestMajor",
        $jiejieExe,
        $inputExe,
        "output=$OutputDir\$OutputName"
    )
    if ($Switches) {
        $args += "switch=$Switches"
    }
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to generate $OutputName"
    }
}

# All defaults (CF+Strings+Resources+Rename+MemberOrder+RemoveMember)
Invoke-Jiejie "jiejie_default.exe"

# Strings only
Invoke-Jiejie "jiejie_strings_only.exe" "+strings,-controlflow,-rename,-resources,-memberorder,-removemember"

# High-strength strings
Invoke-Jiejie "jiejie_highstrings.exe" "+strings,+hightstrings,-controlflow,-rename,-resources,-memberorder,-removemember"

# Control flow only
Invoke-Jiejie "jiejie_controlflow_only.exe" "+controlflow,-strings,-rename,-resources,-removemember,-memberorder"

# Control flow, no rename (preserves field names for Int32ValueContainer verification)
Invoke-Jiejie "jiejie_controlflow_no_rename.exe" "+controlflow,-strings,-rename,-resources,-removemember,-memberorder"

# Rename only
Invoke-Jiejie "jiejie_rename_only.exe" "+rename,-controlflow,-strings,-resources,-memberorder,-removemember"

# Resources only
Invoke-Jiejie "jiejie_resources_only.exe" "+resources,-controlflow,-strings,-rename,-memberorder,-removemember"

# All except rename
Invoke-Jiejie "jiejie_no_rename.exe" "-rename"

# Maximum protection (all + high-strength strings)
# Note: +allocationcallstack causes a null reference in the .NET Core build, omitted
Invoke-Jiejie "jiejie_maximum.exe" "+hightstrings"

# --- Step 5: Verify ---
$count = (Get-ChildItem "$OutputDir\*.exe").Count
Write-Host "`nGenerated $count samples in $OutputDir"
Get-ChildItem "$OutputDir\*.exe" | Format-Table Name, Length
