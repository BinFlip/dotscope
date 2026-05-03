# .NET Reactor Sample Generation Script
#
# Prerequisites:
#   - Windows with .NET Framework 4.8 SDK
#   - .NET Reactor installed via Chocolatey: choco install dotnetreactor
#
# Usage:
#   .\generate.ps1 -TestAppPath "C:\path\to\TestApp.csproj" -OutputDir "C:\path\to\output"
#
# This script:
#   1. Verifies .NET Reactor is installed (via Chocolatey or manual install)
#   2. Builds TestApp for net48
#   3. Generates obfuscated variants with different protection combinations
#
# .NET Reactor CLI reference:
#   https://www.eziriz.com/help/command_line_parameters/
#
# Trial note:
#   The trial is indefinite (nag dialog) with 14-day output execution expiry.
#   Output expiry is irrelevant for our use case (structural analysis, not execution).

param(
    [Parameter(Mandatory=$true)]
    [string]$TestAppPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [string]$ToolVersion = "7.5.0"
)

$ErrorActionPreference = "Stop"

# --- Step 1: Locate .NET Reactor ---
Write-Host "Locating .NET Reactor..."

# Try environment variable first (set by Chocolatey installer)
$reactorExe = $null
if ($env:DOTNET_REACTOR_CMD) {
    $reactorExe = $env:DOTNET_REACTOR_CMD
}

# Try common Chocolatey install path
if (-not $reactorExe -or -not (Test-Path $reactorExe)) {
    $candidatePaths = @(
        "${env:ProgramFiles(x86)}\Eziriz\.NET Reactor\dotNET_Reactor.Console.exe",
        "$env:ProgramFiles\Eziriz\.NET Reactor\dotNET_Reactor.Console.exe",
        "${env:ProgramFiles(x86)}\Eziriz\.NET Reactor\dotNET_Reactor.Console.exe"
    )
    foreach ($path in $candidatePaths) {
        if (Test-Path $path) {
            $reactorExe = $path
            break
        }
    }
}

# Try PATH
if (-not $reactorExe -or -not (Test-Path $reactorExe)) {
    $found = Get-Command "dotNET_Reactor.Console" -ErrorAction SilentlyContinue
    if ($found) {
        $reactorExe = $found.Source
    }
}

if (-not $reactorExe -or -not (Test-Path $reactorExe)) {
    throw @"
.NET Reactor not found. Install via Chocolatey:
  choco install dotnetreactor
Or set DOTNET_REACTOR_CMD to the console exe path.
"@
}

# Print version info
Write-Host "Using .NET Reactor: $reactorExe"
& $reactorExe -q 2>$null  # Quick invocation to verify it works

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
function Invoke-Reactor {
    param(
        [string]$OutputName,
        [string]$Description,
        [hashtable]$Flags
    )

    Write-Host "Generating $OutputName ($Description)..."
    $targetFile = "$OutputDir\$OutputName"

    # Build argument list: start with required args
    $args = @(
        "-file", $inputExe,
        "-targetfile", $targetFile,
        "-q"
    )

    # Add protection flags
    foreach ($key in $Flags.Keys) {
        $args += "-$key"
        $args += "$($Flags[$key])"
    }

    & $reactorExe @args

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to generate $OutputName (exit code $LASTEXITCODE)"
        return
    }

    if (Test-Path $targetFile) {
        $size = (Get-Item $targetFile).Length
        Write-Host "  -> $OutputName OK ($size bytes)"
    } else {
        Write-Warning "Output not found at $targetFile"
    }
}

# Base flags: all protections OFF (explicit baseline)
$allOff = @{
    necrobit                 = "0"
    stringencryption         = "0"
    control_flow_obfuscation = "0"
    antitamp                 = "0"
    resourceencryption       = "0"
    obfuscation              = "0"
    obfuscate_public_types   = "0"
    suppressildasm           = "0"
    antistrong               = "0"
    nativeexe                = "0"
    prejit                   = "0"
    compression              = "0"
}

function MergeFlags {
    param([hashtable]$Base, [hashtable]$Override)
    $result = @{}
    foreach ($key in $Base.Keys) { $result[$key] = $Base[$key] }
    foreach ($key in $Override.Keys) { $result[$key] = $Override[$key] }
    return $result
}

# --- Individual protections (isolated) ---

Invoke-Reactor "reactor_necrobit.exe" "NecroBit only (method body encryption)" `
    (MergeFlags $allOff @{ necrobit = "1" })

Invoke-Reactor "reactor_strings.exe" "String encryption only" `
    (MergeFlags $allOff @{ stringencryption = "1" })

Invoke-Reactor "reactor_controlflow.exe" "Control flow obfuscation (level 5)" `
    (MergeFlags $allOff @{ control_flow_obfuscation = "1"; flow_level = "5" })

Invoke-Reactor "reactor_controlflow_max.exe" "Control flow obfuscation (level 9)" `
    (MergeFlags $allOff @{ control_flow_obfuscation = "1"; flow_level = "9" })

Invoke-Reactor "reactor_resources.exe" "Resource encryption only" `
    (MergeFlags $allOff @{ resourceencryption = "1" })

Invoke-Reactor "reactor_antitamp.exe" "Anti-tamper only" `
    (MergeFlags $allOff @{ antitamp = "1" })

Invoke-Reactor "reactor_obfuscation.exe" "Symbol renaming (non-public)" `
    (MergeFlags $allOff @{ obfuscation = "1" })

Invoke-Reactor "reactor_suppressildasm.exe" "SuppressIldasm only" `
    (MergeFlags $allOff @{ suppressildasm = "1" })

Invoke-Reactor "reactor_antistrong.exe" "Anti strong name removal only" `
    (MergeFlags $allOff @{ antistrong = "1" })

Invoke-Reactor "reactor_prejit.exe" "Pre-JIT native code conversion" `
    (MergeFlags $allOff @{ prejit = "1" })

Invoke-Reactor "reactor_compression.exe" "Output compression only" `
    (MergeFlags $allOff @{ compression = "1" })

# --- Combinations (realistic protection profiles) ---

Invoke-Reactor "reactor_necrobit_strings.exe" "NecroBit + string encryption" `
    (MergeFlags $allOff @{
        necrobit         = "1"
        stringencryption = "1"
    })

Invoke-Reactor "reactor_necrobit_strings_cff.exe" "NecroBit + strings + control flow (level 5)" `
    (MergeFlags $allOff @{
        necrobit                 = "1"
        stringencryption         = "1"
        control_flow_obfuscation = "1"
        flow_level               = "5"
    })

Invoke-Reactor "reactor_full.exe" "Full protection (all enabled)" `
    @{
        necrobit                 = "1"
        necrobit_comp            = "1"
        stringencryption         = "1"
        control_flow_obfuscation = "1"
        flow_level               = "9"
        antitamp                 = "1"
        resourceencryption       = "1"
        resourcecompression      = "normal"
        obfuscation              = "1"
        obfuscate_public_types   = "1"
        suppressildasm           = "1"
        antistrong               = "1"
        compression              = "1"
    }

Invoke-Reactor "reactor_nativeexe.exe" "Native x86 EXE stub" `
    (MergeFlags $allOff @{
        necrobit  = "1"
        nativeexe = "1"
    })

# --- Step 5: VM Virtualization variants ---
# Code virtualization requires:
#   1. <Virtualization>true</Virtualization> in .nrproj (project-level, no CLI flag)
#   2. [Obfuscation(Feature="Virtualization", Exclude=false)] on target methods
# We patch TestApp source with attributes, rebuild, and use .nrproj files.

Write-Host "`nBuilding VM virtualization variants..."
$vmWorkDir = Join-Path $env:TEMP "reactor_vm_work"
if (Test-Path $vmWorkDir) { Remove-Item $vmWorkDir -Recurse -Force }
New-Item -ItemType Directory -Path "$vmWorkDir\Resources" | Out-Null

# Copy TestApp source to work directory
Copy-Item (Join-Path $testAppDir "Program.cs") "$vmWorkDir\Program.cs"
Copy-Item (Join-Path $testAppDir "TestApp.csproj") "$vmWorkDir\TestApp.csproj"
$resourcesDir = Join-Path $testAppDir "Resources"
if (Test-Path $resourcesDir) {
    Get-ChildItem $resourcesDir | ForEach-Object { Copy-Item $_.FullName "$vmWorkDir\Resources\" }
}

# Patch Program.cs: add [Obfuscation(Feature="Virtualization")] to key methods.
$vmSource = [System.IO.File]::ReadAllText("$vmWorkDir\Program.cs")
if ($vmSource -notmatch 'using System\.Reflection;') {
    $vmSource = "using System.Reflection;`n" + $vmSource
}
$vmAttr = '[Obfuscation(Feature = "Virtualization", Exclude = false)]'
$vmSource = $vmSource -replace '(\s+)(public int Add\()',              "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public int Fibonacci\()',        "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public int Factorial\()',        "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public void DemoSwitch\()',      "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public void DemoIfElse\()',      "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public string GetApiKey\()',     "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public string XorEncrypt\()',    "`$1$vmAttr`n`$1`$2"
$vmSource = $vmSource -replace '(\s+)(public string DecryptSecret\()', "`$1$vmAttr`n`$1`$2"
[System.IO.File]::WriteAllText("$vmWorkDir\Program.cs", $vmSource)

Write-Host "Building TestApp with VM attributes..."
Push-Location $vmWorkDir
dotnet build TestApp.csproj -c Release
Pop-Location

$vmInputExe = Join-Path $vmWorkDir "bin\Release\net48\TestApp.exe"
if (-not (Test-Path $vmInputExe)) {
    Write-Warning "VM variant build failed, skipping virtualization samples"
} else {
    # Helper to generate .nrproj and run .NET Reactor with virtualization enabled
    function Invoke-ReactorWithProject {
        param(
            [string]$OutputName,
            [string]$Description,
            [string]$InputFile,
            [string]$ProjectXml
        )
        Write-Host "Generating $OutputName ($Description)..."
        $targetFile = "$OutputDir\$OutputName"
        $projContent = $ProjectXml -replace 'MAIN_ASSEMBLY_PLACEHOLDER', $InputFile `
                                   -replace 'TARGET_FILE_PLACEHOLDER', $targetFile
        $projPath = "$vmWorkDir\$OutputName.nrproj"
        Set-Content $projPath $projContent

        & $reactorExe -project $projPath -q
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to generate $OutputName (exit code $LASTEXITCODE)"
        } elseif (Test-Path $targetFile) {
            $size = (Get-Item $targetFile).Length
            Write-Host "  -> $OutputName OK ($size bytes)"
        } else {
            Write-Warning "Output not found at $targetFile"
        }
    }

    # VM only: virtualization enabled, all other protections off
    $vmOnlyXml = @"
<Reactor_Project ProjectFormat="2">
  <Main_Assembly>MAIN_ASSEMBLY_PLACEHOLDER</Main_Assembly>
  <General_Settings>
    <Show_Loading_Screen>false</Show_Loading_Screen>
    <Target_File>TARGET_FILE_PLACEHOLDER</Target_File>
  </General_Settings>
  <Protection_Settings>
    <Virtualization>true</Virtualization>
    <NecroBit>false</NecroBit>
    <String_Encryption>false</String_Encryption>
    <Control_Flow_Obfuscation>false</Control_Flow_Obfuscation>
    <Anti_Tampering>false</Anti_Tampering>
    <Anti_ILDASM>false</Anti_ILDASM>
    <Obfuscation>false</Obfuscation>
    <Resource_Encryption_And_Compression>false</Resource_Encryption_And_Compression>
    <Strong_Name_Removal_Protection>false</Strong_Name_Removal_Protection>
    <Native_EXE_File>false</Native_EXE_File>
    <Pre-JIT_Methods>false</Pre-JIT_Methods>
    <Application_Compression>false</Application_Compression>
    <Hide_Method_Calls>false</Hide_Method_Calls>
  </Protection_Settings>
</Reactor_Project>
"@
    Invoke-ReactorWithProject "reactor_virtualization.exe" `
        "Code virtualization only (VM on 8 attributed methods)" `
        $vmInputExe $vmOnlyXml

    # VM + full: virtualization plus all standard protections
    $vmFullXml = @"
<Reactor_Project ProjectFormat="2">
  <Main_Assembly>MAIN_ASSEMBLY_PLACEHOLDER</Main_Assembly>
  <General_Settings>
    <Show_Loading_Screen>false</Show_Loading_Screen>
    <Target_File>TARGET_FILE_PLACEHOLDER</Target_File>
  </General_Settings>
  <Protection_Settings>
    <Virtualization>true</Virtualization>
    <NecroBit>true</NecroBit>
    <NecroBit_Reflection_Compatibility_Mode>true</NecroBit_Reflection_Compatibility_Mode>
    <String_Encryption>true</String_Encryption>
    <Control_Flow_Obfuscation>true</Control_Flow_Obfuscation>
    <Control_Flow_Obfuscation_Level>9</Control_Flow_Obfuscation_Level>
    <Anti_Tampering>true</Anti_Tampering>
    <Anti_ILDASM>true</Anti_ILDASM>
    <Obfuscation>true</Obfuscation>
    <Obfuscate_Public_Types>true</Obfuscate_Public_Types>
    <Resource_Encryption_And_Compression>true</Resource_Encryption_And_Compression>
    <Strong_Name_Removal_Protection>true</Strong_Name_Removal_Protection>
    <Application_Compression>true</Application_Compression>
    <Hide_Method_Calls>false</Hide_Method_Calls>
    <Native_EXE_File>false</Native_EXE_File>
    <Pre-JIT_Methods>false</Pre-JIT_Methods>
  </Protection_Settings>
</Reactor_Project>
"@
    Invoke-ReactorWithProject "reactor_virtualization_full.exe" `
        "Code virtualization + all protections" `
        $vmInputExe $vmFullXml
}

# Cleanup VM work directory
Remove-Item $vmWorkDir -Recurse -Force -ErrorAction SilentlyContinue

# --- Step 6: Verify ---
$count = (Get-ChildItem "$OutputDir\*.exe").Count
Write-Host "`nGenerated $count samples in $OutputDir"
Get-ChildItem "$OutputDir\*.exe" | Format-Table Name, Length
