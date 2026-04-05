# Rename Protection (Name Obfuscation)

| Property | Value |
|----------|-------|
| **ID** | `Ki.Rename` |
| **Short ID** | `rename` |
| **Preset** | Minimum |
| **Targets** | Types, Methods, Fields, Events, Properties, Modules |
| **Pipeline Stages** | AnalyzePhase: PostStage Inspection; RenamePhase: PostStage BeginModule; PostRenamePhase: PreStage EndModule; ExportMapPhase: PostStage SaveModules |
| **Dependencies** | None explicitly declared |

## Overview

Obfuscates symbol names (types, methods, fields, properties, events) so decompiled code is unreadable and cannot be recompiled. Uses deterministic hashing to generate replacement names in various character sets. Includes extensive analysis to avoid breaking reflection, serialization, WPF, WinForms, and other framework-dependent naming conventions.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `mode` | See Rename Modes | `Unicode` | Character set for generated names |
| `renPublic` | `true`/`false` | `false` | Rename public/protected members |
| `renEnum` | `true`/`false` | `false` | Rename enum literal names |
| `password` | string | (none) | Password for Reversible mode |
| `generatePassword` | `true`/`false` | `false` | Auto-generate and save password |

## Pipeline Phases

### AnalyzePhase (PostStage Inspection)

Determines which symbols can safely be renamed:

1. **VTable construction**: Builds virtual method tables to track overrides
2. **Analyzer registration**: Registers framework-specific analyzers:
   - **WPFAnalyzer**: Detects XAML-referenced members
   - **WinFormsAnalyzer**: Handles designer-serialized names
   - **JsonAnalyzer**: Detects Newtonsoft.Json serialized properties
   - **CaliburnAnalyzer**: Handles Caliburn.Micro naming conventions
   - **VisualBasicRuntimeAnalyzer**: Preserves VB runtime metadata
   - **VsCompositionAnalyzer**: VS Composition Framework exports
3. **Renamability analysis**: Marks each symbol as renameable or not

### RenamePhase (PostStage BeginModule)

Applies the actual name transformations to all renameable symbols.

### PostRenamePhase (PreStage EndModule)

Post-processing via specialized renamers that handle cross-references and fixups.

### ExportMapPhase (PostStage SaveModules)

Exports the old-name → new-name mapping to a `symbols.map` file for debugging.

## Rename Modes

| Mode | ID | Charset | Example |
|------|----|---------|---------|
| **Empty** | `0x0` | Empty string | `` |
| **Unicode** | `0x1` | Invisible Unicode (zero-width spaces, U+200B–U+206F) | `\u200b\u200c\u200d` |
| **ASCII** | `0x2` | Safe ASCII (excludes `.`, `[`, `]`) | `aX9kQ` |
| **Reflection** | `0x3` | ASCII subset safe for reflection APIs | `R3mPx` |
| **Letters** | `0x4` | a-z, A-Z only | `AbCdE` |
| **Decodable** | `0x10` | `_` + alphanumeric, maintains mapping | `_a1b2c` |
| **Sequential** | `0x11` | `_` + sequential names | `_a`, `_b`, `_c` |
| **Reversible** | `0x12` | AES-256 encrypted, Base64 encoded | `$kE_x9Q==` |
| **Debug** | `0x20` | `_` prefix + original name visible | `_OriginalName` |
| **Retain** | `MaxValue` | Keep original name | `OriginalName` |

### Name Generation Algorithm

```csharp
hash = SHA1(originalName) XOR nameSeed
encodedName = EncodeWithCharset(hash, mode)

// Collision avoidance:
while (encodedName already exists):
    hash = SHA1(hash)
    encodedName = EncodeWithCharset(hash, mode)
```

### Reversible Mode

Uses AES-256 encryption with SHA-256 key derivation:
- Key: `SHA256(password)`
- Per-name IV: derived from first character hash XOR key
- Encoding: Base64 with custom alphabet (`$` for `+`, `_` for `/`)
- Password optionally written to file

## What Gets Renamed

### Excluded from Renaming

- Public/protected members in visible types (unless `renPublic=true`)
- Runtime special names (`.ctor`, `.cctor`, `Finalize`)
- Explicit interface implementations
- `ComImport` / `PInvoke` methods without `DispIdAttribute`
- Delegate types
- Serializable fields (unless `[NonSerialized]`)
- Enum literals (unless `renEnum=true`)
- Global module type (`<Module>`)
- Properties in `INotifyPropertyChanged` implementations
- Anonymous type properties
- Types inheriting from `System.Attribute`
- Types inheriting from `SettingsBase`
- Members referenced by XAML/WPF bindings
- Members referenced by `Type.GetType()`, `GetMethod()`, `GetField()` etc.
- Members used in JSON serialization attributes

### Renamed

- Private/internal types, methods, fields, properties, events
- Method generic parameters (renamed to T0, T1, etc.)
- Namespace names
- Parameter names (if not reflection-dependent)

## Reference Tracking

The renamer maintains `INameReference` tracking for:

- **Type blob references**: Types referenced in method body IL
- **Reflection calls**: `Type.GetType()`, `GetMethod()`, `GetField()` patterns
- **Manifest resources**: Resources using type names as keys
- **Cross-module references**: TypeRefs, MemberRefs pointing to renamed targets
- **Serialization**: Fields/properties used in binary/JSON/XML serialization

## dotscope Handling

Renaming is irreversible (except in Reversible mode with the password). dotscope's `BitMonoRenamer` technique can apply heuristic names based on detected patterns, but original names cannot be recovered.
