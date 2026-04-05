# Obfuscar Research

Comprehensive documentation of Obfuscar protections, based on source code analysis of [obfuscar/obfuscar](https://github.com/obfuscar/obfuscar).

## Protection Index

### Code Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [String Hiding](string-hiding.md) | `Obfuscator` (inline) | Value | XOR-encrypted string storage with per-string accessor methods |

### Data Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [Symbol Renaming](symbol-renaming.md) | `Obfuscator` (pipeline) | Renaming | Type/method/field/property/event/parameter renaming with overload reuse |

### Anti-Analysis Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [SuppressIldasm](suppress-ildasm.md) | `Obfuscator` (inline) | Metadata | SuppressIldasmAttribute injection to block ILDASM |

### Configuration & Infrastructure

| Component | Description |
|-----------|-------------|
| [Skip Rules System](skip-rules.md) | Skip/Force rules, visibility controls, regex/wildcard matching |
| [Mapping File](mapping-file.md) | Text and XML mapping file formats for rename tracking |

## Pipeline Architecture

Obfuscar processes assemblies through a sequential pipeline implemented in `Obfuscator.RunRules()`. Unlike ConfuserEx (which uses a multi-stage pipeline with protection phase registration), Obfuscar executes hardcoded steps in a fixed order:

```
 1.  LoadMethodSemantics()   — Cache getter/setter/add/remove associations
 2.  HideStrings()           — Replace ldstr with calls to decryptor accessors
 3.  RenameFields()          — Rename fields, grouped by type signature
 4.  RenameParams()          — Erase method parameter names (set to null)
 5.  RenameProperties()      — Rename or drop property definitions
 6.  RenameEvents()          — Rename or drop event definitions
 7.  RenameMethods()         — Rename methods with virtual method grouping
 8.  RenameTypes()           — Rename types/namespaces, fix resources and BAML
 9.  PostProcessing()        — Strip ObfuscationAttribute, add SuppressIldasm
10.  SaveAssemblies()        — Write modified assemblies (with optional re-signing)
11.  SaveMapping()           — Write rename mapping file (text or XML)
```

**Key ordering constraint**: String hiding runs before all renaming steps so that string accessor method names use the same character set. Type renaming runs last because it must update all cross-references after fields, methods, properties, and events have been renamed.

### Pre-Pipeline Processing

Before `RunRules()`, each assembly undergoes:

1. **Module loading**: Assembly parsed via System.Reflection.Metadata (SRM) with mutable wrapper
2. **InheritMap construction**: Full inheritance hierarchy built for virtual method grouping
3. **Rule parsing**: Skip/Force rules evaluated from XML project file
4. **Assembly search path resolution**: External assembly references resolved

## Configuration System

### Project File Format

Obfuscar uses an XML project file (typically `obfuscar.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<Obfuscator>
  <!-- Global settings -->
  <Var name="InPath" value="/path/to/input" />
  <Var name="OutPath" value="/path/to/output" />
  <Var name="LogFile" value="/path/to/mapping.txt" />
  <Var name="KeepPublicApi" value="true" />
  <Var name="HideStrings" value="true" />

  <!-- Assembly search paths -->
  <AssemblySearchPath path="/path/to/dependencies" />

  <!-- Module declarations with per-module rules -->
  <Module file="$(InPath)/MyAssembly.dll">
    <SkipType name="MyNamespace.PublicType" skipMethods="true" />
    <SkipMethod name="ToString" />
    <ForceField rx="^m_.*" />
  </Module>

  <!-- Glob-based module inclusion -->
  <Modules>
    <IncludeFiles>**/*.dll</IncludeFiles>
    <ExcludeFiles>**/ThirdParty.dll</ExcludeFiles>
  </Modules>

  <!-- Include external rule files -->
  <Include path="/path/to/shared-rules.xml" />
</Obfuscator>
```

### Settings Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `InPath` | cwd | Input assembly directory |
| `OutPath` | cwd | Output directory |
| `LogFile` | `""` | Mapping file output path |
| `RenameFields` | `true` | Enable field renaming |
| `RenameProperties` | `true` | Enable property renaming/dropping |
| `KeepProperties` | `false` | Rename properties instead of dropping |
| `RenameEvents` | `true` | Enable event renaming/dropping |
| `KeepPublicApi` | `true` | Skip public API renaming |
| `HidePrivateApi` | `true` | Rename non-public API |
| `ReuseNames` | `true` | Overload renaming (same names, different sigs) |
| `UseUnicodeNames` | `false` | Use invisible Unicode characters |
| `UseKoreanNames` | `false` | Use Korean Hangul characters |
| `CustomChars` | `""` | Custom character set for names |
| `HideStrings` | `true` | Enable string hiding |
| `SuppressIldasm` | `true` | Add SuppressIldasmAttribute |
| `MarkedOnly` | `false` | Only obfuscate `[Obfuscation]`-marked members |
| `OptimizeMethods` | `true` | Method optimization (currently disabled in code) |
| `XmlMapping` | `false` | XML mapping format instead of text |
| `RegenerateDebugInfo` | `false` | Regenerate PDB/debug symbols |
| `AnalyzeXaml` | `false` | Parse WPF BAML to protect XAML-referenced types |
| `SkipGenerated` | `false` | Skip compiler-generated types |
| `SkipSpecialName` | `false` | Skip special-name members |
| `KeyFile` | `""` | Strong name key file for re-signing (`"auto"` = detect from assembly) |
| `KeyContainer` | `""` | Strong name key container name |

## Deobfuscation Status

String hiding is fully handled via emulation-based decryption. Symbol renaming is inherently irreversible. Test suite: 6/6 samples pass.

### dotscope Techniques (Detection)

| Technique | Protection | Type |
|-----------|-----------|------|
| `ObfuscarStrings` | String Hiding | SSA (value phase) |

### dotscope Passes (Reversal)

| Pass | Protection | Phase |
|------|-----------|-------|
| `DecryptionPass` (shared) | String Hiding | Value |

### Attribution

Obfuscar attribution requires detection of the string hiding infrastructure (`obfuscar.strings`). No supporting techniques — a single positive string detection triggers attribution.

### Remaining Work

- [ ] Property/event metadata reconstruction — detect orphaned getter/setter pairs without PropertyDef and optionally reconstruct (low priority, cosmetic)
- [ ] Naming mode detection — report which character set was used (informational)

## What Cannot Be Reversed

- **Symbol renaming**: Original names are irrecoverably lost. The mapping file is external to the assembly.
- **Parameter names**: Set to null — no recovery possible.
- **Property/event definitions**: When dropped (not just renamed), the original property/event metadata is lost. Getter/setter methods survive but lose their property association.
- **Overload renaming**: While the IL remains valid, decompiled source shows multiple members with the same name.

## Key Architectural Patterns

### Renaming-First Design

Unlike ConfuserEx (multi-layer protection framework) or BitMono (plugin-based protection pipeline), Obfuscar is fundamentally a renaming tool. String hiding is its only code-transforming protection. This makes it the simplest obfuscator to handle — deobfuscation is primarily string decryption plus metadata cleanup.

### Overload Renaming

Obfuscar's `ReuseNames` feature produces IL-level method/field overloads that are valid in CIL but unrepresentable in most source languages. This is a distinctive signature — methods with different parameter types sharing the same name.

### Virtual Method Grouping

The `InheritMap` class builds a complete inheritance hierarchy and groups all virtual method overrides into `MethodGroup` instances. This ensures that a base method and all its overrides receive the same renamed name, preventing `TypeLoadException` at runtime.

### Property/Event Metadata Stripping

By default, Obfuscar **removes** property and event definitions rather than just renaming them. This is more aggressive than most obfuscators — the getter/setter methods survive but their semantic association is lost.

## References

- [Obfuscar source](https://github.com/obfuscar/obfuscar) (MIT license)
- [Obfuscar documentation](https://docs.obfuscar.com/)
- [Obfuscar NuGet (global tool)](https://www.nuget.org/packages/Obfuscar.GlobalTool/)
- Key source files:
  - `src/Obfuscar/Obfuscator.cs` — Main pipeline
  - `src/Obfuscar/Settings.cs` — Configuration options
  - `src/Obfuscar/NameMaker.cs` — Name generation algorithm
  - `src/Obfuscar/Project.cs` — XML configuration parsing
  - `src/Obfuscar/MapWriter.cs` — Mapping file output
  - `src/Obfuscar/InheritMap.cs` — Virtual method grouping
