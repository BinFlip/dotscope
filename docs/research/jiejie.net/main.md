# JIEJIE.NET Research

Comprehensive documentation of JIEJIE.NET protections, based on source code analysis of [dcsoft-yyf/JIEJIE.NET](https://github.com/dcsoft-yyf/JIEJIE.NET).

| Property | Detail |
|----------|--------|
| **Name** | JIEJIE.NET (杰杰.NET) |
| **Source** | [github.com/dcsoft-yyf/JIEJIE.NET](https://github.com/dcsoft-yyf/JIEJIE.NET) |
| **License** | GPL-2.0 |
| **Platform** | .NET Framework 4.0+, .NET Core 3.1+ |
| **Architecture** | ILDasm → text transform → ILAsm pipeline |
| **de4dot support** | None |

## Protection Index

### Value Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [Integer Constant Hiding](constants.md) | `DCInt32ValueContainer` | Value | Delta-chain initialized static fields replacing all `ldc.i4` instructions |
| [String Encryption](strings.md) | `DCJieJieNetEngine` (inline) | Value | XOR-encrypted string storage (normal: cached fields; high-strength: per-access methods) |
| [typeof() Encryption](typeof.md) | `DCJieJieNetEngine` (inline) | Value | `RuntimeTypeHandle[]` array indirection for `ldtoken`/`GetTypeFromHandle` |
| [Array Initialization Encryption](arrays.md) | `DCJieJieNetEngine` (inline) | Value | XOR-encrypted FieldRVA data with `RuntimeFieldHandle[]` indirection |
| [Resource Encryption](resources.md) | `DCJieJieNetEngine` (inline) | Value | XOR-encrypted resources with `GetManifestResourceStream` interception |
| [Enum Parameter Encryption](enum.md) | `DCJieJieNetEngine` (inline) | Value | Enum argument values routed through `Int32ValueContainer` |
| [Char Value Encryption](char.md) | `DCJieJieNetEngine` (inline) | Value | Char constants routed through `Int32ValueContainer` |

### Code Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [Control Flow Obfuscation](controlflow.md) | `DCJieJieNetEngine` (inline) | Code | Switch-based CFF (Algorithm A) or opaque predicates (Algorithm B) |
| [Lock/Using Structure Obfuscation](lock-using.md) | `DCJieJieNetEngine` (inline) | Code | `Monitor.Enter`/`IDisposable.Dispose` redirected through `JIEJIEHelper` |
| [Property Accessor Wrapping](property-wrapping.md) | `DCJieJieNetEngine` (inline) | Code | Synthetic wrapper methods for frequently-called property accessors |
| [Static Method Collection](static-methods.md) | `DCJieJieNetEngine` (inline) | Code | Eligible static methods relocated to synthetic `_jiejienet_sm` class |

### Anti-Analysis Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [Allocation Call Stack Hiding](allocation.md) | `DCJieJieNetEngine` (inline) | Anti-Analysis | Cross-thread string cloning to obscure allocation profiler stacks |

### Renaming & Metadata

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [Symbol Renaming](renaming.md) | `DCJieJieNetEngine` (inline) | Renaming | Base-26 encoded names with `_jiejie`/`_jj` prefixes, intentional overload collisions |
| [Member Order Shuffling](member-order.md) | `DCJieJieNetEngine` (inline) | Metadata | Random shuffling of member declaration order within classes |
| [Dead Member Removal](dead-members.md) | `DCJieJieNetEngine` (inline) | Metadata | Post-rename removal of const fields, enum constants, and properties |

### Structural

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [Assembly Merging](merging.md) | `DCJieJieNetEngine` (merge pipeline) | Structural | ILMerge-style assembly combining at IL text level |

## Pipeline Architecture

Unlike most obfuscators that operate on PE metadata directly (via dnlib, Mono.Cecil, or AsmResolver), JIEJIE.NET operates at the **IL assembly text level**:

1. **Disassemble**: Invokes `ildasm.exe` to disassemble the input assembly to `.il` text
2. **Parse**: `DCILReader` parses the IL text into an in-memory DOM (`DCILDocument`)
3. **Transform**: `HandleDocument()` applies all obfuscation passes in sequence
4. **Write**: `DCILWriter` serializes the modified DOM back to IL text
5. **Reassemble**: Invokes `ilasm.exe` to produce the output binary
6. **Re-sign**: If SNK file provided, `sn.exe -Ra` re-signs the assembly

This IL-text approach means JIEJIE.NET **never touches raw PE bytes directly** — all transformations are expressed as IL instruction rewrites. There is no PE corruption, no invalid metadata injection, and no anti-tamper protection. The output is always a valid, well-formed .NET assembly.

### HandleDocument() Execution Order

| Step | Protection | Switch | Details |
|------|-----------|--------|---------|
| 1 | Per-class switch parsing | Always | Parse `ObfuscationAttribute.Feature` for per-type/method switch overrides |
| 2 | Type removal | Config | Delete types listed in `RemoveTypes` |
| 3 | Helper class injection | Always | Inject `__DC20211119.JIEJIEHelper` runtime helper class |
| 4 | Custom attribute removal | Config | Strip specified custom attribute types |
| 5 | Resource container replacement | `Resources` | Replace ResourceManager wrapper classes with encrypted versions |
| 6 | Embedded resource encryption | `Resources` | XOR-encrypt embedded resources, redirect `GetManifestResourceStream` |
| 7 | Char value encryption | `ControlFlow` | Replace char literals with `Int32ValueContainer` field loads |
| 8 | Array initialization encryption | `ControlFlow` | XOR-encrypt `RuntimeHelpers.InitializeArray` data |
| 9 | Lock/using structure obfuscation | `ControlFlow` | Redirect `Monitor.Enter`/`IDisposable.Dispose` through helpers |
| 10 | Per-class member handling | `MemberOrder` | Shuffle member declaration order |
| 11 | typeof() encryption | `ControlFlow` | Replace `ldtoken` + `GetTypeFromHandle` with container indirection |
| 12 | Enum parameter encryption | `ControlFlow` | Replace enum argument literals with container field loads |
| 13 | String encryption | `Strings` | Encrypt string literals (normal or high-strength mode) |
| 14 | Data container class commit | Always | Commit `ByteArrayDataContainer` synthetic class |
| 15 | Control flow obfuscation | `ControlFlow` | Switch-based dispatcher or rude mode with opaque predicates |
| 16 | Property accessor wrapping | `ControlFlow` | Wrap frequently-called property getters/setters |
| 17 | Static method collection | `ControlFlow` | Move eligible static methods to synthetic class |
| 18 | Int32ValueContainer commit | `ControlFlow` | Commit integer constant container class |
| 19 | Renaming | `Rename` | Rename types/methods/fields/parameters |
| 20 | Dead member removal | `RemoveMember` | Remove unused const fields and properties |
| 21 | `InternalsVisibleTo` removal | Always | Strip friend assembly attributes |

**Key ordering insight**: `Int32ValueContainer` is committed at step 18, **after** all other ControlFlow-dependent protections. This means the container accumulates field entries from steps 7–17. CFF (step 15) is applied before the container is committed, so the CFF switch indices are among the values stored in the container.

## Configuration System

### Primary Switches (`JieJieSwitchs`)

| Switch | Default | CLI | Description |
|--------|---------|-----|-------------|
| `ControlFlow` | `true` | `+controlflow` / `-controlflow` | CFF + all value encryption (typeof, enum, char, array, lock) |
| `Strings` | `true` | `+strings` / `-strings` | String literal encryption |
| `HightStrings` | `false` | `+hightstrings` / `-hightstrings` | High-strength string encryption (per-access, no caching) |
| `Resources` | `true` | `+resources` / `-resources` | Resource container and embedded resource encryption |
| `AllocationCallStack` | `false` | `+allocationcallstack` / `-allocationcallstack` | Cross-thread string cloning |
| `MemberOrder` | `true` | `+memberorder` / `-memberorder` | Randomize member declaration order |
| `Rename` | `true` | `+rename` / `-rename` | Rename types, methods, fields, parameters |
| `RemoveMember` | `true` | `+removemember` / `-removemember` | Remove unused members after rename |

### Per-Type / Per-Method Overrides

Switches can be overridden at the type or method level via three mechanisms:

1. **`ObfuscationAttribute.Feature`**: Set `Feature = "JIEJIE.NET.SWITCH:+strings,-controlflow,..."`
2. **Const string field**: Declare a `const string` field with value `"JIEJIE.NET.SWITCH:+strings,..."`
3. **Method body ldstr**: Place an `ldstr "JIEJIE.NET.SWITCH:..."` instruction in the method

## Injected Synthetic Types

All injected types use the namespace prefix `__DC20210205` or `__DC20211119`:

| Type | Purpose |
|------|---------|
| `__DC20211119.JIEJIEHelper` | Runtime helper: Monitor wrappers, Dispose wrapper, InitializeArray decryption, resource stream decryption, string cloning |
| `__DC20210205._Int32ValueContainer` | Integer constant indirection — static fields initialized via delta chain |
| `__DC20210205._RuntimeTypeHandleContainer` | typeof() indirection — `RuntimeTypeHandle[]` array with `GetTypeInstance(int)` |
| `__DC20210205._RuntimeFieldHandleContainer` | RuntimeFieldHandle indirection — `RuntimeFieldHandle[]` array with `GetHandle(int)` |
| `__DC20210205._Strings<N>` | Normal string encryption — static fields with `dcsoft(byte[], long)` decryptor |
| `__DC20210205._HightStrings<N>` | High-strength string encryption — per-string decryptor methods |
| `__DC20210205._ByteArrayDataContainer` | Byte array storage via RVA-initialized nested value types |
| `__DC20210205._Res<N>` | Resource wrapper classes (ComponentResourceManager replacement) |
| `__DC20210205._jiejienet_sm` | Collected static methods relocated from original classes |

## Deobfuscation Status

Integer constants, strings (normal + high-strength), typeof(), arrays, resources, and CFF are all handled. Test suite: 10/10 samples pass.

### dotscope Techniques (Detection)

| Technique | Protection | Type |
|-----------|-----------|------|
| `JiejieNetConstants` | Int32ValueContainer | Structural (delta-chain `.cctor`) |
| `JiejieNetStrings` | String Encryption | Structural (dcsoft method + string class pattern) |
| `JiejieNetTypeOf` | typeof() Encryption | Structural (RuntimeTypeHandle array + accessor) |
| `JiejieNetArrays` | Array Init Encryption | Structural (RuntimeFieldHandle array + MyInitializeArray) |
| `JiejieNetResources` | Resource Encryption | SSA-based (post-CFF `SMF_GetContent` analysis) |
| `GenericFlattening` | Control Flow | Generic (switch dispatcher detection) |

### dotscope Passes (Reversal)

| Pass | Protection | Phase |
|------|-----------|-------|
| `Int32ValueContainerPass` | Int32ValueContainer | Value (before CFF) |
| `JiejieStringFieldPass` | String Encryption (normal) | Value |
| `DecryptionPass` (shared) | String Encryption (high-strength) | Value |
| `TypeOfRestorationPass` | typeof() Encryption | Value |
| `ArrayInitRestorationPass` | Array Init Encryption | Value |
| `ResourceRestorationPass` | Resource Encryption | Simplify |
| `CffReconstructionPass` (generic) | Control Flow (Algorithm A) | Structure |

### Critical Ordering

```
Int32ValueContainerPass (resolves all container field loads)
    ↓
JiejieStringFieldPass, TypeOfRestorationPass, ArrayInitRestorationPass (all depend on resolved constants)
    ↓
CffReconstructionPass (switch indices are now concrete constants)
    ↓
ResourceRestorationPass (runs post-CFF, needs SSA analysis of SMF_GetContent)
    ↓
Cleanup (remove JIEJIEHelper, containers, string classes)
```

### Remaining Work

- [ ] DemoIfElse CFF reconstruction — one sample method has lower semantic preservation
- [ ] Resource container class restoration (`.resources` file reconstruction) — currently only embedded resources are fully restored

## What Cannot Be Reversed

- **Symbol renaming**: Original names are irrecoverably lost. The `.map.xml` file is external.
- **Parameter names**: Set to `p0`, `p1`, ... — no recovery possible.
- **Dead member removal**: Removed const fields and properties cannot be reconstructed.
- **Member order**: Original declaration order is lost (but semantically irrelevant).

## Key Architectural Patterns

### Int32ValueContainer as Critical Dependency

`Int32ValueContainer` is the most important type to resolve — nearly every other protection depends on it. CFF switch indices, typeof array indices, array XOR keys, enum values, and char values are all stored as container field loads. The `Int32ValueContainerPass` must run **before all other JIEJIE.NET passes and before CFF unflattening**.

### IL-Text Pipeline

JIEJIE.NET's unique ILDasm → transform → ILAsm architecture means all protections are expressed as IL instruction rewrites. This guarantees valid output assemblies (no PE corruption, no invalid metadata) but limits the obfuscator to protection techniques expressible in IL text. There are no native code protections, no anti-tamper checksums, and no PE-level packing.

### ByteArrayDataContainer Shared Infrastructure

`ByteArrayDataContainer` provides efficient byte array storage for multiple protections (strings, resources, array init data). It uses nested value types with `ExplicitLayout` / `.pack 1` / `.size N` for RVA-backed initialization via `RuntimeHelpers.InitializeArray`. Its `.cctor` must run before any string class `.cctors` (dependency chain).

### Detection and Attribution

JIEJIE.NET always injects the `JIEJIEHelper` class (even when only renaming is enabled). This serves as the anchor detection signal. Supporting signals include the `__DC20210205.*` synthetic types, `dcsoft` method signatures, `_jiejie`/`_jj` naming patterns, and the delta-chain `.cctor` pattern.

## References

- [JIEJIE.NET source](https://github.com/dcsoft-yyf/JIEJIE.NET) (GPL-2.0)
- Key source files:
  - `source/JIEJIEEngine/DCJieJieNetEngine.cs` — Main engine (HandleDocument pipeline)
  - `source/JIEJIEEngine/JieJieSwitchs.cs` — Configuration switches
  - `source/JIEJIEEngine/DCILReader.cs` — IL text parser
  - `source/JIEJIEEngine/DCILWriter.cs` — IL text serializer
  - `source/JIEJIEEngine/CodeTemplate.cs` — JIEJIEHelper template source
