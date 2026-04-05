# ConfuserEx Research

Comprehensive documentation of ConfuserEx protections, based on source code analysis of [mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx).

## Protection Index

### Anti-Runtime Protections

| Protection | ID | Preset | Description |
|------------|-----|--------|-------------|
| [Anti Debug](anti-debug.md) | `Ki.AntiDebug` | Minimum | Runtime debugger/profiler detection and prevention |
| [Anti Dump](anti-dump.md) | `Ki.AntiDump` | Maximum | PE header corruption to prevent memory dumping |
| [Anti IL Dasm](anti-ildasm.md) | `Ki.AntiILDasm` | Minimum | SuppressIldasmAttribute advisory marker |
| [Invalid Metadata](invalid-metadata.md) | `Ki.InvalidMD` | None | Garbage metadata to confuse disassemblers |

### Code Protections

| Protection | ID | Preset | Description |
|------------|-----|--------|-------------|
| [Control Flow](control-flow.md) | `Ki.ControlFlow` | Normal | Switch/jump dispatch table mangling |
| [Constants](constants.md) | `Ki.Constants` | Normal | Constant extraction, encryption, and runtime decoding |
| [Reference Proxy](reference-proxy.md) | `Ki.RefProxy` | Normal | Delegate-based method call indirection |
| [Anti-Tamper](anti-tamper.md) | `Ki.AntiTamper` | Maximum | IL body encryption in custom PE section |

### Data Protections

| Protection | ID | Preset | Description |
|------------|-----|--------|-------------|
| [Resources](resources.md) | `Ki.Resources` | Normal | Embedded resource encryption and compression |
| [Rename](rename.md) | `Ki.Rename` | Minimum | Symbol name obfuscation |

### Structural Protections

| Protection | ID | Preset | Description |
|------------|-----|--------|-------------|
| [Type Scrambler](type-scrambler.md) | `BahNahNah.typescramble` | None | Replace types with generic parameters |
| [Compressor](compressor.md) | `Ki.Compressor` | N/A (Packer) | Pack assembly into encrypted stub |

### Infrastructure

| Protection | ID | Preset | Description |
|------------|-----|--------|-------------|
| [Watermark](watermark.md) | `Cx.Watermark` | Always | ConfusedByAttribute injection |
| [Hardening](hardening.md) | `Cx.Harden` | Minimum | Inline protection helpers into .cctor |

### Shared Components

| Component | Description |
|-----------|-------------|
| [DynCipher](dynciper.md) | Dynamic cipher generation used by multiple protections |

## Pipeline Architecture

ConfuserEx processes assemblies through a multi-stage pipeline. Each protection registers one or more phases at specific pipeline stages.

### Pipeline Stages (Execution Order)

```
1. Inspection      — Engine inspects loaded modules (global, once)
2. BeginModule     — Engine begins processing a module (per-module)
3. ProcessModule   — Engine processes a module (per-module)
4. OptimizeMethods — Engine optimizes method bodies (per-module)
5. EndModule       — Engine finishes processing a module (per-module)
6. WriteModule     — Engine writes module to byte array (per-module, after all modules)
7. Debug           — Engine generates debug symbols (global, once)
8. Pack            — Engine packs output if packer present (global, once)
9. SaveModules     — Engine saves output files (global, once)
```

Each stage has **pre-processing** and **post-processing** sub-phases. Protections insert their phases at either pre or post.

### Protection Phase Registration

| Protection | Phase | Stage | Pre/Post |
|------------|-------|-------|----------|
| AntiDebug | AntiDebugPhase | ProcessModule | Pre |
| AntiDump | AntiDumpPhase | ProcessModule | Pre |
| AntiILDasm | AntiILDasmPhase | ProcessModule | Pre |
| InvalidMetadata | InvalidMDPhase | BeginModule | Post |
| ControlFlow | ControlFlowPhase | OptimizeMethods | Pre |
| Constants | InjectPhase | ProcessModule | Pre |
| Constants | EncodePhase | ProcessModule | Post |
| RefProxy | ReferenceProxyPhase | ProcessModule | Pre |
| AntiTamper | ModuleWriterSetupPhase | BeginModule | Post |
| AntiTamper | InjectPhase | OptimizeMethods | Pre |
| AntiTamper | MDPhase | EndModule | Pre |
| Resources | InjectPhase | ProcessModule | Pre |
| Resources | MDPhase | (ModuleWriter event) | — |
| Rename | AnalyzePhase | Inspection | Post |
| Rename | RenamePhase | BeginModule | Post |
| Rename | PostRenamePhase | EndModule | Pre |
| Rename | ExportMapPhase | SaveModules | Post |
| TypeScrambler | AnalyzePhase | Inspection | Pre |
| TypeScrambler | ScramblePhase | ProcessModule | Post |
| Watermark | WatermarkingPhase | EndModule | Post |
| Hardening | HardeningPhase | OptimizeMethods | Pre |
| Compressor | ExtractPhase | WriteModule | Pre |

## Protection Presets

Protections are grouped into security tiers:

| Preset | Level | Protections |
|--------|-------|-------------|
| **Minimum** | 1 | AntiDebug, AntiILDasm, Rename, Hardening |
| **Normal** | 2 | + ControlFlow, Constants, RefProxy, Resources |
| **Aggressive** | 3 | (No additional protections at this level) |
| **Maximum** | 4 | + AntiDump, AntiTamper |
| **None** | 0 | InvalidMetadata, TypeScrambler, Watermark*, Compressor |

\* Watermark is always applied regardless of preset.

Selecting a preset enables all protections at that level **and below**.

## Dependency Graph

Protections declare ordering constraints via `BeforeProtection` and `AfterProtection` attributes. Dependencies are resolved via topological sort (Kahn's algorithm).

```
                    ┌─────────────────────┐
                    │                     │
                    ▼                     │
AntiDebug ──────► RefProxy ──────► Constants ──────► Resources
                    │                  │                 │
AntiDump  ──────►   │                  │                 │
                    │                  ▼                 │
                    └──────────► ControlFlow ◄───────────┘
                                     ▲
                                     │
                              AntiTamper
```

**Reading the graph**: Arrows point from "runs after" to "runs before".
- RefProxy runs after AntiDebug and AntiDump
- Constants runs after RefProxy
- Resources runs after Constants
- ControlFlow runs after all of them
- AntiTamper runs after Constants, before ControlFlow

## Deobfuscation Status

All standard preset protections (Minimum through Maximum) are fully handled. Test suite: 18/18 samples pass.

### Remaining Work

- [ ] Type Scrambler (`BahNahNah.typescramble`) — not part of any preset
- [ ] Compressor/Packer (`Ki.Compressor`) — not part of any preset
- [ ] Edge case samples: nested types, heavy generics, large methods

## Additional Research

| Document | Description |
|----------|-------------|
| [constants-emulation.md](constants-emulation.md) | Constants protection emulation requirements |
| [x86-native-stubs.md](x86-native-stubs.md) | Extracted x86 native code stubs from samples |

## Key Architectural Patterns

### Code Injection

Most protections follow the same injection pattern:
1. Get runtime type from `Confuser.Runtime` assembly
2. `InjectHelper.Inject()` copies type into module's global type
3. Extract `Initialize()` method
4. Insert call at position 0 of module `.cctor`
5. Rename/hide injected members

### Dynamic Cipher Integration

Constants, Resources, Control Flow, Reference Proxy, Anti-Tamper, and Compressor all use the [DynCipher](dynciper.md) service to generate unique encryption/decryption routines per protected assembly. This ensures no two protected binaries have identical cipher code.

### Module Writer Event Hooks

Several protections hook into `ModuleWriterBase` events for late-stage metadata and PE manipulation:
- **Anti-Tamper**: Creates encrypted PE section
- **Resources**: Encrypts resources during write
- **Invalid Metadata**: Injects garbage metadata entries
- **x86 predicates/encodings**: Inject native code bodies

### Mutation System

The `Mutation` class provides placeholders in runtime code that are replaced during protection:
- `Mutation.KeyI0`, `KeyI1`, etc.: Integer constant injection
- `Mutation.Placeholder()`: Replaced with mode-specific logic
- `Mutation.Crypt()`: Replaced with cipher operations
- `Mutation.Value<T>()`: Replaced with `sizeof(T)` or constant
