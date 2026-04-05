# BitMono Research

Comprehensive documentation of BitMono protections, based on source code analysis of [sunnamed434/BitMono](https://github.com/sunnamed434/BitMono).

## Protection Index

### Code Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [StringsEncryption](strings-encryption.md) | `Protection` | Value | AES-256-CBC string encryption with PBKDF2 key derivation |
| [CallToCalli](call-to-calli.md) | `Protection` | Structure | Convert direct calls to indirect `calli` via reflection |
| [DotNetHook](dotnet-hook.md) | `Protection` | Structure | Method redirection through JIT-patched dummy stubs |
| [UnmanagedString](unmanaged-string.md) | `Protection` | Value | String literals embedded in native x86/x64 method bodies |

### Anti-Analysis Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [AntiDebugBreakpoints](anti-debug-breakpoints.md) | `Protection` | Neutralization | Timing-based breakpoint detection with divide-by-zero crash |
| [BitMethodDotnet](bit-method-dotnet.md) | `Protection` | Junk | Unreachable prefix instruction at method entry |
| [BillionNops](billion-nops.md) | `Protection` | Junk | Dead method with 100,000 NOP instructions |
| [AntiDecompiler](anti-decompiler.md) | `PipelineProtection` | Metadata | Invalid type attributes on nested module types |
| [AntiDe4dot](anti-de4dot.md) | `Protection` | Metadata | Fake obfuscator-identification custom attributes |
| [AntiILdasm](anti-ildasm.md) | `Protection` | Metadata | SuppressIldasmAttribute injection |
| [ObjectReturnType](object-return-type.md) | `Protection` | Metadata | Change `bool` return types to `object` |

### Renaming Protections

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [FullRenamer](full-renamer.md) | `Protection` | Renaming | Word-pool-based symbol renaming |
| [NoNamespaces](no-namespaces.md) | `Protection` | Renaming | Remove all type namespaces |

### PE-Level Packers

| Protection | Class | Category | Description |
|------------|-------|----------|-------------|
| [BitDotNet](bit-dotnet.md) | `PackerProtection` | PE | Corrupt PE signature and CLR header |
| [BitDecompiler](bit-decompiler.md) | `PackerProtection` | PE | Zero CLR header fields |
| [BitMono (packer)](bit-mono-packer.md) | `PackerProtection` | PE | Corrupt PE optional header data directories |
| [BitTimeDateStamp](bit-timedatestamp.md) | `PackerProtection` | PE | Zero PE TimeDateStamp field |

## Pipeline Architecture

BitMono uses a plugin-based architecture built on a lightweight DI container. Protections are loaded as independent plugins and executed sequentially.

### Protection Type Hierarchy

```
IProtection                      — Base: ExecuteAsync()
├── Protection : ProtectionBase  — Standard IL-level protection (runs before PE write)
├── PipelineProtection           — Protection with ordered sub-phases (IPhaseProtection)
└── PackerProtection : IPacker   — Post-write PE-level protection (raw byte manipulation)
```

Key distinction: **Protections** modify the AsmResolver module in memory (IL, metadata). **Packers** modify the on-disk PE file after AsmResolver writes it.

### Execution Pipeline

```
 1.  OutputLoadedModule()           — Log target assembly info
 2.  OutputBitMonoInfo()            — Log BitMono version/runtime
 3.  OutputCompatibilityIssues()    — Warn about framework mismatches
 4.  SortProtections()              — Sort by config + [Obfuscation] attributes
 5.  ConfigureForNativeCode()       — Set PE flags if needed (UnmanagedString)
 6.  ResolveDependencies()          — Resolve assembly references
 7.  ExpandMacros()                 — Normalize IL instructions (short→long forms)
 8.  RunProtectionsAsync()          — Execute all Protection + PipelineProtection instances
 9.  OptimizeMacros()               — Re-optimize IL instructions (long→short)
10.  StripObfuscationAttributes()   — Remove [Obfuscation] attributes
11.  CreatePEImage()                — Build PE image via AsmResolver
12.  WriteModuleAsync()             — Write PE to disk (optional strong name signing)
13.  PackAsync()                    — Execute all PackerProtection instances (post-write)
```

### Configuration

Protections are configured via `protections.json`:

```json
{
  "Protections": [
    { "Name": "StringsEncryption", "Enabled": true },
    { "Name": "CallToCalli", "Enabled": true }
  ]
}
```

Global settings in `obfuscation.json` control `RandomStrings` (word pool for renaming), `FailOnNoRequiredDependency`, `StripObfuscationAttributes`, `X86` (architecture), and `StrongNameKeyFile`.

### Member Exclusion System

Protections annotated with `[DoNotResolve(MemberInclusionFlags)]` skip certain members:

| Flag | Effect |
|------|--------|
| `SpecialRuntime` | Skip runtime-critical members |
| `Model` | Skip data model members |
| `Reflection` | Skip reflection-accessed members |

### Runtime Injection

Several protections clone types from `BitMono.Runtime` into the target assembly using AsmResolver's `MemberCloner`. The runtime module contains:

| Type | Used By | Purpose |
|------|---------|---------|
| `Data` | StringsEncryption | Static byte array fields (key + salt) |
| `Decryptor` | StringsEncryption | AES-256-CBC decryption method |
| `Encryptor` | StringsEncryption | AES-256-CBC encryption (obfuscation time only) |
| `Hooking` | DotNetHook | Platform-specific JIT method patching |

Injected types are marked with `CompilerGeneratedAttribute` and renamed using the word pool.

## Protection Categories

| Category | Protections | Reversible? |
|----------|-------------|-------------|
| **Value** | StringsEncryption, UnmanagedString | Yes — keys are static or embedded |
| **Structure** | CallToCalli, DotNetHook | Yes — tokens are embedded in IL |
| **Neutralization** | AntiDebugBreakpoints | Yes — pattern removal |
| **Junk** | BitMethodDotnet, BillionNops | Yes — dead code removal |
| **Metadata** | AntiDecompiler, AntiDe4dot, AntiILdasm, ObjectReturnType | Yes — attribute/metadata fixes |
| **Renaming** | FullRenamer, NoNamespaces | No — lossy transformation |
| **PE** | BitDotNet, BitDecompiler, BitMono packer, BitTimeDateStamp | Mostly — header repair (timestamp is lossy) |

## Deobfuscation Status

All reversible BitMono protections are fully handled. Test suite: 16/16 samples pass.

### dotscope Techniques (Detection)

| Technique | Protection | Type |
|-----------|-----------|------|
| `BitMonoCalli` | CallToCalli | SSA |
| `BitMonoStrings` | StringsEncryption | SSA |
| `BitMonoUnmanaged` | UnmanagedString | SSA |
| `BitMonoAntiDebug` | AntiDebugBreakpoints | SSA |
| `BitMonoNops` | BillionNops | SSA |
| `BitMonoRenamer` | FullRenamer | SSA |
| `BitMonoJunk` | BitMethodDotnet | Byte |
| `BitMonoHooks` | DotNetHook | Byte |
| `BitMonoPeRepair` | BitDotNet/BitDecompiler/BitMono packer | Byte |

### dotscope Passes (Reversal)

| Pass | Protection | Phase |
|------|-----------|-------|
| `CalltocalliReversalPass` | CallToCalli | Simplify |
| `StringDecryptionPass` | StringsEncryption | Simplify |
| `UnmanagedStringReversalPass` | UnmanagedString | Simplify |
| `AntiDebugRemovalPass` | AntiDebugBreakpoints | Simplify |

### Remaining Work

- [ ] ObjectReturnType — return type inference (cosmetic, low priority)
- [ ] AntiDecompiler — attribute reset (Mono-only, rarely seen)

## Key Architectural Patterns

### Independence of Protections

Unlike ConfuserEx (which layers protections with dependencies and shared cipher infrastructure), BitMono protections are fully independent. Each can be applied and reversed individually with no ordering constraints or cross-protection interactions.

### Token Embedding

CallToCalli and DotNetHook both embed method metadata tokens as `ldc.i4` constants in IL. This makes reversal entirely static — no emulation needed, just extract the embedded token and restore the direct call.

### Native Code Embedding

UnmanagedString creates native methods with `MethodImplAttributes.Native | Unmanaged | PreserveSig` and `MethodAttributes.PInvokeImpl`. The string bytes are embedded directly after a short x86/x64 trampoline that returns a pointer to them. Requires `IsILOnly = false` on the PE.

### Pre-Load PE Repair

PE-level packers (BitDotNet, BitDecompiler, BitMono packer) corrupt the PE before tools can parse it. dotscope's loader transparently detects and repairs these corruptions during loading, before the assembly reaches the deobfuscation pipeline.

## References

- [BitMono source](https://github.com/sunnamed434/BitMono) (MIT license)
- [BitMono documentation](https://bitmono.readthedocs.io/)
- [AsmResolver](https://github.com/Washi1337/AsmResolver) — assembly manipulation library used by BitMono
- Credits for original techniques:
  - [BitDotNet](https://github.com/0x59R11/BitDotNet) — PE corruption
  - [DotNetHook](https://github.com/Elliesaur/DotNetHook) — method hooking
  - [UnmanagedString](https://github.com/MrakDev/UnmanagedString) — native string embedding
