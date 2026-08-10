# Anti-Tamper Protection (Stage 3)

Analysis of .NET Reactor 7.5.0 anti-tamper protection based on reverse engineering
`reactor_antitamp.exe` (48,640 bytes, 214 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## Status (2026-04-24) — Landed

`netreactor.antitamp` technique is implemented and wired into
`TechniqueRegistry::with_config`. `reactor_antitamp.exe` now executes
end-to-end under mono (full `=== Test App === → === Done ===` output),
taking NR mono executability to 9 / 17. The technique detects the
anti-tamper init via `.cctor` fan-in (no hard-coded names), marks the
init method + runtime container type + `<Module>{GUID}` marker + all
purely-injected `.cctor`s for removal, and attaches a Value-phase SSA
pass (`TokenResolverPass`) that folds the metadata-token resolver's
`accessor(<const_int>)` calls back into `ldtoken X` — without the fold,
user `typeof`/`is`/`typeof(List<>)` resolve to wrong types because the
resolver's hard-coded metadata-token arguments don't survive token
renumbering. The NR antitamp encrypted resource (256 B embedded
payload) is also cleaned up via the new
`CleanupRequest::add_manifest_resource(Token)` API: the technique
scans every method on the runtime container (and its nested types) for
`ldstr <name>` references, matches them against the assembly's
`ManifestResource` names, and marks each matched row; the writer's
existing resource-section compaction loop drops the embedded bytes and
remaps `offset_field` on surviving rows during regeneration. Output
now matches `original.exe` modulo only the known `.g.resources`
orphan.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 48,640 | +34,304 (239%) |
| .text section | 0x2E00 | 0xB400 | +34,304 |
| Metadata size | 7,904 | 23,644 | +15,740 |
| TypeDef rows | 13 | 47 | +34 |
| MethodDef rows | 35 | 214 | +179 |
| Methods with bodies | 35 | 172 | +137 |
| Tables count | 17 | 23 | +6 |


## .cctor Injection Pattern

The core anti-tamper mechanism: **every single type** receives a `.cctor` that calls the
CFF-protected initialization method (row 82, `n8kD0qL3P`). This ensures tamper
verification runs before any type is accessed.

Types with injected .cctors (calling row 82):
- `Microsoft.CodeAnalysis.EmbeddedAttribute`
- `System.Runtime.CompilerServices.RefSafetyRulesAttribute`
- `ConfuserExTestApp.Program` (calls row 82 **twice**)
- `ConfuserExTestApp.Greeter`
- `ConfuserExTestApp.Calculator`
- `ConfuserExTestApp.ControlFlowDemo`
- `ConfuserExTestApp.SecretHolder`
- `ConfuserExTestApp.ExtendedPatterns` (prepended to existing .cctor)
- `ObfuscationAttribute`
- `<PrivateImplementationDetails>`
- `<Module>{09D611C0-FB7B-E958-B628-0ADDCF2E3E7D}`

The `<Module>::.cctor` calls both `n8kD0qL3P` (row 82) and `m8DE92F4EC237975`
(trial date check).


## Initialization Method

`n8kD0qL3P` (token 0x06000052, 42 locals): CFF-obfuscated with a 22-case switch
dispatcher plus additional `beq` overflow checks.

Key operations within the CFF:
1. **Builds a 32-byte AES-256 key** using obfuscated constant arithmetic:
   ```
   ldc.i4  63
   ldc.i4  109
   add              // = 172 -> byte[0]
   ```
2. **Loads an encrypted resource stream** by name (ldstr at user string offset 0x70000d1a)
3. **Creates a BinaryReader** and reads the stream:
   - `BinaryReader.ReadInt64()` — offset or size header
   - `Stream.get_Length()` — total stream length
   - `BinaryReader.ReadBytes()` — encrypted data block
4. **Decrypts using AES** via `gEHfEJ9aJKgHNTQig9::tRelL85we1`
5. The decrypted data is used to validate/restore method bodies


## AES Decryption Helper

`gEHfEJ9aJKgHNTQig9::tRelL85we1` (shared with resource encryption):

```
call       Encoding.get_UTF8()
ldarg.0  / callvirt  String.GetBytes()       // key string -> bytes
stloc.0
ldc.i4.s   32
newarr     byte[]
dup
ldtoken    field(row 82)                     // embedded IV from RVA field
call       RuntimeHelpers.InitializeArray()
stloc.1                                      // 32-byte IV from static data
call       Encoding.get_UTF8()
ldarg.1  / callvirt  String.GetBytes()       // derive key bytes
call       internal_hash_method
stloc.2
newobj     RijndaelManaged()                 // AES-256
stloc.3
ldloc.3  / ldloc.1  / set_IV()
ldloc.3  / ldloc.2  / set_Key()
ldloc.3  / callvirt  CreateDecryptor()
newobj     CryptoStream(stream, transform, Read)
// write, flush, read decrypted bytes
callvirt   Stream.ToArray()
ret
```

Uses **RijndaelManaged (AES-256)** with a 32-byte IV from embedded static field data
and a key derived from string arguments.


## Metadata-Token Resolver Type

`YD8k0qML3PKMLfTJjJ.F46Ke0VXdMyeVlwqPE` (TypeDef 0x02000023 in the
current sample; name rotates between builds) — the NR metadata-token
resolver. Caches a `ModuleHandle` in a static field (`nxXPZyx8Ok`) and
exposes typed accessors that resolve raw metadata tokens to runtime
handles at load time. NR's rewriter replaces every user `ldtoken X` in
non-`.cctor` method bodies with `ldc.i4 <raw_metadata_token>; call
accessor(int32)` — denying static analysis the direct type/field/method
reference and gating resolution behind the cached module handle.

**⚠ Previous revisions of this doc incorrectly described the accessors
as `Interlocked.{Exchange,CompareExchange}` tamper-state wrappers; that
was a misreading of the first disassembly pass.** The actual bodies,
verified against the current 7.5.0 sample on 2026-04-24, use the
`ModuleHandle.GetRuntime{Type|Field|Method}HandleFromMetadataToken` BCL
methods — ordinary runtime metadata resolution, not interlocked state.

### .cctor (token 0x060000d5 in current sample)

Resolves the module via reflection and stores it to the static field:

```
ldtoken    TypeDef(this type)
call       Type.GetTypeFromHandle()
callvirt   Type.get_Assembly()
callvirt   Assembly.GetModules()
ldc.i4.0 / ldelem.ref
callvirt   Module.get_ModuleHandle()
stsfld     <static ModuleHandle field>
ret
```

### Accessor methods (4-instruction shape each)

`RFfeRly7o(int32) -> RuntimeTypeHandle` — type-handle accessor:

```
ldsflda    <static ModuleHandle field>
ldarg.0
call       instance ModuleHandle::GetRuntimeTypeHandleFromMetadataToken(int32)
ret
```

`T8QzrqFRj(int32) -> RuntimeFieldHandle` — field-handle accessor:

```
ldsflda    <static ModuleHandle field>
ldarg.0
call       instance ModuleHandle::GetRuntimeFieldHandleFromMetadataToken(int32)
ret
```

A corresponding `GetRuntimeMethodHandleFromMetadataToken` accessor is
not present in the current sample but the detector handles it for
forward compatibility.

Why the fold matters: the `int32` argument is the *raw metadata token
value in the obfuscated assembly* (e.g. `0x01000003` = TypeRef row 3).
After cleanup remaps TypeRef rows, those hard-coded tokens would point
at different types. `TokenResolverPass` resolves each constant-argument
accessor call at deob time by replacing the `Call` with
`LoadToken(Token(raw_int))` — the generic token-remapping cleanup
pipeline then rewrites the `LoadToken`'s token to the correct post-
deobfuscation row, so user code keeps working and the resolver type
itself becomes truly orphan for the cleanup sweep.


## GUID-Annotated Marker Types

Anti-tamper injects GUID-suffixed types as tamper signatures:
- `<Module>{09D611C0-FB7B-E958-B628-0ADDCF2E3E7D}`
- `<PrivateImplementationDetails>{556113CE-EF52-4949-A529-597962C3B69E}`

These serve as integrity markers — their presence and metadata positions are part of
the tamper verification hash.


## Detection Signatures

| Signal | Pattern |
|--------|---------|
| GUID types | `<Module>{GUID}` and `<PrivateImplementationDetails>{GUID}` types |
| `.cctor` fan-in | 5+ types' `.cctor`s converge on a single target method (implemented by `helpers::find_cctor_fan_in_target`) |
| Token-resolver accessor | Static method signature `(int32) -> ValueType` whose body is `ldsflda; ldarg.0; call ModuleHandle.GetRuntime*HandleFromMetadataToken; ret` (implemented by `helpers::find_nr_token_resolver`) |
| AES helper | `SymmetricAlgorithm`/`RijndaelManaged` + 32-byte IV loaded from an RVA field via `RuntimeHelpers.InitializeArray` (currently unused as a detection signal — left for future corroboration) |
| Trial guard | `DateTime(year, month, day)` + `TimeSpan.get_Days()` + 14-day check (owned by `netreactor.antitrial`) |

The landed `netreactor.antitamp` detection requires (all must hold):

1. **Gate**: `<Module>` trial guard present (same NR-context gate as
   `licensecheck` / `privateimpl`).
2. **Primary**: `find_cctor_fan_in_target` returns `Some` (fan-in ≥ 5).
3. **Corroboration**: at least one `<Module>{GUID}` marker type OR one
   `<PrivateImplementationDetails>{GUID}` container is present.


## Deobfuscation Strategy (as implemented)

1. **Mark the init method** (`init_method_token`) for cleanup — this
   causes `NeutralizationPass` to NOP every surviving `call <init>` in
   other method bodies (notably `<Module>::.cctor` and any `.cctor`
   that had the init call prepended to user code).
2. **Mark the runtime container type** (`runtime_type_token` — the
   init method's declaring type) — `expand_type_tokens` cascades to
   its nested types (AES helper, CFF lookup tables, etc.), fields, and
   methods.
3. **Mark purely-injected `.cctor`s** — thin bodies whose *only*
   instruction stream is `call init; ret` (`classify_injected_cctors`
   returns these). Modified `.cctor`s (init call prepended to user
   code) are left in place — the NOP'd call is harmless and the user
   portion survives.
4. **Mark `<Module>{GUID}` marker types** — the generic orphan sweep
   refuses these (no non-cctor methods), so they need explicit
   marking. `<PrivateImplementationDetails>{GUID}` containers are
   already owned by `netreactor.privateimpl`.
5. **Fold metadata-token resolver calls** — `TokenResolverPass`
   (Value phase) rewrites `accessor(<const_int>)` → `LoadToken(Token)`
   for every accessor of the detected resolver type. The resolver
   type itself is marked for cleanup (detection gives its TypeDef
   token) and becomes truly orphan after the fold.

Compare to NRS's `AntiManipulationPatcher` (Stage 3), which searches
for string literals `"is tampered"` / `"Debugger Detected"` and nukes
the entire method body. That is name-fragile and, critically, drops
the runtime metadata-token accessors whether or not the init code is
removed — producing the same typeof-loss symptom we saw before landing
`TokenResolverPass`.

### dotscope Infrastructure Leverage

- **`NeutralizationPass`** — NOPs `call <removed_token>` sites
  (handles the init call in all surviving `.cctor`s and any user
  method that happens to call the init).
- **`expand_type_tokens`** — cascades type-level deletions to nested
  types, methods, fields.
- **`sweep_empty_module_cctor`** — picks up `<Module>::.cctor` once
  the init (and trial) calls are NOP'd.
- **`find_unreferenced_types`** — orphan-sweeps the resolver type
  after `TokenResolverPass` eliminates its only callers.
- **Token remapping / `RidRemapper`** — rewrites the `LoadToken`
  tokens emitted by `TokenResolverPass` through the new TypeRef rows
  during PE regeneration, keeping user `typeof`/`is` correct.
