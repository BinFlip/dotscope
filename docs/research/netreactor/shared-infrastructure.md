# Shared .NET Reactor Infrastructure

Every .NET Reactor-protected assembly (regardless of which protections are enabled)
injects the same baseline infrastructure. This document catalogs these shared components,
which are consistent across all 18 test samples.

## Baseline Injection (Present in ALL Samples)

### 1. Trial Guard: `<Module>::m8DE92F4E*`

Every sample has a module-level static method with name prefix `m8DE92F4E` (suffix
varies per build configuration — likely a hash of the build settings).

**Pattern** (identical logic, different method names per sample):
```
call       Assembly.GetExecutingAssembly()
ldc.i4     2026              // build year
ldc.i4     4                 // build month
ldc.i4     5                 // build day
newobj     DateTime(int, int, int)
call       DateTime.op_Subtraction   // now - buildDate
stloc      0
ldloca     0
call       TimeSpan.get_Days()
stloc      1
ldloc      1
ldc.i4     14                // forward threshold
bgt        -> throw
ldloc      1
ldc.i4     -14               // backward threshold
bgt        -> return
ldstr      "Trial expired"
newobj     Exception(string)
throw
```

**Detection signature**: Static method on `<Module>` with name starting `m8DE92F4E`,
containing `DateTime` construction + `TimeSpan.get_Days()` + comparison against `14`/`-14`.

### 2. Module .cctor

`<Module>::.cctor` calls the trial guard. In samples with additional protections (e.g.,
NecroBit), it also calls the main decryption initialization method.

### 3. Delegate Proxy: `AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4`

The namespace (`AsG4wKEPrjKTCY31dc`) and type name (`uy4ZXuP8hhYiKuNrl4`) are
**identical across ALL samples** — they are deterministic per .NET Reactor version,
not per build. Only the method name within the type varies per build.

**Delegate resolution pattern**:
```
ldsfld     <module reference field>
ldarg.0
ldc.i4     0x02000000        // TypeDef token prefix
add                          // arg + 0x02000000 = TypeDef token
call       Module.ResolveType(int)
callvirt   Type.GetMethods()
// iterate methods...
ldarg.1
ldc.i4     0x06000000        // MethodDef token prefix
add                          // arg + 0x06000000 = MethodDef token
call       Module.ResolveMethod(int)
// create delegate and invoke
call       Delegate.CreateDelegate(Type, MethodInfo)
callvirt   Delegate.Invoke(...)
```

This hides direct method calls behind reflection-resolved delegate indirection.
Arguments are token offsets (without table prefix), and the proxy adds the table
prefix at runtime.

**Detection signature**: Method containing `ldc.i4 0x02000000` + `add` followed by
`Module.ResolveType`, and `ldc.i4 0x06000000` + `add` followed by `Module.ResolveMethod`.

### 4. License Check: `UWxvxUSU2ZrCqT9K8B.gttro5yuWySr2hbdEM`

Also deterministic namespace/type names across all samples. Contains a method with
the same trial guard logic as `<Module>::m8DE92F4E*` but with:
- A static boolean field guard (`sfld 0x0400000c`) to execute only once
- Called from `ExtendedPatterns::.cctor` (or similar user type .cctor)

### 5. ObfuscationAttribute

Injected in most samples (unless the original already has it). Full attribute class
with properties: `ApplyToMembers`, `Exclude`, `Feature`, `StripAfterObfuscation`.
8-10 methods (getters/setters + .ctor + .cctor).


## Stable Type Name Detection

The following namespace/type names are **stable across all .NET Reactor 7.5.0 samples**
and can be used as detection signatures:

| Namespace | Type | Role |
|-----------|------|------|
| `AsG4wKEPrjKTCY31dc` | `uy4ZXuP8hhYiKuNrl4` | Delegate proxy resolution |
| `UWxvxUSU2ZrCqT9K8B` | `gttro5yuWySr2hbdEM` | Runtime license/date check |
| `AoIBWWlDJbaf7LijnA` | `oMu6jVbdhHEH79DDhU` | Main decryption runtime (NecroBit, anti-strong) |

These names likely change between .NET Reactor versions but are deterministic within
a version.


## Common Metadata Changes

All protected samples share these metadata mutations:

1. **Sorted tables bitmask cleared**: Set to `0x0000000000000000` (all zeros). The
   original has `0x000016003301FA00`. This means .NET Reactor does NOT sort metadata
   tables, which is technically valid but unusual.

2. **Entry point token shifted**: Changes from original (typically `0x06000003`) to a
   higher row number due to injected methods.

3. **New metadata tables added**: Varies by protection, but commonly adds InterfaceImpl,
   FieldMarshal, PropertyMap, Property, MethodSemantics, NestedClass tables.


## Cleanup Strategy

For any .NET Reactor deobfuscation, the baseline cleanup is:

1. **Remove trial guard**: Delete `<Module>::m8DE92F4E*` and its .cctor call
2. **Remove delegate proxy type**: Delete `AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4`
3. **Remove license check type**: Delete `UWxvxUSU2ZrCqT9K8B.gttro5yuWySr2hbdEM`
4. **Remove ObfuscationAttribute**: Delete if injected (not originally present)
5. **Restore sorted tables**: Re-sort metadata tables per ECMA-335 requirements
6. **Fix entry point**: Adjust if needed after method removal
