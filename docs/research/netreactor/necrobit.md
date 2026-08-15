# NecroBit — Method Body Encryption (Stage 1)

Analysis of .NET Reactor 7.5.0 NecroBit protection based on reverse engineering
`reactor_necrobit.exe` (70,144 bytes, 258 methods) against `original.exe` (14,336 bytes,
35 methods) using dotscope disassembly. The named tokens and RVAs throughout are
from that sample; `reactor_full.exe` and `reactor_virtualization_full.exe`
provide the full-protection layout, whose runtime is split across more methods
and whose storage differs (see *Two Operating Modes*).

NecroBit is .NET Reactor's most critical protection. It encrypts all method bodies,
replacing them with stubs. Without reversing NecroBit first, all other deobfuscation
stages operate on encrypted bytecode and produce no results.

Both storage variants are fully supported — see *Support Status* for the
per-sample recovery counts, and *What the Emulator Must Provide* for what
reversing them depends on.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 70,144 | +55,808 (~4.9x) |
| .text section | 0x2E00 (11,776) | 0x10800 (67,584) | +55,808 |
| .rsrc section | 0x600 | 0x600 | unchanged |
| .reloc section | 0x200 | 0x200 | unchanged |
| Metadata RVA | 0x2BEC | 0xAC74 | shifted |
| Metadata size | 7,904 | 26,416 | +18,512 |
| Entry point token | 0x06000003 | 0x06000007 | changed |
| TypeDef rows | 13 | 46 | +33 types |
| MethodDef rows | 35 | 258 | +223 methods |
| TypeRef rows | 43 | 107 | +64 |
| MemberRef rows | 54 | 217 | +163 |
| Field rows | 26 | 84 | +58 |
| Param rows | 24 | 251 | +227 |
| #Strings heap | 2,220 | 9,860 | +7,640 |
| #Blob heap | 900 | 2,876 | +1,976 |
| #US heap | 2,688 | 4,388 | +1,700 |
| Sorted tables mask | 0x000016003301FA00 | 0x0000000000000000 | cleared |
| Methods with bodies | 35 | 216 | 42 without bodies |


## Method Body Encryption Pattern

All original user methods have their bodies replaced with minimal stubs. The stub pattern
depends on the return type:

**Value-type return (int, bool, etc.)**:
```
nop
nop
ldc.i4.0     // push default(T)
ret
```

**Reference-type return (string, object)**:
```
nop
nop
ldnull       // push null
ret
```

**Void return**:
```
nop
nop
nop
ret
```

### Encrypted Method Examples

| Method | Original Body | Stub Body |
|--------|--------------|-----------|
| `Calculator::Add` | `ldarg.1; ldarg.2; add; ret` | `nop; nop; ldc.i4.0; ret` |
| `Calculator::Subtract` | `ldarg.1; ldarg.2; sub; ret` | `nop; nop; ldc.i4.0; ret` |
| `Calculator::Factorial` | Complex recursive body | `nop; nop; ldc.i4.0; ret` |
| `Calculator::Fibonacci` | Complex loop body | `nop; nop; ldc.i4.0; ret` |
| `Calculator::Divide` | Includes try/catch | `nop; nop; ldc.i4.0; ret` |
| `Greeter::SayHello` | String formatting calls | `nop; nop; nop; ret` |
| `SecretHolder::GetApiKey` | Returns constant string | `nop; nop; ldnull; ret` |
| `SecretHolder::DecryptSecret` | XOR decryption logic | `nop; nop; ldnull; ret` |
| `ControlFlowDemo::DemoIfElse` | If/else branching | `nop; nop; nop; ret` |
| `ControlFlowDemo::DemoSwitch` | Switch statement | `nop; nop; nop; ret` |
| `ExtendedPatterns::DemoEmbeddedResources` | Resource loading | `nop; nop; nop; ret` |

**Exception**: `Program::Main` (the entry point, token 0x06000007) is NOT encrypted.
It retains its full body because the runtime needs it to initialize the decryption
infrastructure.


## .cctor Injection

.NET Reactor injects a `.cctor` (static class constructor) into **every type**, including
types that did not originally have one. The original binary had 1 `.cctor`
(`ExtendedPatterns::.cctor`); the protected binary has **17 .cctors**.

All injected .cctors call the same initialization method:
`AoIBWWlDJbaf7LijnA.oMu6jVbdhHEH79DDhU::qp1d5IbOJ` (token 0x0600005c, row 92).

Types that received injected .cctors:
- `<Module>` (also calls `m8DE92F4E878B70C`, row 1)
- `Microsoft.CodeAnalysis.EmbeddedAttribute`
- `System.Runtime.CompilerServices.RefSafetyRulesAttribute`
- `ConfuserExTestApp.Program`
- `ConfuserExTestApp.Greeter`
- `ConfuserExTestApp.Calculator`
- `ConfuserExTestApp.ControlFlowDemo`
- `ConfuserExTestApp.SecretHolder`
- `<PrivateImplementationDetails>`
- `<Module>{09D611C0-FB7B-E958-B628-0ADDCF2E3E7D}`
- `ObfuscationAttribute`
- `AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4`
- `SFU4mbT3GMret7THonf`

The pre-existing `ExtendedPatterns::.cctor` was **modified** to prepend a call to row 92
before its original static array initialization code.

The `<Module>::.cctor` is special: it calls both `qp1d5IbOJ` (row 92) AND
`m8DE92F4E878B70C` (row 1, trial check). Since `<Module>` .cctor runs before any other
code (ECMA-335 Section II.10.5.3), this ensures the decryption infrastructure is
established first.


## Trial/Time-Bomb Check

`<Module>::m8DE92F4E878B70C` (token 0x06000001, RVA 0x2050) is a 14-day trial check:

```
call       Assembly.GetExecutingAssembly()
ldc.i4     2026              // year
ldc.i4     4                 // month (April)
ldc.i4     5                 // day (5th)
newobj     DateTime(int, int, int)
call       DateTime.op_Subtraction
stloc      0
ldloca     0
call       TimeSpan.get_Days()
stloc      1
ldloc      1
ldc.i4     14                // 14 days forward
bgt        -> throw
ldloc      1
ldc.i4     -14               // 14 days backward
bgt        -> ret
ldstr      "Trial expired"
newobj     Exception(string)
throw
```

A second trial check (`UWxvxUSU2ZrCqT9K8B.gttro5yuWySr2hbdEM::g63L7wP2v`, row 256)
exists with a `blt` guard and a static field flag to execute only once. It is called
from `ExtendedPatterns::.cctor`.


## Core Decryption Runtime

### Main Initialization: `qp1d5IbOJ` (token 0x0600005c, row 92)

This is the central NecroBit runtime method and the largest method in the binary:

| Property | Value |
|----------|-------|
| RVA | 0x3A44 |
| Size | ~26,144 bytes (to ~0xA001) |
| Local variables | 120 |
| Switch table entries | 667 |

The method is heavily CFF-protected:
```
ldc.i4     610              // initial state
stloc      100              // state variable
ldloc      100
switch     [667 targets...]  // 667-entry switch table
```

State transitions use XOR/shift arithmetic on the state variable (local 100).
Opaque predicate helpers are used for branch conditions:
- Row 207 (`Nb5ywgep3ylDcaXl81`): `ldnull; ldnull; ceq; ret` = always `true`
- Row 208 (`I7Ssjqa6MqgEUesX2g`): `ldnull; ret` = always `null`


### Crypto Implementation

**Key/IV Derivation** (`oYiEKuNrl`, row 67):
- Operates on byte arrays with 512-bit (64-byte) block alignment
- Padding formula: `paddingBits = 448 - (inputLen * 8) % 512; if 0, use 512`
- Output allocation: `inputLen + paddingBits/8 + 8`
- This is the **MD5/SHA Merkle-Damgard construction padding** scheme

**Block Cipher Decryption** (`TjnwAVttr`, row 75):
- 4 arguments, 17 locals
- Processes data in 4-byte blocks: `div 4`, `rem 4`
- Constructs 32-bit words: `byte[i+3]<<24 | byte[i+2]<<16 | byte[i+1]<<8 | byte[i]`
- Key schedule expansion from key array
- XOR-based decryption of each block

**Resource Stream Decryption** (`xMLhfTJjJ`, row 82):
- 38 locals
- Loads embedded resource via `Type.Assembly.GetManifestResourceStream(name)`
- Reads entire stream into byte array
- Applies block cipher decryption (calls `TjnwAVttr` pattern inline)
- Processes in 4-byte blocks with Merkle-Damgard padding


### Method Body Patcher

`NvQ34uZt895nxEhi2FIr` (row 88, token 0x06000058):
- 6 arguments (`native int, native int, native int, uint32, native int, uint32&`), 6 locals
- Checks `IntPtr.Size` (4 vs 8) for 32-bit vs 64-bit runtime
- Computes method table entry address: `ReadInt32/ReadInt64(ptr, IntPtr.Size * 2)`
- Looks up the Hashtable (field 0x04000020) with the method table address as key
- If found: extracts `F8hvhbdPnO8vvu7JNq.MumlBExyIn` byte[] (field 0x04000043)
- Allocates unmanaged memory via `AllocCoTaskMem(body.Length)`
- Copies body bytes: `Marshal.Copy(body, 0, allocAddr, body.Length)`
- Writes pointer back: `WriteIntPtr(ptr, IntPtr.Size * 2, allocAddr)`
- Writes size: `WriteInt32(ptr, IntPtr.Size * 3, body.Length)`
- Invokes `VirtualProtect` delegate (field 0x0400002F) to make memory executable
- If Hashtable miss: falls through to the VirtualProtect delegate directly

### Value Type `F8hvhbdPnO8vvu7JNq` (token 0x02000019)

Per-method decrypted data container stored in the Hashtable:

| Field | Token | Type | Description |
|-------|-------|------|-------------|
| `MumlBExyIn` | 0x04000043 | `byte[]` | Decrypted method body IL bytes |
| `qP5lgnwPwb` | 0x04000042 | `bool` | Mode flag (controls patcher behavior) |

### VirtualProtect Resolution Chain

.NET Reactor avoids direct P/Invoke to `VirtualProtect` (to prevent detection).
Instead, it resolves and calls VirtualProtect dynamically:

1. **`gEHrfEJaJ`** (token 0x06000066): Loads `kernel32.dll` via `LoadLibrary`
   - Concatenates `"kernel " + "32.dll"` (split to avoid string scanning)
   - Calls `r5dJ1Wps7` (wrapper for `LoadLibrary`)
   - Caches handle in static field 0x04000024
2. **`CXS1O9crd`** (token 0x06000063): Resolves and calls VirtualProtect
   - Concatenates `"Virtual " + "Protect"` (split to avoid string scanning)
   - Calls `zZLUAiZym` (wrapper for `GetProcAddress`)
   - Creates delegate via `Marshal.GetDelegateForFunctionPointer`
   - Caches delegate in static field 0x04000022
   - Calls `Invoke(addr, size, protection, &oldProtect)` on the delegate
   - Called 2600 times during init (once per method body region)
3. **Delegate type** `m7UHHdCo3pOEqhECZW` (token 0x0200001e):
   - Extends `MulticastDelegate`
   - Has `[UnmanagedFunctionPointer(CallingConvention.StdCall)]`
   - Signature: `int32 Invoke(native int, int32, int32, int32&)` — matches
     `BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD)`

### Why the VirtualProtect Return Value Matters

The delegate's return value drives **CFF path selection** inside the init
method, not just the success of the memory-protection call. The init checks it to
decide which switch cases to execute:

- **Returns `TRUE`**: the init proceeds through the Hashtable-population path,
  building the per-method records and writing the decrypted bodies back.
- **Returns anything else** (including a symbolic value, when the call is not
  modelled): the flow takes different branches, skips Hashtable population
  entirely, and falls into a direct-write path whose `Marshal.WriteInt32` calls
  target CLR runtime addresses that do not exist in an emulated process.

So an emulator that cannot resolve this call does not merely lose the protection
change — it steers the protection down a path that produces no usable data at
all. This is why the resolution chain has to be modelled end to end rather than
short-circuited with a plausible return value.

## Injected Type Inventory (33 new types)

| Type | Namespace | Role | Methods |
|------|-----------|------|---------|
| `<Module>` extensions | — | Trial check + init orchestrator | 2 |
| `ObfuscationAttribute` | — | Obfuscation marker attribute | 8 |
| `uy4ZXuP8hhYiKuNrl4` | `AsG4wKEPrjKTCY31dc` | Helper (NecroBit-encrypted) | 3 |
| `SFU4mbT3GMret7THonf` | — | .cctor caller | 1 |
| `oMu6jVbdhHEH79DDhU` | `AoIBWWlDJbaf7LijnA` | **Main runtime class** (~150 methods) | ~150 |
| `P5Jm7BfKKssHPr88Ae` | — | Helper/marker | 1 |
| `fauqjrPN7rkwbb3T2ZV`1` | — | Generic container | 2 |
| `gEHfEJ9aJKgHNTQig9` | — | Helper (NecroBit-encrypted) | 2 |
| `VM792LkqNpj06PcE1F` | — | Data reader/accessor | 5 |
| `gttro5yuWySr2hbdEM` | `UWxvxUSU2ZrCqT9K8B` | Second trial check | 1 |
| `<PrivateImplementationDetails>{...}` | — | Static array data | 1 |
| `<Module>{...}` | — | GUID-tagged module type | 1 |

The main runtime class `oMu6jVbdhHEH79DDhU` contains the decryption engine, crypto
helpers, resource unpacking, CFF infrastructure, and opaque predicate methods.


## Runtime Restoration Flow

At runtime, the NecroBit protection works as follows:

1. **`<Module>::.cctor`** fires first (ECMA-335 guarantee)
2. Calls `qp1d5IbOJ` (main initialization, CFF-protected with 667 switch cases)
3. Calls `m8DE92F4E878B70C` (trial/time-bomb check)
4. `qp1d5IbOJ` performs the full decryption pipeline:
   a. Checks idempotency guard (static bool field 0x04000031) — exits if already run
   b. Sets up the `Hashtable` (field 0x04000020) for method body storage
   c. Obtains module base address via `ProcessModule` reflection chain (NOT
      `Marshal.GetHINSTANCE` — uses `Process.GetCurrentProcess().Modules` iteration
      and `ModuleHandle` reflection)
   d. Reads encrypted method bodies from embedded managed resource via
      `GetManifestResourceStream`
   e. Derives keys using MD5-style padding (`oYiEKuNrl`)
   f. Decrypts using custom XOR/shift block cipher (`TjnwAVttr`)
   g. For each decrypted method body:
      - Creates a `F8hvhbdPnO8vvu7JNq` struct with the decrypted `byte[]`
      - Stores it in the Hashtable via wrapper `g5IZbVJaqsq6omGBSWt` (calls
        `Hashtable.Add(Int64 key, boxed struct)`)
      - The Int64 key is derived from the method table pointer
      - Also directly writes bytes to method table addresses via
        `Marshal.WriteInt32` and wrapper `Xklg21rbD4RmpuGcmR` (calls
        `Marshal.Copy`)
   h. Invokes `VirtualProtect` via delegate to make patched memory executable
   i. Loop terminates when `BinaryReader.ReadInt32` throws `EndOfStreamException`
      (caught by CFF exception handler)
5. When any type is accessed, its `.cctor` calls `qp1d5IbOJ` again (idempotent —
   guard at step 4a returns immediately)
6. On subsequent JIT compilation, the CLR reads the patched method table entries
   and JIT-compiles the restored IL


## Deobfuscation Strategy

### Emulation-Based Approach (dotscope)

Rather than reimplementing the cipher, dotscope runs the protection's own
initialization under emulation and reads the result out of the emulated process.
Both storage variants are recovered this way — see *Support Status*.

1. **Detect** via structural patterns (stub methods, .cctor fan-in, trial check
   pattern, body patcher pattern) — no hardcoded names
2. **Emulate `<Module>::.cctor`** with:
   - Trial check methods bypassed via token-matched hook
   - Anti-tamper RSA check bypassed (`VerifyHash → true`)
   - Injected .cctors bypassed to prevent re-entrancy
   - Full BCL hook coverage for Marshal, Process, Module, crypto, streams
   - Transparent pinned array support for managed/native shared backing
3. **Extract decrypted bodies** via one of two strategies, chosen by variant —
   not "best result wins": the heap path is tried first and the image path is
   the fallback when it declines.
   - **Heap extraction** (variant A): Find a byte array on the managed heap
     matching the NecroBit data format (see Data Format below).
     `find_variant_a_blob` skips `group_count == 0`, because variant B's
     authoritative bodies are in the address space rather than the heap.
   - **PE image extraction** (variant B): Read patched method bodies directly
     from the PE image in the address space. The init method writes decrypted
     bodies to PE RVAs via `Marshal.WriteInt32`, which requires the emulated
     `VirtualProtect` to have made those pages writable.
4. **Store restored bodies**: Use `CilAssembly::store_method_body()` to replace
   stub RVAs with real method body data.
5. **Regenerate PE**: Rebuild the assembly.
6. **Cleanup**: Remove runtime type, injected .cctors, trial check methods.

### Decrypted Data Format (Reversed)

The decrypted byte array has a 24-byte header followed by method body records.
Two variants are identified by the `group_count` field:

**Header** (24 bytes):
```
[0..4]   first_method_token  (table 0x06 = MethodDef)
[4..8]   total_size          (expected total data size)
[8..12]  reserved_1
[12..16] reserved_2
[16..20] group_count         (0 = variant B, >0 = variant A)
[20..24] flags
```

**Variant A** (necrobit-only, `group_count > 0`):
```
Header (24 bytes)
Group entries (group_count × 8 bytes): [RVA(4), LocalVarSig/FatHdr(4)]
Method count (4 bytes)
Per-method: [IL_start_RVA(4), maxstack(4), IL_byte_count(4), IL_bytes...]
```
Group entries provide fat method header metadata (StandAloneSig tokens for
local variable signatures, flags+maxstack words for headerless methods).
The IL_start_RVA is MethodDef.rva + 1 (tiny) or + 12 (fat).

**Variant B** (full-protection, `group_count = 0`):
```
Header (24 bytes)
Per-method: [MethodDef_RVA(4), flags(4), complete_method_body...]
```
Each body is a complete CIL method body (tiny/fat header + code + EH sections),
parseable by `MethodBody::from()`.

### Two Operating Modes

The init method reads a **data format flag** from the decrypted data stream
(`BinaryReader::ReadInt32`). This flag controls which CFF path is taken:

- **Flag = 4** (Variant A / necrobit-only): The init method runs two phases.
  Phase 1 decrypts the encrypted resource into a byte array. Phase 2 creates a
  MemoryStream from the decrypted data and reads method body records into the
  array on the heap. Extraction reads from the heap byte array.

- **Flag = 1** (Variant B / full-protection): The init method runs Phase 1 only,
  writing decrypted method bodies directly to the PE image at each method's RVA
  via `IntPtr` addresses and `Marshal.WriteInt32`. Extraction reads from the PE
  image in the address space.

### Support Status

Both variants are fully recovered.

| Sample | Variant | Stubs | Restored |
|---|---|---|---|
| `reactor_necrobit.exe` | A | 45 | 45 |
| `reactor_necrobit_strings_cff.exe` | A | 56 | 56 |
| `reactor_full.exe` | B | 59 | 59 |
| `reactor_virtualization_full.exe` | B | 562 | 562 |

Asserted per variant by `restores_every_stub_in_a_necrobit_only_binary` and
`restores_every_stub_in_a_full_protection_binary` in `necrobit.rs`. Both count
restored bodies rather than checking that the transform returned `Ok` — a
transform that recovers *some* bodies reports success, so a count is the only
assertion that distinguishes full recovery from partial, or from none.

### What the Emulator Must Provide

NecroBit is decrypted by running the protection's own code, so recovery depends
on the emulator being faithful in a few specific places. Each of these is load
bearing: without it, extraction yields nothing rather than less.

**A working `VirtualProtect`, reached through dynamic resolution.**
Variant B's bodies are written into `.text`, which the PE loader maps
`READ|EXECUTE` from the section characteristics. The write only succeeds because
the protection calls `VirtualProtect` first — and it never declares that
P/Invoke, resolving it through `LoadLibrary`/`GetProcAddress` and calling it
through a delegate (see *VirtualProtect Resolution Chain*). Hook matching keyed
on declared P/Invoke alone therefore never sees it.

dotscope preserves identity across the whole chain: `LoadLibrary` returns a
distinct handle per module, `GetProcAddress` records the resolved function
against that module, `GetDelegateForFunctionPointer` turns the fake address into
a token, and the delegate invocation reconstructs a native call context from it.
The call then runs through the ordinary hook path with its real arguments, so the
`kernel32!VirtualProtect` hook installs a page protection override — the *effect*,
not merely a `TRUE` return value. Returning success without applying the
protection is indistinguishable from working right up until the first write.

**Writes into a mapped-but-unwritable page must report that.**
A write refused on protection is not the same as a write to unmapped memory.
Treating them alike — materialising a fresh region at the enclosing 64KB
boundary — maps over the loaded image, because for an image address that
boundary is the image base. The resulting overlap error names the wrong cause and
is fatal. `AccessViolation` is propagated; only genuinely unmapped addresses are
auto-allocated.

**`IntPtr` values must survive both construction forms.** The body patcher builds
its target addresses through `IntPtr`, from a value-type local (`ldloca + call`)
and from `newobj`. See *IntPtr Construction Forms* below.

**Cleanup must not run ahead of decryption.** A method whose body is still an
encrypted stub contributes no call edges, so everything it references reads as
unreachable. If the transform fails, deleting on that basis removes the original
code — the reason the sample was kept. Techniques report what they could not
restore via `Technique::unrecovered_methods`; cleanup protects those methods,
withholds the failed technique's own request, and skips type-level
unreferenced-type removal, since the call graph cannot then distinguish
unreachable from undecrypted.

### On the Variant B Heap Blob

A blob shaped like the NecroBit data format is present on the managed heap during
a variant-B run, and `is_necrobit_data_array` accepts it. `find_variant_a_blob`
discards it (`group_count == 0`) and extraction reads the address space instead,
which is correct: variant B's authoritative bodies are the ones written into the
image.

Note that the variant-B branch of that shape check is weak — `len >= 36`, a
MethodDef token byte at offset 0, and one method-body header byte at offset 32.
It gates nothing today because variant B never parses from the heap. Anything
that starts parsing heap blobs should validate by walking the record chain
instead: each RVA resolving to a known method, each `MethodBody::from` succeeding,
and the walk terminating at the buffer's end.

### IntPtr Construction Forms

The body patcher computes its write targets through `IntPtr`, reaching the BCL
hooks in two shapes that must both be handled:

1. **`IntPtr.ToInt64` with a `ManagedPointer` as `this`**, from `ldloca + call`
   on a value-type local. The pointer has to be dereferenced to reach the
   `NativeInt` value.

2. **`IntPtr..ctor` with an `ObjectRef` as `this`**, from `newobj` allocating a
   heap object. The value is stored as a synthetic field on that object.

Handling only one of them leaves every `Marshal.WriteInt32` writing to address 0
rather than a PE image RVA, and no bodies are recoverable.

### Comparison with NRS Approach

NRS's `MethodDecrypter` stage:
- Searches for native method signatures to find the decryptor
- Extracts XOR key from `ldind_I8` + `ldc_I8`/`ldc_I4` patterns
- Decrypts the resource and patches method bodies

Our emulation approach avoids reimplementing the proprietary cipher — the
protection's own code does the decryption. This is more robust against cipher
changes between .NET Reactor versions.
