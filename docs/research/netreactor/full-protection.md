# Full Protection Combination

Analysis of .NET Reactor 7.5.0 with all protections enabled based on
`reactor_full.exe` (142,848 bytes, 381 methods) against `original.exe`
(14,336 bytes, 35 methods).

## File-Level Changes

| Property | Original | Full | Delta |
|----------|----------|------|-------|
| File size | 14,336 | 142,848 | +128,512 (9.97x) |
| TypeDef rows | 13 | ~80+ | ~+67 |
| MethodDef rows | 35 | 381 | +346 |


## Protection Layering Order

.NET Reactor applies protections in a fixed order, as visible from the generation log:

```
1. Examining Code...Done
2. Suppress Decompilation - Step 1...Done    (SuppressIldasm metadata corruption)
3. Obfuscation (Naming Convention -> Standard)...Done  (Symbol renaming)
4. Compress and Encrypt Resources...Done     (Resource encryption, Stage 7)
5. String Encryption...Done                  (String encryption, Stage 6)
6. Anti Tampering...Done                     (Anti-tamper, Stage 3)
7. Control Flow Obfuscation...Done           (CFF, Stage 2)
8. Suppress Decompilation - Step 2...Done    (SuppressIldasm final pass)
9. Encrypt/Convert Code...Done               (NecroBit, Stage 1)
10. Sign Assembly...Done                     (Anti strong name, Stage 12)
11. Final Steps...Done
```

### Deobfuscation Must Reverse This Order

NecroBit (applied last) must be reversed first. Then CFF, then string decryption,
etc. This matches the NRS pipeline order:

```
Stage 1:  NecroBit decryption           (reverse step 9)
Stage 2:  Control flow deobfuscation    (reverse step 7)
Stage 3:  Anti-tamper neutralization    (reverse step 6)
Stage 6:  String decryption             (reverse step 5)
Stage 7:  Resource decryption           (reverse step 4)
Stage 12: Strong name removal           (reverse step 10)
Stage 15: Symbol renaming               (reverse step 3)
Cleanup:  SuppressIldasm metadata repair (reverse steps 2, 8)
```


## Interaction Between Protections

### NecroBit + CFF

NecroBit encrypts ALL method bodies, including those already CFF-obfuscated.
After NecroBit decryption, the CFF-protected methods are revealed with their
switch dispatchers and opaque predicates intact.

### NecroBit + String Encryption

String decryptor methods and the XOR key container initialization are also
NecroBit-encrypted. After body restoration, the string decryption infrastructure
becomes available for analysis.

### CFF + String Encryption

String call sites within CFF-protected methods have their arithmetic expressions
embedded in CFF switch case blocks. The CFF reconstruction must complete before
string call sites can be cleanly identified and resolved.

### Anti-Tamper + NecroBit

Anti-tamper's .cctor injection (calling the initialization method) is present
alongside NecroBit's .cctor injection. The `<Module>::.cctor` calls both the
anti-tamper init AND the NecroBit init. Both must be neutralized during cleanup.

### Resource Encryption + NecroBit

The resource resolver methods are NecroBit-encrypted. Resource decryption only
becomes possible after method body restoration.

### Symbol Renaming + Everything

Renaming is applied before protections, so all injected .NET Reactor types and
the obfuscated original types share the randomized naming space. Detection must
rely on structural patterns, not names.


## Cumulative Infrastructure

The full-protection binary contains the combined infrastructure from all protections:

| From | Types | Methods |
|------|-------|---------|
| NecroBit | Main runtime class (~150 methods), .cctor injection in all types | ~200 |
| String encryption | Decryptor, XOR key container (~90 fields) | ~30 |
| CFF | GUID container type (126 fields), per-type helpers | ~50 |
| Resource encryption | Resolver type, native memory utils | ~40 |
| Anti-tamper | Verification type (Interlocked ops), GUID markers | ~10 |
| Anti strong name | MD5 implementation, DynamicMethod patching | ~20 |
| Shared | Trial guard, delegate proxy, license check, ObfuscationAttribute | ~15 |
| **Total injected** | | **~346** |


## Full-Protection NecroBit Architecture

The NecroBit implementation in the full-protection binary differs significantly from
the necrobit-only binary. The init method is split across multiple methods, and the
body writing mechanism uses different call patterns.

### Module .cctor Call Chain

The `<Module>::.cctor` (`0x06000002`) makes exactly two calls:

1. `0x06000067` at IL offset 0x0005 — Main initialization (fan-in target, called by
   all type .cctors). CFF-protected with 674-case switch, 122 locals, 6199 instructions.
   Handles resource decryption, key derivation, and Hashtable population.
2. `0x0600005C` at IL offset 0x000A — Anti-tamper verification + body patching.
   CFF-protected with 19-case switch, 42 locals, 2288 instructions.

The fan-in detection identifies `0x06000067` as the init method (called by 16+ .cctors).
Method `0x0600005C` is called only from Module .cctor but does the actual body patching.

### Method 0x06000067 — Main Initialization

This is the CFF-protected master initialization method:

- Resolves the module via reflection (`Type.GetTypeFromHandle` + `Assembly.GetModules`)
- Reads encrypted data from embedded managed resources (`GetManifestResourceStream`)
- Decrypts data using custom XOR/shift cipher (element-level `stelem.i1` + `ldelem.u1`)
- Populates a `Hashtable` with decrypted method body records (245 Add calls)
- Sets up VirtualProtect, Marshal.Copy infrastructure for body writing
- Writes CLR method header patches via `Marshal.WriteInt32` (3,770 calls)
- Sets idempotency guard field to prevent re-entry

The Hashtable entries contain per-method decrypted data:
- Key: Int64 (derived from method table pointer address)
- Value: Boxed value type struct with fields:
  - `byte[]` field (decrypted IL code)
  - `bool` field (mode flag controlling patcher behavior)

### Method 0x0600005C — Anti-Tamper + Body Patching

This method has two phases:

**Phase 1: Anti-tamper verification**
- Opens the assembly file via `FileStream` (`C:\Users\...\TestApp.exe` from VirtualFs)
- Reads the file and computes a hash via `HashAlgorithm.TransformBlock/TransformFinalBlock`
- Reads an RSA signature from the file
- Verifies via `RSACryptoServiceProvider.VerifyHash`
- If verification fails, throws `"<AssemblyName> is tampered."`

**Phase 2: Body patching**
- Calls `0x06000063` (VirtualProtect resolver) 152 times — once per method body region
- Calls body patcher method `0x06000063` which:
  - Checks `IntPtr.Size` for 32/64-bit pointer arithmetic
  - Looks up method body in Hashtable by method table address
  - If found: reads bytecode array field, calls `Marshal.Copy` to write body
  - Invokes `VirtualProtect` delegate to make patched memory executable
  - Also uses `Marshal.WriteInt32` for direct method table field writes

### Method 0x06000063 — Body Patcher / VirtualProtect Resolver

NOT CFF-protected (linear flow, 124 instructions, 6 locals).

- Checks field `0x0400003B` for conditional argument selection
- On first call: loads `kernel32.dll`, resolves `VirtualProtect` via `GetProcAddress`,
  creates delegate via `GetDelegateForFunctionPointer`, caches in field `0x04000022`
- Uses `IntPtr.Size` to determine pointer size (4 or 8 bytes)
- Performs Hashtable lookup (`box + callvirt get_Item`) with method address as key
- If hit: reads `byte[]` field (`0x04000040`), `Marshal.Copy` + `Marshal.AllocCoTaskMem`
  to write body to fresh unmanaged memory
- Updates method table pointer via `Marshal.WriteIntPtr` to point to new allocation
- Writes size via `Marshal.WriteInt32`
- Invokes VirtualProtect delegate for memory protection
- Magic constant `216669565` comparison gates a secondary delegate callback (`0x06000128`)

### Key Differences from Necrobit-Only Binary

| Aspect | Necrobit-Only | Full Protection |
|--------|---------------|-----------------|
| Init methods | 1 (fan-in target does everything) | 2 (setup + body patching split) |
| Body patcher args | 6 | 4 |
| Hashtable field | `0x04000020` | Different field offset |
| Byte array field | `0x04000043` | `0x04000040` |
| VirtualProtect field | `0x0400002F` | `0x04000022` |
| Anti-tamper check | None | RSA signature verification |
| Marshal.WriteInt32 calls | ~433 | ~3,770 |
| Hashtable entries | N/A (direct byte array) | 245 per run |
| Body data location | Single byte array on heap | Hashtable entries (per-method) |

### Extraction Strategy (Full Protection)

The necrobit-only extraction finds a single byte array on the heap matching a
structured header format (MethodDef token + group_count + method entries). This
format does NOT exist in the full-protection binary.

For full protection, the decrypted bodies are stored in the Hashtable as per-method
`byte[]` arrays. Two possible extraction approaches:

**A) Hashtable extraction**: After emulation, iterate the Hashtable Dictionary on the
heap. For each entry, the value is a boxed struct with a `byte[]` field containing
the decrypted IL. Requires mapping Int64 keys (method table addresses) back to
MethodDef tokens — possible via PE image RVA-to-address calculation.

**B) Address space extraction**: After emulation, the `Marshal.Copy` writes have
placed decrypted body data at addresses in the AddressSpace. The body patcher
allocates fresh unmanaged memory via `AllocCoTaskMem`, copies the body there, then
updates the method table pointer to point to the new allocation. Reading the
method table entries from the address space can recover the body pointers and data.

### Anti-Tamper Bypass

The anti-tamper verification always fails in emulation because the
`HashAlgorithm.TransformBlock/TransformFinalBlock` hooks return stub data. The
computed hash never matches the RSA signature. Fix: hook
`RSACryptoServiceProvider::VerifyHash` to return `true` (1) during NecroBit emulation.

This bypass is now implemented in `hooks.rs::create_antitamper_bypass_hook()`.


## Deobfuscation Pipeline

The recommended deobfuscation order for the full-protection binary:

1. **Byte-transform phase**: NecroBit decryption (restore all method bodies)
2. **Byte-transform phase**: SuppressIldasm metadata repair (fix Assembly table,
   GUID refs, empty TypeRef)
3. **IL detection**: Identify CFF containers, string decryptors, resource resolvers,
   anti-tamper hooks
4. **SSA phase**: CFF reconstruction (resolve opaque predicates + switch dispatchers)
5. **SSA phase**: String decryption (evaluate call-site arithmetic, emulate decryptor)
6. **SSA phase**: Constant propagation + dead code elimination
7. **Resource phase**: Decrypt and restore encrypted resources
8. **Neutralization**: Remove anti-tamper .cctor injections, anti-debug/anti-strong code
9. **Cleanup**: Remove all injected types, restore sorted tables, fix entry point
10. **Renaming**: Apply smart renaming to recover readable names (irreversible original names)
