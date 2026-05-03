# Anti-Tamper Protection (Stage 3)

Analysis of .NET Reactor 7.5.0 anti-tamper protection based on reverse engineering
`reactor_antitamp.exe` (48,640 bytes, 214 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

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


## Anti-Tamper Verification Type

`YD8k0qML3PKMLfTJjJ.F46Ke0VXdMyeVlwqPE` — unique to anti-tamper, provides
thread-safe tamper state tracking:

### .cctor (token 0x060000d5)
Resolves the module via reflection and stores to a static field:
```
ldtoken    TypeDef(row 35)
call       Type.GetTypeFromHandle()
callvirt   Assembly.get_Assembly()
callvirt   Assembly.GetModules()
ldc.i4.0 / ldelem.ref
stsfld     field(row 71)
```

### Thread-Safe State Methods

`RFfeRly7o` (token 0x060000d2): Atomic exchange
```
ldsflda    field(row 71)
ldarg.0
call       Interlocked.Exchange()
ret
```

`T8QzrqFRj` (token 0x060000d3): Atomic compare-and-exchange
```
ldsflda    field(row 71)
ldarg.0
call       Interlocked.CompareExchange()
ret
```

These provide thread-safe tamper state tracking — if tampering is detected during
concurrent type initialization, the state is atomically updated.


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
| .cctor injection | Every type has `.cctor` calling the same target method |
| Interlocked ops | `Interlocked.Exchange`/`CompareExchange` in injected types |
| AES decryption | `RijndaelManaged` + 32-byte IV from `RuntimeHelpers.InitializeArray` |
| Trial guard | `DateTime(year, month, day)` + `TimeSpan.get_Days()` + 14-day check |


## Deobfuscation Strategy

1. **Neutralize the .cctor chain**: Remove injected `.cctor` calls to the init method
2. **Remove verification types**: Delete `YD8k0qML3PKMLfTJjJ.F46Ke0VXdMyeVlwqPE`,
   GUID-annotated types, and the shared runtime infrastructure
3. **Restore modified .cctors**: If a type originally had a `.cctor`, remove the
   prepended `call` to the init method

The NRS `AntiManipulationPatcher` (Stage 3) takes a different approach: it searches
for string literals "is tampered" and "Debugger Detected", then replaces the entire
method body with `ret`. Our approach can use the more reliable pattern of detecting
the `.cctor` injection and GUID marker types.

### dotscope Infrastructure Leverage

- **`NeutralizationPass`**: Can neutralize the anti-tamper check methods
- **Cleanup pipeline**: Orphan type removal handles the injected infrastructure
- **`.cctor` restoration**: Needs a pass to identify and remove prepended init calls
