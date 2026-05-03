# Anti Strong Name Removal (Stage 12)

Analysis of .NET Reactor 7.5.0 anti-strong-name protection based on reverse engineering
`reactor_antistrong.exe` (35,840 bytes, 152 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

This is the largest injection among individual protections (+117 methods, 150% size
increase), because it includes a complete hand-written MD5 implementation and runtime
strong name verification bypass framework.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 35,840 | +21,504 (150%) |
| TypeDef rows | 13 | 46 | +33 |
| MethodDef rows | 35 | 152 | +117 |
| TypeRef rows | 43 | 98 | +55 (crypto, reflection) |
| Field rows | 26 | 84 | +58 (MD5 state, keys) |
| MemberRef rows | 54 | 158 | +104 |
| Param rows | 24 | 233 | +209 |
| Tables count | 17 | 23 | +InterfaceImpl, FieldMarshal, PropertyMap, Property, MethodSemantics, NestedClass |


## Injected Custom MD5 Implementation

The main runtime class `AoIBWWlDJbaf7LijnA.oMu6jVbdhHEH79DDhU` contains a complete
hand-written MD5 hash implementation (avoiding BCL crypto API detection):

### MD5 Round Functions

| Method | Row | Function | Formula |
|--------|-----|----------|---------|
| `HZsbG4wKP` | 0x06000039 | Round F | `((B & C) \| (~B & D)) + A + X[k] + T[i-1]`, rotate + add |
| `SjKlTCY31` | 0x0600003a | Round G | `((B & D) \| (C & ~D))` |
| `xchyMu6jV` | 0x0600003b | Round H | `(B ^ C ^ D)` |
| `xhHSEH79D` | 0x0600003c | Round I | `(C ^ (B \| ~D))` |
| `nhUVUoIBW` | 0x0600003d | Left-rotate | `(value >> (32 - shift)) \| (value << shift)` |

### MD5 Core Transform

`oYiEKuNrl` (row 0x06000038): Message padding and block processing.
- 512-bit (64-byte) block alignment
- Padding formula: `paddingBits = 448 - (inputLen * 8) % 512; if 0, use 512`
- Output stored to static field `0x04000026`
- Static field `0x0400001c` contains the 64-entry T-table (MD5 constants)


## Cryptographic Provider Detection

`M5uXWySr2` (row 0x06000041): Detects available crypto providers at runtime.
- First tries direct `newobj` instantiation of a crypto provider
- On failure, tries a second provider type
- Final fallback: `Type.GetType(string, string)` via reflection
- Tests multiple type name strings (user string offsets 0x70000b70, 0x70000c0f, 0x70000c7b)
- Casts result to a crypto interface

`obdeEMFWx` (row 0x06000042): Checks if strong name verification is available.
- Tries direct `newobj`, catches exception and sets flag
- Falls back to calling `StrongNameSignatureVerificationEx` or equivalent
- Returns boolean via static field

`aDJMbaf7L` (row 0x0600003e): Lazy initialization wrapper that calls `obdeEMFWx`
once and caches the result.


## Runtime Strong Name Verification Removal

### Primary Removal Method

`xMLhfTJjJ` (row 0x06000047) — 38 locals. This is the core strong name bypass:

1. Loads the target assembly type via `GetType()`
2. Checks a static field for initialization flag
3. Reads an embedded resource stream from a specific type
4. Decrypts/decodes using the custom MD5 implementation
5. Parses with `BinaryReader` (reads pairs of int values)
6. For each entry: resolves a method by metadata token (`0x06000000` range)
7. Creates `DynamicMethod` instances with specific calling conventions
8. Emits IL using `ILGenerator` with a 5-case switch for different `OpCode.Emit` overloads
9. Replaces strong-name-checking method bodies with NOP stubs at runtime

The switch at RVA `0x00003E9A` dispatches between 5 IL emit strategies, then emits a
return instruction. This effectively replaces verification method bodies dynamically.

### Embedded Verification Data Decryption

`gEHfEJ9aJKgHNTQig9::tRelL85we1`: Decrypts the embedded verification data.
- Creates a 32-byte key from token data
- Instantiates a symmetric algorithm (Rijndael/AES)
- Sets key + IV
- Creates encryptor and transforms input bytes

### Assembly Name Resolution

`ArxkjtX8g` (row 0x06000051): Extracts assembly name with 3 fallback strategies:
1. Cast to `AssemblyName`, call `.Name`
2. Call `GetName()`, then `Replace("PublicKeyToken", "")`
3. Call `ToString()`, then `GetMethod("string")` and invoke

All wrapped in try/catch for resilience across .NET versions.


## Deobfuscation Strategy

For static deobfuscation, the anti-strong-name protection can be handled by:

1. **Remove the injected runtime framework**: Delete the 33 injected types and their
   methods (MD5 implementation, crypto detection, DynamicMethod patching)
2. **Remove .cctor hooks**: Clean up calls to the initialization method
3. **Strip strong name if present**: If the assembly was strong-named, strip the
   signature since deobfuscation invalidates it anyway

The NRS `StrongNamePatcher` (Stage 12) takes a simpler approach: it detects methods
with crypto locals (MD5/Rijndael/SymmetricAlgorithm) and a specific call chain pattern
(GetPublicKeyToken -> ToBase64String -> compare), then forces the conditional branch
to the success path. Our cleanup pipeline can simply remove the injected types entirely.
