# String Encryption (Stage 6)

Analysis of .NET Reactor 7.5.0 string encryption based on reverse engineering
`reactor_strings.exe` (60,416 bytes, 175 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 60,416 | +46,080 (4.2x) |
| .text section | 0x2E00 | 0xE200 | +45,568 (4.9x) |
| Metadata size | 7,904 | 23,904 | +15,998 (3x) |
| TypeDef rows | 13 | 47 | +34 |
| MethodDef rows | 35 | 175 | +140 |
| Field rows | 26 | 189 | +163 |
| MemberRef rows | 54 | 175 | +121 |
| #Strings heap | 2,220 | 11,580 | +9,360 (5.2x) |
| **#US heap** | **2,688** | **1,500** | **-1,188 (0.56x)** |
| #Blob heap | 900 | 2,468 | +1,568 (2.7x) |
| Entry point | 0x06000003 | 0x06000005 | shifted |
| Methods with bodies | 35 | 133 | +98 |

Key observation: The **#US heap shrinks** from 2,688 to 1,500 bytes. String literals
were removed from the user string heap and encrypted into an embedded resource.


## Call-Site Transformation

Every `ldstr` instruction is replaced with an arithmetic expression that computes an
index, XORs it with a per-call-site key, and calls the decryptor:

**Original** (`SecretHolder::GetApiKey`):
```
ldstr      "SK-12345-ABCDE-67890"
ret
```

**Protected**:
```
ldc.i4     587450816              // constant A
neg                                // arithmetic obfuscation
ldc.i4     -908162384             // constant B
xor                                // A ^ B -> intermediate
ldsfld     0x040000ba             // load XOR key container singleton
ldfld      0x04000063             // load per-call-site key (instance field)
xor                                // intermediate ^ per_site_key -> string index
call       iX38Xvt6D(int32)      // decryptor -> string
ret
```

### Three-Layer Obfuscation

1. **Arithmetic obfuscation**: The string index is computed via 2-4 operations
   (`add`, `sub`, `xor`, `neg`, `not`, `shl`, `shr`) on obfuscated constants
2. **Per-call-site XOR key**: Each call site loads a *different* instance field from
   the key container (`0x040000ba`). Every string reference uses a unique XOR key
   (fields at rows 99, 130, 132, 134, 146, 162, etc.)
3. **Single decryptor entry**: All sites call `iX38Xvt6D` (token `0x0600004c`, row 76)
   with signature `string(int32)`


## XOR Key Container

**Type**: `<Module>{b83948b0-5a3e-4632-b1da-238626dd6db0}` (GUID-suffixed)

**Singleton**: Static field `0x040000ba` (row 186)

**Initialization** (`k07c5fa791abe46909bf096e4973f1761`, token `0x060000af`):
- Called from the type's `.cctor`
- Creates the container instance and stores to `0x040000ba`
- Initializes **~90 instance fields** with per-call-site XOR keys
- Each key computed through obfuscated constant arithmetic

Example initialization:
```
newobj     <container .ctor>
stsfld     0x040000ba              // store singleton
ldsfld     0x040000ba              // load it
ldc.i4     -966327232              // obfuscated computation
ldc.i4     907602648
sub
ldc.i4     1605286114
sub
ldc.i4     1636171570
xor
stfld      0x04000066              // store key for field row 102
```

All values are constant — the entire key container is statically determinable.


## Decryptor Method: `iX38Xvt6D`

**Token**: `0x0600004c` (row 76)
**Class**: `AoIBWWlDJbaf7LijnA.oMu6jVbdhHEH79DDhU`
**Signature**: `string(int32)`
**Locals**: 12

### Algorithm

1. **Initialization check** (first call only):
   - Checks if decrypted buffer (`0x0400002d`, byte array) has content
   - If empty: loads encrypted resource via `Assembly.GetManifestResourceStream(name)`
   - Calls `gEm2r20hb` (row 75) for stream processing
   - Decrypts using custom TEA/XTEA cipher + AES

2. **Integrity check**:
   - Counter field `0x04000036` checked against threshold 75
   - Performs AppDomain/assembly name verification

3. **Cache lookup** (with `Monitor.Enter` locking):
   - Computes index from input: `BitConverter.ToInt32(buffer, arg0)`
   - Checks cache (`Hashtable` at `0x04000038`)
   - Cache hit: returns cached string

4. **Decrypt on miss**:
   - Timestamp/trial check via `EJgIj6AlD`
   - Extracts byte slice: `Array.Copy(buffer, arg0 + 4, ...)`
   - Decodes: `Encoding.UTF8.GetString(bytes)`
   - Caches result in `Hashtable`

5. **Fallback**: Returns empty/error string on exception

### String Buffer Format

The decrypted buffer is a flat byte array. Each string entry:
```
[offset + 0..3]  int32 length (little-endian)
[offset + 4..4+length-1]  UTF-8 encoded string data
```

The `int32` argument to the decryptor is the **byte offset** into this buffer.


## Cryptographic Infrastructure

### Custom TEA/XTEA-Variant Cipher

`TjnwAVttr` (token `0x06000040`, row 64): 4 arguments, 25 locals.
- Uses constants `806012376`, `1922674540`, `1503154019`, `172107351`
  (characteristic TEA/XTEA round constants)
- Barrel shifts: `shl`/`shr.un` by 5, 8, 9, 10, 25, 27
- XOR mixing with divide-add rounds
- Output stored in static field `0x0400002d` (the decrypted byte buffer)

### MD5-Style Padding

`oYiEKuNrl` (token `0x06000038`, row 56): 1 argument, 20 locals.
- Padding formula: `(448 - (len * 8 % 512) + 512) % 512`
- Creates expanded buffer with Merkle-Damgard-style padding
- Used for key derivation before the block cipher

### AES Decryption

`gEHfEJ9aJKgHNTQig9::tRelL85we1` (token `0x06000083`, row 131):
- Creates 32-byte key from `RuntimeFieldHandle` (embedded RVA data)
- `RijndaelManaged` with `CreateDecryptor`
- `CryptoStream` for streaming decryption
- Shared with anti-tamper and resource encryption stages


## Initialization Chain

```
<Module>::.cctor
  -> m8DE92F4E936DC22          Trial check (DateTime 2026-04-05, +/-14 days)

AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4::.cctor
  -> EJgIj6AlD                 Timestamp verification
  -> ldtoken + GetTypeFromHandle + Assembly -> stsfld 0x04000019  (Module ref)

AoIBWWlDJbaf7LijnA.oMu6jVbdhHEH79DDhU::.cctor
  -> Initializes ~30 static fields (flags, counters, caches, crypto state)
  -> ldtoken + Assembly -> stsfld 0x0400003a  (Assembly ref for resource loading)
  -> Initializes 64-byte array from RuntimeFieldHandle (AES key/IV)
  -> Creates Monitor locks, Hashtable, etc.

<Module>{b83948b0-...}::.cctor
  -> k07c5fa791abe46909bf096e4973f1761  (XOR key container init, ~90 fields)
```


## Detection Signatures

| Signal | Pattern |
|--------|---------|
| Call-site rewrite | `ldstr` replaced with `ldc.i4; [arith]; ldsfld; ldfld; xor; call decryptor` |
| Decryptor method | Signature `string(int32)` in injected type, contains `GetManifestResourceStream` |
| XOR key container | `<Module>{GUID}` type with 90+ Int32 instance fields |
| #US heap shrinkage | Protected #US heap smaller than original |
| TEA/XTEA constants | `806012376`, `1922674540`, `1503154019`, `172107351` in cipher method |


## Deobfuscation Strategy

### Approach A: Emulation-Based (Recommended)

1. **Register the decryptor**: Detect `string(int32)` signature in the main runtime type
2. **Warmup**: Run `.cctor` chain through emulation to initialize crypto state
3. **Per-call-site resolution**:
   - Evaluate the arithmetic expression + XOR to get the int32 index
   - Call the decryptor via emulation to get the plaintext string
   - Replace the entire sequence with `ldstr <plaintext>`
4. **Cleanup**: Remove the decryptor type, XOR key container, encrypted resource

This approach works with the existing `DecryptionPass` infrastructure — register the
decryptor method, let emulation handle the crypto.

### Approach B: Static Decryption

1. **Extract the encrypted resource** from the managed resource stream
2. **Evaluate the XOR key container** (all constant arithmetic)
3. **Decrypt the resource**: Implement the TEA/XTEA cipher + AES decryption
4. **Map call sites**: Evaluate each call site's arithmetic to get the buffer offset
5. **Read strings**: Parse the `[length][utf8_data]` format at each offset

This avoids emulation but requires reimplementing the proprietary cipher.

### dotscope Infrastructure Leverage

- **`DecryptionPass`**: Register the `string(int32)` decryptor, emulate warmup + calls
- **`generic.strings` detection**: The `string(int32)` signature already matches NR's
  decryptor shape
- **Emulation engine**: AES BCL support (`crypto/symmetric.rs`) handles RijndaelManaged
- **Constant propagation**: Can resolve the arithmetic expressions at call sites
