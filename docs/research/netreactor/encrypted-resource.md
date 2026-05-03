# Shared EncryptedResource Infrastructure

Multiple .NET Reactor protections share a common encrypted resource mechanism for
storing protected data (method bodies, string tables, resource data, token maps).
This document describes the shared cryptographic infrastructure observed across
all samples.

## Usage Across Protections

| Protection | What's Encrypted | Resource Content |
|-----------|-----------------|------------------|
| NecroBit (Stage 1) | Method bodies | Encrypted IL for all methods |
| String encryption (Stage 6) | String table | All string literals packed as `[len][utf8]` entries |
| Resource encryption (Stage 7) | Assembly resources | Manifest resources (names + data) |
| Anti-tamper (Stage 3) | Validation data | Method body hashes/checksums |
| Anti strong name (Stage 12) | Verification data | Token pairs for DynamicMethod patching |
| Code virtualization | VM bytecode | Custom instruction stream |


## Decryption Components

### AES Decryption: `gEHfEJ9aJKgHNTQig9::tRelL85we1`

Present in every sample with encrypted resources. Uses `RijndaelManaged` (AES-256):

```
call       Encoding.get_UTF8()
ldarg.0  / callvirt  String.GetBytes()     // key string -> bytes
stloc.0
ldc.i4.s   32
newarr     byte[]
dup
ldtoken    field(row N)                    // embedded IV from RVA field
call       RuntimeHelpers.InitializeArray()
stloc.1                                    // 32-byte IV from static data
// ... key derivation ...
newobj     RijndaelManaged()
set_IV(stloc.1)
set_Key(derived_key)
CreateDecryptor()
newobj     CryptoStream(stream, transform, Read)
// write, flush, read
callvirt   Stream.ToArray()                // decrypted bytes
ret
```

**Key observations:**
- IV is 32 bytes, embedded in a static field initialized via `RuntimeHelpers.InitializeArray`
- Key is derived from string arguments (not hardcoded)
- Uses standard `CryptoStream` with `CryptoStreamMode.Read`


### Custom Block Cipher: `TjnwAVttr`

Some protections (NecroBit, strings) also use a custom XOR/shift block cipher,
distinct from AES:

- 4 arguments, 17-25 locals
- Processes data in 4-byte blocks
- Constructs 32-bit words: `byte[i+3]<<24 | byte[i+2]<<16 | byte[i+1]<<8 | byte[i]`
- Key schedule expansion from key array
- XOR-based decryption of each block

String encryption uses TEA/XTEA-variant constants:
`806012376`, `1922674540`, `1503154019`, `172107351`


### MD5-Style Padding: `oYiEKuNrl`

Key/IV derivation uses Merkle-Damgard construction padding:
- 512-bit (64-byte) block alignment
- Padding: `paddingBits = 448 - (inputLen * 8) % 512; if 0, use 512`
- Output: `inputLen + paddingBits/8 + 8`
- Used before the block cipher for key derivation


## Resource Loading Pattern

All protections load encrypted data the same way:

```
ldsfld     <assembly_ref>          // Assembly reference (stored in .cctor)
ldstr      <resource_name>         // resource name from #US heap
callvirt   Assembly.GetManifestResourceStream(string)
// ... create BinaryReader, read structured data ...
// ... decrypt via tRelL85we1 or TjnwAVttr ...
```

The resource name is a string in the #US heap, different per protection.


## Key Derivation Patterns

### Pattern A: CFF-Protected Constant Assembly

Used by anti-tamper and resource encryption. The CFF-protected initialization
method builds a 32-byte key array through obfuscated constant arithmetic:

```
ldc.i4     63
ldc.i4     109
add                    // = 172 -> byte[0]
```

Each byte is computed from 2-4 constant operations. The entire 32-byte key is
statically determinable.

### Pattern B: Field-Embedded Keys

Used by string encryption. The 32-byte IV and key seed are embedded in static
fields initialized via `RuntimeHelpers.InitializeArray` from RVA data.

### Pattern C: XOR Key Container

Used by string encryption call sites. A GUID-suffixed `<Module>` type holds
~90 instance Int32 fields, each a per-call-site XOR key.


## Deobfuscation Approach

### Emulation-Based (Recommended)

Run the `.cctor` chain through the emulation engine:
1. Module .cctor initializes the decryption infrastructure
2. Emulate key derivation and AES/cipher setup
3. Intercept `GetManifestResourceStream` to provide the actual resource data
4. Capture the decrypted output

This avoids reimplementing the proprietary cipher variants.

### Static Extraction

For protections where emulation is too complex:
1. Extract the embedded resource directly from the PE
2. Extract the IV from the RVA field data
3. Extract the key from the CFF-protected method (constant propagation)
4. Implement AES-256-CBC decryption (standard, well-known)
5. Handle the TEA/XTEA variant for string encryption


## NRS Comparison

NRS's `EncryptedResource` class (~1,320 lines) handles 4 decrypter variants:

| NRS Variant | Detection | Scheme |
|-------------|-----------|--------|
| V1 (Classic AES) | CryptoStream + ICryptoTransform locals | AES-CBC, 32-byte key/IV from `InitialValue` |
| V2 (Rolling XOR) | Int32 + Byte[] locals | XOR with rolling sum |
| V3 | Variant of V2 | Rolling XOR variant |
| V4 | Extended pattern | More sophisticated |

Our analysis confirms V1 (AES) is the primary scheme in .NET Reactor 7.5.0,
with the custom TEA/XTEA cipher as an additional layer for string encryption.
