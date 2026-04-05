# String Hiding

| Property | Value |
|----------|-------|
| **Protection** | String Hiding (`StringSqueeze`) |
| **Class** | `Obfuscator` (inline implementation) |
| **Category** | Value (string encryption) |
| **Targets** | Method instructions (`ldstr`) |
| **Configuration** | `HideStrings`, `SkipStringHiding`, `ForceStringHiding` |
| **Dependencies** | Runs first in pipeline (step 2), before all renaming steps |

## Overview

Replaces all string literals with calls to per-string accessor methods in an injected helper class. The string data is stored as a UTF-8 byte array encrypted with a simple XOR cipher using the byte index and a fixed constant (`0xAA`). At runtime, a static constructor decrypts the byte array once, and individual accessor methods extract and cache specific strings on demand.

## Injected Type Structure

```
<PrivateImplementationDetails>{GUID}           — Helper class (CompilerGenerated)
├── 1{GUID}/2                                  — Nested struct (ExplicitLayout, packed)
│   └── Field with HasFieldRVA                 — Encrypted byte data source
├── Field "3" (static)                         — RVA field referencing the nested struct
├── Field "4" (static, byte[])                 — Runtime byte array (decrypted data)
├── Field "5" (static, string[])               — String cache array
├── Method "6" (static, private)               — Shared string getter: UTF8.GetString()
├── Method "A" (static, public)                — Per-string accessor for string #0
├── Method "B" (static, public)                — Per-string accessor for string #1
├── ... more per-string accessors
└── .cctor                                     — Static constructor (XOR decryption loop)
```

The helper class name follows the pattern `<PrivateImplementationDetails>{GUID}` where the GUID is derived from the assembly. Method names for per-string accessors use the configured character set (`A`, `B`, `a`, `Ab`, etc.).

## Encryption Algorithm

### Obfuscation-Time Encryption

All unique string literals are collected, UTF-8 encoded, and concatenated into a single byte array. Each string's offset and length within the array are recorded. The byte array is then XOR-encrypted:

```csharp
for (int i = 0; i < data.Length; i++)
    data[i] = (byte)(data[i] ^ (byte)i ^ 0xAA);
```

Each byte is XORed with two values:
1. Its position index (truncated to byte: `(byte)i`)
2. The constant `0xAA` (170, binary `10101010`)

The encrypted byte array is stored as a FieldRVA in the nested struct.

### Runtime Decryption (Static Constructor)

The `.cctor` performs the reverse XOR operation to decrypt the byte array at class initialization:

```cil
// Allocate working arrays
newarr     System.String              // string cache array → field "5"
stsfld     string[] ::"5"
newarr     System.Byte               // byte array → field "4"
stsfld     uint8[] ::"4"

// Copy encrypted RVA data to working array
ldsfld     uint8[] ::"4"
ldtoken    field valuetype '1{GUID}'/2 ::"3"
call       void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class System.Array, valuetype System.RuntimeFieldHandle)

// XOR decryption loop
ldc.i4.0
stloc.0                               // i = 0
loop:
    ldsfld     uint8[] ::"4"
    ldloc.0                            // i
    ldsfld     uint8[] ::"4"
    ldloc.0
    ldelem.u1                          // data[i]
    ldloc.0                            // i
    xor                                // data[i] ^ i
    ldc.i4     0xAA                    // 0xAA
    xor                                // ^ 0xAA
    conv.u1
    stelem.i1                          // data[i] = result
    ldloc.0
    ldc.i4.1
    add
    stloc.0                            // i++
    ldloc.0
    ldsfld     uint8[] ::"4"
    ldlen
    conv.i4
    clt
    brtrue     loop                    // while i < data.Length
ret
```

## Per-String Accessor Methods

Each unique string gets a dedicated static method with lazy caching:

```cil
// Method "A" — accessor for string #0
ldsfld     string[] <PrivateImplementationDetails>{GUID}::"5"
ldc.i4     <stringIndex>              // index into cache array
ldelem.ref
dup
brtrue.s   IL_ret                     // if already cached, return it
pop
ldc.i4     <stringIndex>              // cache index
ldc.i4     <byteOffset>              // offset into decrypted byte array
ldc.i4     <byteLength>              // UTF-8 byte length
call       string <PrivateImplementationDetails>{GUID}::"6"(int32, int32, int32)
IL_ret:
ret
```

## Shared String Getter (Method "6")

The shared getter extracts a substring from the decrypted byte array using UTF-8 encoding:

```cil
// Method "6": string(int32 cacheIndex, int32 offset, int32 length)
call       class System.Text.Encoding System.Text.Encoding::get_UTF8()
ldsfld     uint8[] <PrivateImplementationDetails>{GUID}::"4"
ldarg.1                                // byte offset
ldarg.2                                // byte length
callvirt   string System.Text.Encoding::GetString(uint8[], int32, int32)
stloc.0
ldsfld     string[] <PrivateImplementationDetails>{GUID}::"5"
ldarg.0                                // cache index
ldloc.0
stelem.ref                             // cache[index] = decoded string
ldloc.0
ret
```

## Call Site Transformation

Each `ldstr` instruction in the original code is replaced with a call to the corresponding accessor method:

```
// Before:
ldstr      "Hello, World!"

// After:
call       string <PrivateImplementationDetails>{GUID}::A()
```

The accessor method is static, parameterless, and returns `string`.

## Configuration

| Setting | Default | Scope | Description |
|---------|---------|-------|-------------|
| `HideStrings` | `true` | Global | Enable/disable string hiding for all assemblies |
| `SkipStringHiding` | — | Per-type/method rule | Exclude specific types/methods from string hiding |
| `ForceStringHiding` | — | Per-type/method rule | Force string hiding even if type/method is otherwise skipped |

Type-level skip rules support the `skipStringHiding` attribute in the `TypeAffectFlags` bitmask (bit 0x10).

## Key Observations

- The XOR encryption is trivially reversible — the key is deterministic (byte index + `0xAA`)
- All strings from the assembly are concatenated into a single byte array, making it easy to extract all strings at once after decryption
- The lazy caching pattern (check cache → call getter → store) means strings are only decoded once per accessor
- UTF-8 encoding means multi-byte characters are correctly handled
- The injected type name `<PrivateImplementationDetails>{GUID}` mimics compiler-generated types, providing mild camouflage

## Detection Signatures

- **Type name pattern**: `<PrivateImplementationDetails>{GUID}` (namespace starts with `<PrivateImplementationDetails>{`)
- **Structural signature**: Nested `ExplicitLayout` struct with a static field named `"3"` having `HasFieldRVA`, plus static fields `"4"` (byte array) and `"5"` (string array)
- **Method "6" signature**: `string(int32, int32, int32)` — shared string getter
- **Multiple parameterless string-returning methods**: 5+ static methods with no parameters returning `string` in the same type
- **XOR pattern in `.cctor`**: `xor` / `ldc.i4 0xAA` / `xor` sequence in the decryption loop

## dotscope Handling

Handled by `ObfuscarStrings` technique (detection + decryptor registration) feeding into the shared `DecryptionPass` (emulation-based reversal). The technique extracts the XOR key byte from the `.cctor` bytecode, registers the `.cctor` as a warmup method, and registers all per-string accessor methods as decryptors. After emulation, call sites are replaced with constant `ldstr` instructions and the injected helper type is removed during cleanup.
