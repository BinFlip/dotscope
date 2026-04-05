# Compressor (Packer)

| Property | Value |
|----------|-------|
| **ID** | `Ki.Compressor` |
| **Short ID** | `compressor` |
| **Type** | Packer (not a Protection) |
| **Pipeline Stage** | Pack stage (runs after all protections) |
| **Dependencies** | Runs last in the pipeline |

## Overview

Packs the protected assembly by compressing and encrypting it into a resource embedded in a minimal stub executable. At runtime, the stub decrypts, decompresses, and loads the original assembly into memory, then transfers execution to the original entry point. This reduces output file size and adds an additional layer of protection.

## Configuration

No user-configurable parameters beyond enable/disable. Uses Normal or Dynamic key derivation internally.

## Architecture

### ExtractPhase (PreStage WriteModule)

1. Identifies the executable module (Console or Windows application)
2. Converts the module to a NetModule (removes the entry point)
3. Records all manifest resources and the original entry point token

### Compressor.Pack() — Stub Generation

Creates a minimal stub assembly that wraps the original:

1. **Stub module creation**:
   - Creates new `ModuleDefUser` with original assembly metadata (runtime version, machine type, DLL characteristics)
   - In compatibility mode: wraps in separate assembly with `.cr` suffix
   - In normal mode: inserts as first module in original assembly

2. **Runtime injection**:
   - Injects `Confuser.Runtime.Compressor` class into stub
   - Injects key derivation logic (Normal or Dynamic deriver)
   - Injects LZMA decompressor reference

3. **Original module embedding**:
   - Original module renamed to `"koi"`
   - Converted to metadata-only format
   - SHA1 hash computed and stored in file table
   - Entry point nullified (stub is now the entry point)

4. **Multi-module handling**:
   - Referenced assemblies encrypted separately
   - Each stored as embedded resource with Base64-encoded name
   - Name derivation: `Base64(XOR(UTF8(assemblyFullName.ToUpperInvariant()), key[4..]))`
   - Hash seed: `0x6fff61`, then iterative multiply-add per byte

## Encryption Algorithm

### Step 1: Key Generation (LCG)

```
s = seed
for i in 0..15:
    s = (s * s) % 0x143FC089
    k[i] = s
    s = (s * s) % 0x444D56FB
    w[i] = s
```

### Step 2: Key Derivation

Apply the key deriver to produce the final 16-element key:

**Normal Deriver**:
```
state = initial_value
for each element:
    select operation based on state % 3:
        0: result = dst ^ src
        1: result = dst * src
        2: result = dst + src
    apply additional transform with 3 random odd constants (k1, k2, k3):
        state = (state * state) % 0x2E082D35
        select based on new state % 3:
            0: result += k1
            1: result ^= k2
            2: result *= k3
```

**Dynamic Deriver**:
- Uses `IDynCipherService` to generate random cipher pair
- Applies cipher operations to key arrays

### Step 3: Byte-level XOR

```
state = seed
for i in 0..data.Length:
    data[i] ^= (byte)state
    if i % 256 == 0:
        state = (state * state) % 0x8A5CB7
```

### Step 4: LZMA Compression

Applies LZMA compression to the XORed data.

### Step 5: Word-level XOR with Key Chaining

```
for each uint32 word at index i:
    encrypted = word ^ key[i % 16]
    key[i % 16] = (key[i % 16] ^ word) + 0x3DDB2819
```

## Data Storage

The encrypted module bytes are stored in:
- A nested `DataType` value type with explicit layout
- A static field with FieldRVA pointing to the data
- Populated at runtime via `RuntimeHelpers.InitializeArray()`

## Key Signature (KeySig)

A 16-byte signature stored as a `StandAloneSig` metadata token:

| Bytes | Content |
|-------|---------|
| 0–3 | Original entry point token (little-endian) |
| 4–15 | Random bytes (bitwise OR with 1 to avoid zeros) |

Used as XOR multiplier for assembly name encoding.

## Runtime Execution

### Main(string[] args)

```csharp
static int Main(string[] args) {
    // 1. Load encrypted module
    uint size = Mutation.KeyI0;                    // Injected buffer size
    uint[] encryptedData = Mutation.Placeholder;   // Injected buffer reference

    // 2. Decrypt
    byte[] decryptedModule = Decrypt(encryptedData, keySeed);

    // 3. Load as module
    Assembly asm = Assembly.GetExecutingAssembly();
    Module mod = asm.LoadModule("koi", decryptedModule);

    // 4. Get original entry point
    int entryToken = /* extracted from KeySig bytes 0-3 */;
    MethodBase entryPoint = mod.ResolveMethod(entryToken);

    // 5. Execute
    object result = entryPoint.Invoke(null, new object[] { args });
    return result is int ? (int)result : 0;
}
```

### Decrypt(uint[] data, uint seed)

```
1. Generate k[], w[] from seed via LCG
2. Apply key derivation (Normal or Dynamic)
3. Reverse word-level XOR with key chaining
4. LZMA decompress
5. Reverse byte-level XOR
6. Return decrypted assembly bytes
```

### Assembly Resolution

Handles loading of referenced assemblies packed as resources:

```csharp
AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => {
    // 1. Compute name hash: 0x6fff61, then iterate
    uint hash = 0x6FFF61;
    foreach (byte b in encodedNameBytes)
        hash = hash * 0x5E3F1F + b;    // Not exact, simplified

    // 2. Look up embedded resource by Base64-encoded name
    // 3. Decrypt and return Assembly.Load(decryptedBytes)
};
```

## Stub Protection

The generated stub is itself protected with a `StubProtection` that adds:
- **InjPhase** (Inspection): Injects key signature verification
- **SigPhase** (BeginModule): Computes SHA1 integrity hash of stub module

## dotscope Handling

Not yet implemented. Would be a pre-processing step: unpack the stub to recover the original assembly, then apply deobfuscation normally.
