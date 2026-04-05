# Constants Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.Constants` |
| **Short ID** | `constants` |
| **Preset** | Normal |
| **Targets** | Methods |
| **Pipeline Stages** | InjectPhase: PreStage ProcessModule; EncodePhase: PostStage ProcessModule |
| **Dependencies** | Must run before `Ki.ControlFlow`, must run after `Ki.RefProxy` |

## Overview

Extracts literal constants (strings, integers, longs, floats, doubles, array initializers) from method bodies, encodes them into a compressed and encrypted buffer, and replaces the original instructions with calls to a decoder method. Three encoding modes provide increasing levels of protection for the ID-to-constant mapping.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `mode` | `Normal`, `Dynamic`, `x86` | `Normal` | Decoder complexity |

## Architecture

The protection operates in two phases:

### Phase 1: InjectPhase

Injects the runtime decoder infrastructure into the target module:

1. **Decompressor injection**: Gets LZMA decompressor from `ICompressionService`, injects into global type
2. **Helper injection**: Injects `Confuser.Runtime.Constant` type into global type
3. **Data structure creation**: Creates an explicit-layout `ValueType` with a static field for storing the encrypted buffer (uses FieldRVA)
4. **Decoder instantiation**: Creates N copies (default 5) of the `Get<T>()` generic decoder method, each with:
   - Randomized type IDs: `StringID`, `NumberID`, `InitializerID` (each 0–3, all different)
   - Mode-specific decoder logic injected via `ModeHandler.CreateDecoder()`
5. **Initialize mutation**: Patches the `Initialize()` method:
   - Replaces `Mutation.Crypt()` calls with mode-specific decryption IL
   - Replaces `Lzma.Decompress()` calls with actual decompressor method
6. **Module integration**: Inserts `call Initialize` at position 0 of module `.cctor`

### Phase 2: EncodePhase

Extracts and encodes all eligible constants:

1. **Constant extraction**: Scans all method bodies for eligible instructions
2. **Buffer construction**: Encodes constants into a `List<uint>` buffer
3. **Buffer encryption**: XOR-based block encryption with key chaining
4. **Reference patching**: Replaces original instructions with decoder calls

## Eligible Constants

| Type | Instruction | Condition |
|------|------------|-----------|
| Strings | `ldstr` | Non-empty strings |
| Int32 | `ldc.i4` | Value not in [-1, 8] (unless Primitive flag set) |
| Int64 | `ldc.i8` | Value not in [-1, 1] |
| Float32 | `ldc.r4` | Value not in {-1, 0, 1} |
| Float64 | `ldc.r8` | Value not in {-1, 0, 1} |
| Arrays | `RuntimeHelpers.InitializeArray()` | Primitive element type with valid RVA data |

Array initializers are detected by the pattern:
```
ldc.i4    <length>
newarr    <elementType>
dup
ldtoken   <rvaField>
call      RuntimeHelpers.InitializeArray
```

## Buffer Format

### Encoding Layout

All values are stored as `uint32` elements:

| Type | Format | Layout |
|------|--------|--------|
| String | UTF-8 bytes | `[length:u32] [utf8_data:u32...]` |
| Int32/Float32 | Direct value | `[value:u32]` |
| Int64/Float64 | Split value | `[lo:u32] [hi:u32]` |
| Array | Prefixed data | `[total_bytes:u32] [element_count:u32] [data:u32...]` |

Byte arrays are packed into `uint32` elements (little-endian, last element zero-padded if needed).

### Compression Pipeline

1. Convert `List<uint>` to byte array (little-endian)
2. Compress with LZMA
3. Pad to 16-uint32 alignment (fill with zeros)

### Encryption

**Key derivation** (XorShift32):

```
state = keySeed  (random 32-bit value)
for i in 0..15:
    state ^= state >> 12
    state ^= state << 25
    state ^= state >> 27
    key[i] = state
```

**Block encryption**:

```
for each 16-uint block at offset:
    encrypted[0..15] = ModeHandler.Encrypt(buffer[offset..offset+15], key[0..15])
    key[j] ^= encrypted[j]  for j in 0..15   // Key chaining
```

The encrypted buffer is stored in a static field with FieldRVA.

## ID Encoding Scheme

Each constant reference is encoded as a 32-bit ID:

| Bits | Field |
|------|-------|
| 0–29 | Buffer index (byte offset / 4) |
| 30–31 | Type ID (StringID, NumberID, or InitializerID) |

The type IDs are randomized per decoder instance (each assigned a unique value 0–3).

The ID is further transformed by the mode-specific encoder before being embedded in IL.

## Encoding Modes

### Normal Mode

**ID encoding**: Multiplicative cipher with XOR:

```csharp
// Protection time (Encode):
encoded_id = (id ^ k2) * k1    // k1 is random odd number, k2 is random

// Runtime (decoder stub IL):
decoded_id = input * modInverse(k1)    // Multiplicative inverse
decoded_id = decoded_id ^ k2
```

**Buffer encryption**: Simple XOR:

```csharp
for i in 0..15:
    result[i] = data[offset + i] ^ key[i]
```

### Dynamic Mode

**ID encoding**: Same as Normal mode (multiplicative + XOR)

**Buffer encryption**: Uses `IDynCipherService` to generate a random cipher pair:
- Forward cipher compiled as .NET delegate (used at protection time)
- Inverse cipher emitted as CIL (injected into `Initialize()` method)

See [DynCipher](dynciper.md) for details on cipher generation.

### x86 Mode

**ID encoding**: Expression-based with native x86 decoder:
1. Generates a DynCipher expression pair
2. Compiles the inverse expression to x86 machine code
3. Creates a native method (`PinvokeImpl | Native | Unmanaged | PreserveSig`)
4. Decoder stub calls the native method to decode the ID
5. Forward expression compiled as .NET delegate for protection-time encoding

**Buffer encryption**: Uses DynCipher (same as Dynamic mode)

Removes `ILOnly` flag from PE, same as the x86 predicate in Control Flow.

## Runtime Decoder

### Initialize() Method

Called from module `.cctor` before any user code:

```
1. Read buffer length from injected key
2. Load encrypted buffer via RuntimeHelpers.InitializeArray()
3. Derive 16-element key from seed via XorShift32
4. Decrypt in 16-uint blocks:
   for each block:
       w[0..15] = buffer[offset..offset+15]
       Mutation.Crypt(w, key)    // Mode-specific decryption
       Convert w to bytes (little-endian)
       key[j] ^= w[j]           // Key chain update
5. LZMA decompress → store in static field 'b'
```

### Get\<T\>(int id) Method

Generic decoder called at each constant use site:

```csharp
static T Get<T>(int id) {
    // Anti-tampering: verify caller is same assembly
    if (!Assembly.GetExecutingAssembly().Equals(Assembly.GetCallingAssembly()))
        return default(T);

    // Mode-specific ID decode (injected via Mutation.Placeholder)
    id = Mutation.Placeholder(id);

    // Extract type from top 2 bits
    int t = (int)((uint)id >> 30);
    id = (id & 0x3FFFFFFF) << 2;   // Buffer byte offset

    if (t == StringID) {
        // Read UTF-8: [length:4] [data:length]
        int len = buffer[id] | (buffer[id+1]<<8) | (buffer[id+2]<<16) | (buffer[id+3]<<24);
        return (T)(object)String.Intern(Encoding.UTF8.GetString(buffer, id+4, len));
    }
    else if (t == NumberID) {
        // Direct memory copy: sizeof(T) bytes from buffer[id]
        T[] arr = new T[1];
        Buffer.BlockCopy(buffer, id, arr, 0, Unsafe.SizeOf<T>());
        return arr[0];
    }
    else if (t == InitializerID) {
        // Array: [total_bytes:4] [count:4] [data:total_bytes-4]
        int total = ...; int count = ...;
        T[] arr = new T[count];
        Buffer.BlockCopy(buffer, id+8, arr, 0, total-4);
        return (T)(object)arr;
    }
}
```

## CFG Context Integration

When combined with Control Flow protection in CFG mode, constant IDs are XORed with a 4-element state machine:

### CFGCtx Structure

```csharp
struct CFGCtx {
    uint A, B, C, D;

    CFGCtx(uint seed) {
        A = seed *= 0x21412321;
        B = seed *= 0x21412321;
        C = seed *= 0x21412321;
        D = seed *= 0x21412321;
    }

    uint Next(byte flag, uint value) {
        // bit 7: explicit (assign) vs incremental (modify)
        // bits 0-1: which element to update (A=0, B=1, C=2, D=3)
        // bits 2-3: which element to return

        if (flag & 0x80) {  // Explicit
            element[flag & 3] = value;
        } else {  // Incremental
            switch (flag & 3) {
                case 0: A ^= value;
                case 1: B += value;
                case 2: C ^= value;
                case 3: D -= value;
            }
        }
        return element[(flag >> 2) & 3];
    }
}
```

State updates are interspersed with constant decoding, making each constant's ID dependent on the execution path.

### CFG State Initialization

```
seed = random_uint32
A = seed * 0x21412321; seed *= 0x21412321
B = seed * 0x21412321; seed *= 0x21412321
C = seed * 0x21412321; seed *= 0x21412321
D = seed * 0x21412321
```

## Reference Patching

### Normal Mode Patching

```
Original:  ldstr "hello"
Patched:   ldc.i4 <encoded_id>
           call   Get<string>(int)
```

### CFG Mode Patching

Integrates constant ID decoding with CFG state updates:
```
ldc.i4    <cfgFlag>
ldc.i4    <cfgValue>
call      CFGCtx.Next(byte, uint)    // Returns state element
ldc.i4    <encoded_id>
xor                                   // XOR with CFG state
call      Get<T>(int)
```

## dotscope Handling

Handled by `ConfuserExConstants` technique (detection) and `DecryptionPass` (emulation). The emulation engine executes `Initialize()` to decrypt the buffer, then SSA-based constant propagation resolves individual `Get<T>()` call IDs. CFG mode requires path-sensitive state tracking. See [constants-emulation.md](constants-emulation.md) for emulation details.
