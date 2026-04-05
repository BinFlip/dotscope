# ConfuserEx Constants Protection - Emulation Requirements

> See also: [Constants Protection](constants.md) for the complete protection architecture, encoding modes, buffer format, and CFG context details.

This document analyzes ConfuserEx's constants protection mechanism and documents
what our emulation needs to support for successful decryption.

## Source Files

- `Confuser.Runtime/Constant.cs` - Runtime decryption code
- `Confuser.Runtime/Mutation.cs` - Placeholder markers for code injection
- `Confuser.Runtime/Lzma.cs` - LZMA decompression
- `Confuser.Protections/Constants/*.cs` - Protection implementation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Constants Protection Flow                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Build Time (ConfuserEx):                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Collect all │ -> │ Encode &    │ -> │ LZMA        │         │
│  │ constants   │    │ encrypt     │    │ compress    │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                                     │                 │
│         v                                     v                 │
│  ┌─────────────┐                      ┌─────────────┐          │
│  │ Replace w/  │                      │ Store in    │          │
│  │ Get<T>(id)  │                      │ field RVA   │          │
│  └─────────────┘                      └─────────────┘          │
│                                                                 │
│  Runtime (.cctor / Initialize):                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Load RVA    │ -> │ Decrypt     │ -> │ LZMA        │         │
│  │ data array  │    │ (xorshift)  │    │ decompress  │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                                              │                  │
│                                              v                  │
│                                       ┌─────────────┐          │
│                                       │ Store in    │          │
│                                       │ static `b`  │          │
│                                       └─────────────┘          │
│                                                                 │
│  Runtime (Get<T> call):                                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Decode id   │ -> │ Extract     │ -> │ Return      │         │
│  │ (mul, xor)  │    │ from `b`    │    │ value       │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 1. Static Constructor (.cctor) / Initialize()

The `Initialize()` method is called from the module's `.cctor` and performs
one-time initialization of the decryption state.

### Source Code (Constant.cs)

```csharp
static byte[] b;  // Decrypted constants buffer

static void Initialize() {
    // 1. Get buffer length and encrypted data
    var l = (uint)Mutation.KeyI0;                           // Injected: buffer length
    uint[] q = Mutation.Placeholder(new uint[Mutation.KeyI0]); // Injected: RVA data

    // 2. Generate decryption key using xorshift RNG
    var k = new uint[0x10];
    var n = (uint)Mutation.KeyI1;                           // Injected: key seed
    for (int i = 0; i < 0x10; i++) {
        n ^= n >> 12;
        n ^= n << 25;
        n ^= n >> 27;
        k[i] = n;
    }

    // 3. Decrypt in 16-element blocks
    int s = 0, d = 0;
    var w = new uint[0x10];
    var o = new byte[l * 4];
    while (s < l) {
        for (int j = 0; j < 0x10; j++)
            w[j] = q[s + j];
        Mutation.Crypt(w, k);                               // Injected: cipher code
        for (int j = 0; j < 0x10; j++) {
            uint e = w[j];
            o[d++] = (byte)e;
            o[d++] = (byte)(e >> 8);
            o[d++] = (byte)(e >> 16);
            o[d++] = (byte)(e >> 24);
            k[j] ^= e;                                      // CBC mode feedback
        }
        s += 0x10;
    }

    // 4. LZMA decompress
    b = Lzma.Decompress(o);
}
```

### Code Injection Points

At build time, ConfuserEx replaces placeholder markers:

| Placeholder | Replacement |
|-------------|-------------|
| `Mutation.KeyI0` | `ldc.i4 <buffer_length>` |
| `Mutation.KeyI1` | `ldc.i4 <key_seed>` |
| `Mutation.Placeholder(new uint[...])` | Field load + `RuntimeHelpers.InitializeArray` |
| `Mutation.Crypt(w, k)` | Inline cipher code (mode-dependent) |

### Cipher Modes

**Normal Mode:** Simple XOR
```csharp
for (int i = 0; i < 0x10; i++)
    block[i] ^= key[i];
```

**Dynamic Mode:** Randomly generated cipher using DynCipher
- Operations: XOR, ADD, SUB, MUL, rotate, matrix transforms
- Different cipher generated for each protected assembly

### Emulation Requirements for .cctor

| Requirement | Description |
|-------------|-------------|
| Array allocation | `newarr` for uint[] and byte[] |
| Array access | `ldelem`, `stelem` for uint and byte |
| Field RVA access | `RuntimeHelpers.InitializeArray` - load data from PE |
| Arithmetic | XOR, shift, add, sub, mul (32-bit unsigned) |
| LZMA decompression | Complex algorithm - **requires hook** |
| Static field store | Store result in `b` field |

## 2. Decryptor Method - Get<T>(int id)

The generic decryptor method retrieves constants from the decrypted buffer.

### Source Code (Constant.cs)

```csharp
static T Get<T>(int id) {
    // Anti-tampering check (often bypassed)
    if (Assembly.GetExecutingAssembly().Equals(Assembly.GetCallingAssembly())) {

        // 1. Decode the ID (per-decoder transformation)
        id = Mutation.Placeholder(id);   // Injected: id * k1_inv ^ k2

        // 2. Extract type and offset
        int t = (int)((uint)id >> 30);   // Top 2 bits = type
        id = (id & 0x3fffffff) << 2;     // Bottom 30 bits = offset (*4)

        T ret;
        if (t == Mutation.KeyI0) {       // Type 0: String
            int l = b[id] | (b[id+1] << 8) | (b[id+2] << 16) | (b[id+3] << 24);
            ret = (T)(object)string.Intern(Encoding.UTF8.GetString(b, id+4, l));
        }
        else if (t == Mutation.KeyI1) {  // Type 1: Primitive (int, float, etc.)
            var v = new T[1];
            Buffer.BlockCopy(b, id, v, 0, Mutation.Value<int>()); // sizeof(T)
            ret = v[0];
        }
        else if (t == Mutation.KeyI2) {  // Type 2: Array
            int s = b[id] | (b[id+1] << 8) | (b[id+2] << 16) | (b[id+3] << 24);
            int l = b[id+4] | (b[id+5] << 8) | (b[id+6] << 16) | (b[id+7] << 24);
            Array v = Array.CreateInstance(typeof(T).GetElementType(), l);
            Buffer.BlockCopy(b, id+8, v, 0, s - 4);
            ret = (T)(object)v;
        }
        else
            ret = default(T);

        return ret;
    }
    return default(T);
}
```

### ID Encoding

Each decoder instance has unique keys (k1, k2):
```
encoded_id = (actual_id ^ k2) * k1
decoded_id = encoded_id * modInv(k1) ^ k2
```

The `Mutation.Placeholder(id)` is replaced with:
```cil
ldarg.0                    // load id
ldc.i4 <modInv(k1)>
mul
ldc.i4 <k2>
xor
```

### Emulation Requirements for Get<T>

| Requirement | Description |
|-------------|-------------|
| Generic method instantiation | Handle `Get<int>`, `Get<string>`, etc. |
| Reflection | `Assembly.GetExecutingAssembly()`, `GetCallingAssembly()` |
| Arithmetic | Multiply, XOR, shift, AND |
| Array access | Byte array indexing |
| `Buffer.BlockCopy` | Memory copy between arrays |
| `Encoding.UTF8.GetString` | String decoding |
| `string.Intern` | String interning |
| `Array.CreateInstance` | Dynamic array creation |
| Type introspection | `typeof(T).GetElementType()` |

## 3. CFGCtx - Control Flow Context

Used by control flow obfuscation to compute switch targets dynamically.

### Source Code (Constant.cs)

```csharp
internal struct CFGCtx {
    uint A, B, C, D;

    public CFGCtx(uint seed) {
        A = seed *= 0x21412321;
        B = seed *= 0x21412321;
        C = seed *= 0x21412321;
        D = seed *= 0x21412321;
    }

    public uint Next(byte f, uint q) {
        // Update state based on flags
        if ((f & 0x80) != 0) {           // Set mode
            switch (f & 0x3) {
                case 0: A = q; break;
                case 1: B = q; break;
                case 2: C = q; break;
                case 3: D = q; break;
            }
        }
        else {                           // Combine mode
            switch (f & 0x3) {
                case 0: A ^= q; break;
                case 1: B += q; break;
                case 2: C ^= q; break;
                case 3: D -= q; break;
            }
        }

        // Return selected state
        switch ((f >> 2) & 0x3) {
            case 0: return A;
            case 1: return B;
            case 2: return C;
        }
        return D;
    }
}
```

### Usage in Control Flow Obfuscation

```csharp
// Obfuscated code pattern
CFGCtx ctx = new CFGCtx(seed);
int state = initial_state;
while (true) {
    switch (state % num_blocks) {
        case 0:
            // original block 0
            state = (int)ctx.Next(flag0, val0);
            break;
        case 1:
            // original block 1
            state = (int)ctx.Next(flag1, val1);
            break;
        // ...
    }
}
```

### Emulation Requirements for CFGCtx

| Requirement | Description |
|-------------|-------------|
| Struct allocation | Value type on stack/locals |
| Struct field access | Read/write A, B, C, D fields |
| Constructor call | `newobj` or inline initialization |
| Method call | `call` to `Next` |
| Arithmetic | Multiply, XOR, ADD, SUB (32-bit) |
| Switch statement | Computed jump targets |

## dotscope Handling

All emulation requirements are fully implemented. LZMA decompression is handled via a native hook (too complex to emulate). `Assembly.GetExecutingAssembly`/`GetCallingAssembly` reflection checks are hooked to always succeed.
