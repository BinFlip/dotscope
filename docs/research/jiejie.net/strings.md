# String Encryption

| Property | Value |
|----------|-------|
| **Protection** | String Encryption |
| **Class** | `DCJieJieNetEngine` (inline, line 6342) |
| **Category** | Value (string encryption) |
| **Targets** | `ldstr` instructions |
| **Configuration** | `Strings` (normal mode), `HightStrings` (high-strength mode) |
| **Dependencies** | `ByteArrayDataContainer` for encrypted byte storage |

## Overview

JIEJIE.NET implements two string encryption modes sharing the same core XOR algorithm:

- **Normal mode** (`Strings`): `ldstr` → `ldsfld` — strings are pre-decrypted in `.cctor` and cached in static fields
- **High-strength mode** (`HightStrings`): `ldstr` → `call` — strings are decrypted on every access via per-string accessor methods

Empty strings are replaced with `ldsfld string [mscorlib]System.String::Empty` (no encryption needed).

## Injected Types

### Normal Mode

Classes named `__DC20210205._Strings<N>` (50–100 strings per class, randomly batched).

Each class contains:
- `_Data : byte[]` static field — the encrypted byte blob
- Static `string` fields `_0`, `_1`, ... — one per encrypted string
- `dcsoft(byte[], int64) -> string` — the decryption method
- `.cctor` — calls `dcsoft` for each string field and stores the result

### High-Strength Mode

Classes named `__DC20210205._HightStrings<N>`.

Each class contains:
- `_Data : byte[]` static field — the encrypted byte blob
- Static methods `_0()`, `_1()`, ... — each returns a string by calling `dcsoft`
- `dcsoft(byte[], int64) -> string` — same decryption method
- `.cctor` — only initializes `_Data`

### Byte Array Storage

Encrypted data is stored via `__DC20210205._ByteArrayDataContainer`:
- Nested value types `_DATA<N>` with `.pack 1` and `.size <byteCount>`
- Static fields `_Field<N>` stored `at I_BDC<N>` (RVA-backed data section)
- Static methods `_<N>()` return `byte[]` via `RuntimeHelpers.InitializeArray`

## Encryption Algorithm

Source: `DCJieJieNetEngine.EncryptStringValues_AddString()` (line 6885)

```
Parameters:
    lstDatas : List<byte>     -- accumulating byte blob
    strValue : string         -- plaintext string
    keyOffset : int           -- per-class random key [10000, 99999)

Returns: long (the 64-bit packed key)

Algorithm:
    itemEncryptKey = random(10000, 55535)    // per-string random key

    // Pack the 64-bit key:
    longKey = (lstDatas.Count / 2)           // startIndex in char units
    longKey = (longKey << 24) + strValue.Length   // string length
    longKey = (longKey << 16) + (ushort)(itemEncryptKey ^ keyOffset)  // XOR-masked key

    key = itemEncryptKey
    for each char c in strValue:
        v = (ushort)(c ^ key)       // XOR char with rolling key
        lstDatas.Add(v >> 8)        // big-endian: high byte
        lstDatas.Add(v & 0xFF)      // big-endian: low byte
        key++                       // increment key per character
```

### 64-bit Key Layout

```
Bits 63..40:  startIndex (char-unit offset into byte blob, up to 24 bits)
Bits 39..16:  string length (up to 24 bits, but only 20 bits used in decoder mask)
Bits 15..0:   (itemEncryptKey ^ keyOffset) (XOR-masked per-string key)
```

The shifts are `<< 24` then `<< 16`, so startIndex occupies bits 40+, length occupies bits 16–39, and the masked key occupies bits 0–15.

## Decryption Algorithm

Source: Inline IL in `dcsoft` method. C# equivalent:

```csharp
static string dcsoft(byte[] datas, long key)
{
    // 1. Extract per-string XOR key, unmask with class keyOffset
    int key2 = (int)(key & 0xFFFF) ^ keyOffset;  // keyOffset is ldc.i4 immediate in IL

    // 2. Extract string length
    key >>= 16;
    int length = (int)(key & 0xFFFFF);  // 20-bit mask = 1048575

    // 3. Extract start index
    key >>= 24;
    int startIndex = (int)key;

    // 4. Decrypt character-by-character
    char[] array = new char[length];
    for (int i = 0; i < length; i++)
    {
        int byteIdx = (i + startIndex) * 2;  // << 1 in IL
        array[i] = (char)(((datas[byteIdx] << 8) + datas[byteIdx + 1]) ^ key2);
        key2++;
    }
    return new string(array);
}
```

## IL Patterns After Obfuscation

### Normal Mode

```
// Original:
ldstr "Hello World"

// Obfuscated:
ldsfld string __DC20210205._Strings42::_3
```

The `.cctor` of `_Strings42`:
```il
call      uint8[] __DC20210205._ByteArrayDataContainer::_0()
stloc.0
ldloc.0
ldc.i8    0x0000000A00050C3F     // packed key for _0
call      string __DC20210205._Strings42::dcsoft(uint8[], int64)
stsfld    string __DC20210205._Strings42::_0
ldloc.0
ldc.i8    0x0000001400070B2E     // packed key for _1
call      string __DC20210205._Strings42::dcsoft(uint8[], int64)
stsfld    string __DC20210205._Strings42::_1
...
ret
```

### High-Strength Mode

```
// Original:
ldstr "Hello World"

// Obfuscated:
call string __DC20210205._HightStrings50::_3()
```

Each wrapper method:
```il
ldsfld    uint8[] __DC20210205._HightStrings50::_Data
ldc.i8    0x0000000A00050C3F
call      string __DC20210205._HightStrings50::dcsoft(uint8[], int64)
ret
```

## Resource String Decryption (`GetString`)

A separate simpler XOR decryptor exists for resource strings used by `JIEJIEHelper::GetString()`:

```csharp
static string GetString(byte[] bsData, int startIndex, int bsLength, int key)
{
    int chrsLength = bsLength / 2;
    char[] chrs = new char[chrsLength];
    for (int i = 0; i < chrsLength; i++, key++)
    {
        int bi = startIndex + i * 2;
        chrs[i] = (char)(((bsData[bi] << 8) + bsData[bi + 1]) ^ key);
    }
    return new string(chrs);
}
```

Here `startIndex` is a byte offset, `bsLength` is in bytes, and `key` is the raw XOR key (not packed). This is used for resource container class decryption (see [resources.md](resources.md)).

## Detection Signatures

- **Type name pattern**: Classes matching `__DC20210205._Strings\d+` or `__DC20210205._HightStrings\d+`
- **Method signature**: Static method `dcsoft(byte[], int64)` returning `string`
- **Data container**: Class `__DC20210205._ByteArrayDataContainer` with nested `_DATA\d+` value types
- **IL pattern**: `.cctor` calling `dcsoft` with `ldc.i8` + storing to static string fields
- **Key extraction**: The `ldc.i4 <keyOffset>` in `dcsoft` method body (the XOR operand after `and 0xFFFF`)

## dotscope Handling

Handled by `JiejieNetStrings` technique (detection + warmup registration) and `JiejieStringFieldPass` (SSA-level field load → decrypted string constant replacement). Normal mode: the technique registers `ByteArrayDataContainer` `.cctor` as a dependency warmup, then string class `.cctors` as secondary warmups. The pass reads emulated field values and replaces `LoadStaticField` ops with `DecryptedString` constants. High-strength mode: accessor methods are registered as decryptors feeding into the shared `DecryptionPass` for emulation-based reversal.
