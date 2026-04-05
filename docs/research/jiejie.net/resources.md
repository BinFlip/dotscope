# Resource Encryption

| Property | Value |
|----------|-------|
| **Protection** | Resource Encryption |
| **Class** | `DCJieJieNetEngine` (`ApplyResouceContainerClass`, `EncryptEmbeddedResource`) |
| **Category** | Value (resource encryption) |
| **Targets** | ResourceManager accessor classes, ComponentResourceManager, embedded resources |
| **Configuration** | `Resources` switch (enabled by default) |
| **Dependencies** | `ByteArrayDataContainer` (encrypted data storage), `JIEJIEHelper` (runtime decryption methods) |

## Overview

JIEJIE.NET implements three resource encryption sub-techniques:

1. **Resource container class replacement** — replaces `ResourceManager`-backed accessor classes with encrypted versions
2. **ComponentResourceManager replacement** — replaces WinForms designer resource loading
3. **Embedded resource encryption** — XOR-encrypts raw embedded resources and hooks `GetManifestResourceStream`

## Sub-Technique 1: Resource Container Class Replacement

Source: `ApplyResouceContainerClass()` (line 5268)

### Detection of Resource Classes

Identifies classes that are .NET resource wrappers:
- Have exactly 2 fields: `ResourceManager` + `CultureInfo`
- Have getter methods (`get_XXX`) that call `ResourceManager.GetString()` or `GetObject()`
- Have a `ResourceManager` property returning a cached instance

### Encryption

All resource values (strings, bitmaps) are serialized into a single encrypted byte array.

**String encryption**:
```
key = random(1000, int.MaxValue - 1000)
for each char in string:
    v = char ^ key
    bytes.Add(v >> 8)     // big-endian high byte
    bytes.Add(v & 0xFF)   // big-endian low byte
    key++
```

**Bitmap encryption**:
```
key = random byte
bitmap → BMP format byte array
for each byte:
    byte ^= key
    key++
```

### Replacement

The original class is completely replaced with a synthetic version:
- `.cctor` loads the encrypted byte array from `ByteArrayDataContainer`
- String getters call `JIEJIEHelper::GetString(byte[], int startIndex, int byteLength, int key)`
- Bitmap getters call `JIEJIEHelper::GetBitmap(byte[], int startIndex, int byteLength, int key)` with lazy caching via static fields
- Unused resource items (getter methods never called) are removed
- Member order is shuffled

### GetString Decryptor

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

## Sub-Technique 2: ComponentResourceManager Replacement

Source: lines 5537–5661

### Detection

Detects `InitializeComponent()` methods that create `System.ComponentModel.ComponentResourceManager`.

### Encryption

- Resource data is optionally GZip-compressed (if >512 bytes savings and >2x ratio)
- Then XOR-encrypted with random key (100–234), incrementing per byte:
  ```
  key = random(100, 234)
  for each byte in data:
      byte ^= key
      key = (key + 1) % 256  // wraps at byte boundary
  ```

### Replacement

A synthetic class `__DC20210205._Res<N>` extending `ComponentResourceManager` is injected:
- Constructor decrypts/decompresses data
- Overrides `ApplyResources` and `GetString` as `MyApplyResources`/`MyGetString`
- The `.resources` file is removed from the assembly

## Sub-Technique 3: Embedded Resource Encryption

Source: `EncryptEmbeddedResource()` (line 6908)

### What Is Encrypted

All embedded resources except:
- `.resources` files
- `.ico` files
- `.bmp` files

### Encryption

```
xorKey = random(100, 233)
for each byte in resource:
    byte ^= xorKey
    // xorKey does NOT increment (single-byte XOR for entire resource)
```

Optionally GZip-compressed if >50KB and compression ratio <0.6.

A 4-byte little-endian header is prepended: original decompressed length (0 = no compression).

### Runtime Hooks

The following calls are redirected through `JIEJIEHelper`:

| Original Call | Redirected To |
|---------------|---------------|
| `Assembly.GetManifestResourceStream(string)` | `JIEJIEHelper::SMF_GetManifestResourceStream(Assembly, string)` |
| `Assembly.GetManifestResourceStream(Type, string)` | `JIEJIEHelper::SMF_GetManifestResourceStream2(Assembly, Type, string)` |
| `Assembly.GetManifestResourceNames()` | `JIEJIEHelper::SMF_GetManifestResourceNames(Assembly)` |
| `Assembly.GetManifestResourceInfo(string)` | `JIEJIEHelper::SMF_GetManifestResourceInfo(Assembly, string)` |

The helper maintains a `Dictionary<string, byte[]>` mapping resource names to encrypted data. `SMF_ResStream` is a nested `Stream` class that XOR-decrypts in its `Read()` method.

### SMF_GetContent (Resource Lookup)

The `SMF_GetContent(string name)` method is typically CFF-obfuscated. After CFF unflattening, it resolves to an if-else chain comparing the resource name against known strings and returning the corresponding byte array from `ByteArrayDataContainer`:

```
if (String.Equals(name, "resource1.bin")) return ByteArrayDataContainer._0();
if (String.Equals(name, "resource2.txt")) return ByteArrayDataContainer._1();
...
return null;
```

## Detection Signatures

- **Helper class**: `__DC20211119.JIEJIEHelper` with `GetString`, `GetBitmap`, `SMF_*` methods
- **Nested Stream**: `JIEJIEHelper` containing a nested class with 10+ methods implementing `Stream` interface (Read, Write, Seek, Flush, Length, Position property accessors)
- **Resource wrapper classes**: `__DC20210205._Res<N>` extending `ComponentResourceManager`
- **Call redirections**: `callvirt Assembly::GetManifestResourceStream` replaced with `call JIEJIEHelper::SMF_GetManifestResourceStream`
- **ByteArrayDataContainer references**: Large byte arrays loaded via `ByteArrayDataContainer`

## dotscope Handling

Handled by `JiejieNetResources` technique (detection + byte transform) and `ResourceRestorationPass` (SSA-level call redirection reversal). The technique uses SSA-based detection (post-CFF unflattening) to extract resource name → data method mappings from the `SMF_GetContent` if-else chain. The byte transform phase decrypts FieldRVA data (XOR + optional GZip decompression) and inserts `ManifestResource` entries back into the assembly. The SSA pass redirects `SMF_*` calls back to their original `Assembly.GetManifest*` targets. Runs in the **Simplify phase** — must execute before cleanup removes the helper class.
