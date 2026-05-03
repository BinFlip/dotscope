# Resource Encryption (Stage 7)

Analysis of .NET Reactor 7.5.0 resource encryption based on reverse engineering
`reactor_resources.exe` (54,272 bytes, 185 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 54,272 | +39,936 (278%) |
| .text section | 0x2E00 | 0xCA00 | +39,936 |
| Metadata size | 7,904 | 23,036 | +15,132 |
| TypeDef rows | 13 | 49 | +36 |
| MethodDef rows | 35 | 185 | +150 |
| Methods with bodies | 35 | 143 | +108 |
| Tables count | 17 | 23 | +6 |


## Call-Site Rewriting

Resource encryption replaces direct BCL calls to resource APIs with calls to the
injected resolver type:

**Original** `DemoEmbeddedResources`:
```
ldloc.0
callvirt   Assembly::GetManifestResourceNames()
stloc.1
```

**Protected** `DemoEmbeddedResources`:
```
ldloc.0
call       EJsBjqD3uVy8IwCD9w.G7JZLAxiZym8sY748W::eBxqprrF8(ResourceManager)
stloc.1
```

The `callvirt` to a BCL method is replaced with a `call` to the injected resolver.
The rest of the method body is structurally identical (only token numbers shift due
to expanded metadata tables).

**No .cctor injection**: Unlike anti-tamper, resource encryption does NOT inject
`.cctor` calls into original types. Initialization is lazy (on first resource access).


## Resource Resolver Type

`EJsBjqD3uVy8IwCD9w.G7JZLAxiZym8sY748W` — 29+ methods.

### Static Fields

| Field | Purpose |
|-------|---------|
| Row 71 | `string[]` — decrypted resource name array |
| Row 72 | Cached decrypted assembly data |
| Row 73 | `bool` — initialization flag |
| Row 74 | `bool` — registration flag |

### .cctor
```
ldc.i4.0 / newarr string[] / stsfld field(71)   // empty resource array
ldnull   / stsfld field(72)                      // null data
ldc.i4.0 / stsfld field(73)                      // not initialized
ldc.i4.0 / stsfld field(74)                      // not registered
```

### Lazy Initializer: `kLjw4iIsCLsZtxc4lksN0j`
```
ldsfld     field(74)         // check if registered
brtrue     -> ret
ldc.i4.1 / stsfld field(74)  // set registered flag
newobj     G7JZLAxiZym8sY748W.ctor()  // create instance (registers resolver)
pop / ret
```

### Resource Interceptor: `eBxqprrF8` (1 argument)

Intercepts resource resolution requests:
```
ldarg.0
ldtoken    TypeDef(row 35)
call       Type.GetTypeFromHandle()
callvirt   Type.get_Assembly()
call       ReferenceEquals()          // check if request is for THIS assembly
brfalse    -> passthrough

ldsfld     field(73)                  // check if decrypted
brtrue     -> serve_cached
call       OpMPoypqBX()              // decrypt all resources (massive CFF method)

// serve_cached:
newobj     ResourceSet()
// ... load decrypted resource from cache
callvirt   Assembly.GetManifestResourceStream()
callvirt   Stream.ToArray()
ret

// passthrough:
ldarg.0  / callvirt .get_Name()       // return name for non-self assemblies
ret
```

### Main Decryption Engine: `OpMPoypqBX` (46 locals)

The core resource decryption method — CFF-protected with a **358-case switch**
(~400 dispatch entries). This is the largest CFF method across all samples.

Operations within the CFF:
1. Builds AES keys using obfuscated constant arithmetic
2. Loads encrypted resource data from an embedded managed resource stream
3. Uses `BinaryReader` to read structured encrypted data
4. Decrypts resource names and data using AES (via `tRelL85we1`)
5. Stores decrypted names in field(71) and assembly data in field(72)
6. Sets initialization flag in field(73)

### Resource Name Lookup: `ywiPIOE9br`
```
ldsfld     field(73)         // check init
brtrue     -> skip
call       OpMPoypqBX()     // lazy decrypt

ldarg.1  / callvirt String.ToLowerInvariant()
stloc.0
// loop through decrypted resource names
ldsfld     field(71)         // resource name array
ldloc.1  / ldelem.ref
ldloc.0  / call String.Equals()
brfalse    -> next
ldsfld     field(72)         // return cached assembly
castclass  Assembly
ret
```


## Native Memory Utility Type

`S7L7mnstnVcO04e5JH` — 10 methods providing low-level memory operations:

| Method | Purpose | Pattern |
|--------|---------|---------|
| `I75l5DElFW` | Unaligned int32 read | `ldind.u4` with byte-by-byte fallback (switch on alignment) |
| `oxwlrOtd5b` | Memory compare | Byte-by-byte `ldind.u1` + `ceq` |
| `h8flmlF1vO` | Memory fill | `stind.i1` loop |
| `HxFlvT96vp` | Reflection invoke | `ldtoken` + `GetTypeFromHandle` + `MakeGenericMethod` + `Invoke` |
| `MKRltyYrpA` | Read bytes | Native pointer to managed byte array copy |

The reflection invoke method (`HxFlvT96vp`) is used for version-compatible
deserialization/decompression across different .NET framework versions.


## Detection Signatures

| Signal | Pattern |
|--------|---------|
| Call-site rewrite | `callvirt Assembly::GetManifest*` replaced with `call` to injected type |
| Resolver type | Type with `OpMPoypqBX`-like massive CFF method (300+ switch cases) |
| Native memory util | Type with 10 methods doing `ldind.u1`/`stind.i1` pointer operations |
| Lazy init | Static bool fields for initialization/registration state |
| AES decryption | Same `RijndaelManaged` pattern as anti-tamper |


## Deobfuscation Strategy

1. **Identify the resource resolver type**: Look for the call-site rewrite pattern
   (BCL resource method replaced with call to injected type)
2. **Decrypt resources**: Either emulate `OpMPoypqBX` or extract the AES key from
   the CFF-protected body and decrypt the embedded resource directly
3. **Restore call sites**: Replace `call resolver::method()` with original
   `callvirt Assembly::GetManifest*()` calls
4. **Extract embedded assemblies**: If assemblies are embedded in the encrypted resource,
   extract them as separate files
5. **Remove injected types**: Delete the resolver type, native memory utilities, and
   shared infrastructure

### Comparison with NRS Approach

NRS's `ResourceResolver` (Stage 7):
- Finds types with 3-4 fields (Boolean, Object, String[]/Assembly)
- Locates `(Object, ResolveEventArgs)` handler signature
- Validates `EncryptedResource` decrypter
- Decrypts via EncryptedResource, decompresses with QuickLZ or Deflate

Our approach can leverage emulation to run the CFF-protected decryption method,
avoiding the need to reimplement the AES key derivation logic.
