# Array Initialization Encryption

| Property | Value |
|----------|-------|
| **Protection** | Array Initialization Encryption (`RuntimeFieldHandleContainer`) |
| **Class** | `DCJieJieNetEngine` (`Encrypt_ArrayDefine`, line 6209) |
| **Category** | Value (data encryption) |
| **Targets** | `RuntimeHelpers.InitializeArray()` call sites |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | `Int32ValueContainer` (handle indices and XOR keys), `JIEJIEHelper` (wrapper method) |

## Overview

JIEJIE.NET encrypts static array initialization data by XOR-encrypting the RVA-backed field data and redirecting the `RuntimeHelpers.InitializeArray()` call through a decrypting wrapper `JIEJIEHelper::MyInitializeArray`. The field handle is indirected through a `RuntimeFieldHandleContainer` array, and the XOR decryption key is passed as an additional parameter.

## Original Pattern

```il
ldc.i4     256                                              // array size
newarr     [mscorlib]System.Int32
dup
ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=1024'
               '<PrivateImplementationDetails>'::'$$method0x6000001-1'
call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(
               class [mscorlib]System.Array,
               valuetype [mscorlib]System.RuntimeFieldHandle)
```

## Obfuscated Pattern

```il
ldsfld     int32 __DC20210205._Int32ValueContainer::_N_256  // array size (from container)
newarr     [mscorlib]System.Int32
dup
ldsfld     int32 __DC20210205._Int32ValueContainer::_N_3    // handle index
call       valuetype [mscorlib]System.RuntimeFieldHandle
               __DC20210205._RuntimeFieldHandleContainer::GetHandle(int32)
ldsfld     int32 __DC20210205._Int32ValueContainer::_N_42   // XOR key
call       void [__DC20211119]__DC20211119.JIEJIEHelper::MyInitializeArray(
               class [mscorlib]System.Array,
               valuetype [mscorlib]System.RuntimeFieldHandle,
               int32)
```

## Data Encryption Algorithm

Source: `Encrypt_ArrayDefine_Items()` (line 6106)

The raw bytes backing the array field are XOR-encrypted in-place in 4-byte blocks:

```csharp
// XOR in 4-byte blocks, processing from end to start
int xorKey = randomKey;  // random int
for (int i = data.Length - 4; i >= 0; i -= 4)
{
    *(int*)(data + i) ^= xorKey;
    xorKey += 13;  // key increments by 13 per block
}
```

Key characteristics:
- Block processing is **from end to start** (last 4 bytes first)
- XOR key **increments by 13** per 4-byte block
- The key is stored as an `Int32ValueContainer` field, passed as the third argument to `MyInitializeArray`

## RuntimeFieldHandle Indirection

**Class**: `__DC20210205._RuntimeFieldHandleContainer`

Contains:
- `_Handles : RuntimeFieldHandle[]` — static array of all field handles
- `GetHandle(int32) -> RuntimeFieldHandle` — returns `_Handles[index]`
- `.cctor` — populates the array from `ldtoken field` instructions (shuffled order)

Distinguished from `RuntimeTypeHandleContainer` by the accessor's return type: `ValueType` (RuntimeFieldHandle) vs `Class` (System.Type).

## MyInitializeArray Wrapper

The helper method in `__DC20211119.JIEJIEHelper`:

```csharp
static void MyInitializeArray(Array array, RuntimeFieldHandle handle, int encKey)
{
    RuntimeHelpers.InitializeArray(array, handle);  // normal initialization (with encrypted data)
    // Then XOR-decrypt the array elements in-place (reverse the encryption)
    // Same 4-byte block XOR, end-to-start, key += 13 per block
}
```

## Detection Signatures

- **Type name** (pre-rename): `__DC20210205._RuntimeFieldHandleContainer`
- **Helper method**: `JIEJIEHelper::MyInitializeArray(Array, RuntimeFieldHandle, int32)` — 3-parameter signature distinguishes it from standard 2-parameter `RuntimeHelpers.InitializeArray`
- **Call pattern**: `ldsfld` (index) + `call GetHandle` + `ldsfld` (key) + `call MyInitializeArray`
- **Structural**: Class with exactly 1 static field of `ValueType[]` array, `.cctor` with `ldtoken field` instructions

## dotscope Handling

Handled by `JiejieNetArrays` technique (detection + byte transform) and `ArrayInitRestorationPass` (SSA-level call unwrapping). The technique detects both the `RuntimeFieldHandleContainer` and the `MyInitializeArray` wrapper by structural analysis. The SSA pass replaces `Call(GetHandle, index)` → `Const(FieldHandle(field_tokens[index]))` and unwraps `Call(MyInitializeArray, array, handle, key)` → `Call(RuntimeHelpers.InitializeArray, array, handle)`. The actual FieldRVA data decryption is performed in the technique's `byte_transform` phase using the resolved XOR keys — 4-byte blocks from end to start with key incrementing by 13.
