# typeof() Encryption

| Property | Value |
|----------|-------|
| **Protection** | typeof() Encryption (`RuntimeTypeHandleContainer`) |
| **Class** | `DCJieJieNetEngine` (line 7313) |
| **Category** | Value (type handle indirection) |
| **Targets** | `ldtoken <type>` + `Type.GetTypeFromHandle()` instruction pairs |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | `Int32ValueContainer` (array indices stored as container field loads) |

## Overview

JIEJIE.NET encrypts `typeof(T)` expressions by replacing the direct `ldtoken <type>` + `Type.GetTypeFromHandle()` pattern with an array-based indirection through a synthetic container class. Type tokens are collected into a `RuntimeTypeHandle[]` array in randomized order, and call sites are replaced with index-based lookups.

## Original Pattern

```il
ldtoken    [mscorlib]System.String
call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(
               valuetype [mscorlib]System.RuntimeTypeHandle)
```

## Obfuscated Pattern

```il
ldsfld     int32 __DC20210205._Int32ValueContainer::_N_3    // type index (from container)
call       class [mscorlib]System.Type
               __DC20210205._RuntimeTypeHandleContainer::GetTypeInstance(int32)
```

## Injected Type

**Class**: `__DC20210205._RuntimeTypeHandleContainer`

Contains:
- `_Handles : RuntimeTypeHandle[]` — static array of all type handles
- `GetTypeInstance(int32) -> Type` — retrieves `Type.GetTypeFromHandle(_Handles[index])`

### .cctor Initialization

```il
newobj     instance void class [mscorlib]System.Collections.Generic.List`1<
               valuetype [mscorlib]System.RuntimeTypeHandle>::.ctor()
stloc.0
ldloc.0
ldtoken    [mscorlib]System.String
callvirt   instance void class [mscorlib]System.Collections.Generic.List`1<
               valuetype [mscorlib]System.RuntimeTypeHandle>::Add(!0)
ldloc.0
ldtoken    [mscorlib]System.Int32
callvirt   ... List::Add(!)
...
ldloc.0
callvirt   instance !0[] class [mscorlib]System.Collections.Generic.List`1<
               valuetype [mscorlib]System.RuntimeTypeHandle>::ToArray()
stsfld     valuetype [mscorlib]System.RuntimeTypeHandle[]
               __DC20210205._RuntimeTypeHandleContainer::_Handles
```

The type order is **randomized** (`ObfuseListOrder`) — indices do not correspond to any predictable ordering.

### GetTypeInstance Method

```il
ldsfld     valuetype [mscorlib]System.RuntimeTypeHandle[]
               __DC20210205._RuntimeTypeHandleContainer::_Handles
ldarg.0                    // int32 index
ldelem     [mscorlib]System.RuntimeTypeHandle
call       class [mscorlib]System.Type
               [mscorlib]System.Type::GetTypeFromHandle(
                   valuetype [mscorlib]System.RuntimeTypeHandle)
ret
```

## Exclusions

- **Generic types** are excluded from typeof encryption
- The `ldtoken` must be immediately followed by `Type.GetTypeFromHandle()` to qualify

## Detection Signatures

- **Type name** (pre-rename): `__DC20210205._RuntimeTypeHandleContainer`
- **Method**: Static method `GetTypeInstance(int32)` returning `System.Type`
- **Static field**: `RuntimeTypeHandle[]` array (exactly 1 static field of array-of-ValueType)
- **.cctor pattern**: `List<RuntimeTypeHandle>` construction + repeated `ldtoken` + `Add` + final `ToArray` + `stsfld`

## dotscope Handling

Handled by `JiejieNetTypeOf` technique (detection + type token extraction) and `TypeOfRestorationPass` (SSA-level call replacement). The technique parses the container's `.cctor` to extract the ordered list of type tokens from `ldtoken` instructions — no emulation needed, purely static IL analysis. The pass resolves `Call(GetTypeInstance, index)` → `LoadToken(TypeRef(type_tokens[index]))` after `Int32ValueContainerPass` has resolved the index argument to a constant.
