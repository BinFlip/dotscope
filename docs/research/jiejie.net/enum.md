# Enum Parameter Encryption

| Property | Value |
|----------|-------|
| **Protection** | Enum Parameter Encryption |
| **Class** | `DCJieJieNetEngine` (`EncryptMethodParamterEnumValue`, line 7264) |
| **Category** | Value (constant encryption) |
| **Targets** | `ldc.i4` instructions preceding `call`/`callvirt` where the last parameter is an enum type |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | `Int32ValueContainer` (stores the enum integer values) |

## Overview

JIEJIE.NET detects integer constant loads (`ldc.i4`) that serve as enum arguments to method calls and replaces them with `Int32ValueContainer` field loads. This hides enum values from static analysis — decompilers can no longer resolve the enum member name from the integer constant.

## Algorithm

Source: `EncryptMethodParamterEnumValue()` (line 7264)

### Pattern Detection

```
ldc.i4     <enumValue>
call/callvirt  <methodWithEnumParam>
```

The method checks whether the called method's last parameter is a value type (enum). If so, the preceding `ldc.i4` is replaced:

```
// Before:
ldc.i4     3                              // e.g., DayOfWeek.Wednesday
call       void Foo::SetDay(valuetype DayOfWeek)

// After:
ldsfld     int32 __DC20210205._Int32ValueContainer::_N_3
call       void Foo::SetDay(valuetype DayOfWeek)
```

### Scope

Only the last parameter position is checked. Multi-enum-parameter calls only have the final argument encrypted. This is a deliberate simplification in JIEJIE.NET's implementation.

## Detection Signatures

No unique signature — this protection is invisible after `Int32ValueContainer` resolution. The replaced `ldc.i4` values are standard integer constants that happen to represent enum members.

## dotscope Handling

Automatically handled by `Int32ValueContainerPass`. Once all container field loads are resolved to concrete `ldc.i4` constants, the enum values are restored to their original form. No enum-specific pass is needed.
