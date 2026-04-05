# Char Value Encryption

| Property | Value |
|----------|-------|
| **Protection** | Char Value Encryption |
| **Class** | `DCJieJieNetEngine` (`EncryptCharValue`, line 7179) |
| **Category** | Value (constant encryption) |
| **Targets** | `ldc.i4` instructions used as `char` values in comparisons and assignments |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | `Int32ValueContainer` (stores the char integer values) |

## Overview

JIEJIE.NET detects integer constant loads that represent character values and replaces them with `Int32ValueContainer` field loads. This runs early in the pipeline (step 9) before string encryption.

## Algorithm

Source: `EncryptCharValue()` (line 7179)

### Pattern Detection

A `ldc.i4` instruction qualifies if its value is in the range [1, 0xFFFF] (valid `char` range) AND one of:
1. The **previous instruction** produces a `System.Char` type, OR
2. The **next instruction** consumes a `System.Char` type
3. The **next instruction** is a comparison/arithmetic operator: `add`, `and`, `beq`, `bgt`, `ble`, `blt`, `bne`, `ceq`, `cgt`, `clt`

### Transformation

```
// Before:
ldc.i4     65                             // 'A'
beq        IL_match

// After:
ldsfld     int32 __DC20210205._Int32ValueContainer::_N_65
beq        IL_match
```

## Detection Signatures

No unique signature — indistinguishable from other `Int32ValueContainer` field loads after the container is committed.

## dotscope Handling

Automatically handled by `Int32ValueContainerPass`. Once all container field loads are resolved to concrete `ldc.i4` constants, char values are restored to their original form. No char-specific pass is needed.
