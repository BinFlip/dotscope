# Lock/Using Structure Obfuscation

| Property | Value |
|----------|-------|
| **Protection** | Lock/Using Structure Obfuscation |
| **Class** | `DCJieJieNetEngine` (`Encrypt_Lock_Using_Structure`, line 6243) |
| **Category** | Code (call redirection) |
| **Targets** | `Monitor.Enter()` and `IDisposable.Dispose()` call sites |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | `JIEJIEHelper` class (wrapper methods) |

## Overview

JIEJIE.NET redirects `Monitor.Enter()` and `IDisposable.Dispose()` calls through wrapper methods in the injected `JIEJIEHelper` class. This hides the `lock()` and `using()` patterns from decompilers. The wrapper methods are functionally identical pass-throughs.

## Transformations

| Original | Replacement |
|----------|-------------|
| `call Monitor.Enter(object)` | `call JIEJIEHelper::Monitor_Enter(object)` |
| `call Monitor.Enter(object, ref bool)` | `call JIEJIEHelper::Monitor_Enter2(object, ref bool)` |
| `callvirt IDisposable.Dispose()` | `call JIEJIEHelper::MyDispose(object)` |

The wrappers simply forward to the original methods:

```csharp
static void Monitor_Enter(object obj) => Monitor.Enter(obj);
static void Monitor_Enter2(object obj, ref bool lockTaken) => Monitor.Enter(obj, ref lockTaken);
static void MyDispose(object obj) => ((IDisposable)obj).Dispose();
```

Unused wrappers are automatically removed if the corresponding pattern is not found in the assembly (e.g., if no `using` statements exist, `MyDispose` is not injected).

## Detection Signatures

- **Method names** (pre-rename): `JIEJIEHelper::Monitor_Enter`, `JIEJIEHelper::Monitor_Enter2`, `JIEJIEHelper::MyDispose`
- **Call pattern**: `call` to a static method accepting `object` that internally calls `Monitor.Enter` or `IDisposable.Dispose`

## dotscope Handling

Handled by the `ResourceRestorationPass` which redirects `JIEJIEHelper` calls back to their original BCL targets, and by the generic cleanup/neutralization pipeline which removes the `JIEJIEHelper` class after all call sites have been restored.
