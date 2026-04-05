# AntiDebugBreakpoints

| Property | Value |
|----------|-------|
| **Protection** | `AntiDebugBreakpoints` |
| **Class** | `Protection` |
| **Category** | Neutralization (anti-debug) |
| **Targets** | Method bodies |
| **Attributes** | `[DoNotResolve(MemberInclusionFlags.SpecialRuntime)]` |
| **Runtime** | None (uses BCL types) |

## Overview

Injects timing-based anti-debug checks into method bodies. The injected code records the current time at method entry and checks elapsed time before method exit. If execution took longer than 5 seconds (indicating a debugger breakpoint was hit), the code triggers a divide-by-zero exception to crash the process.

## Algorithm

For each method body (skips constructors, property getters/setters, and methods already containing `Thread.Sleep` or `Task.Delay` calls):

1. Add 3 local variables: `DateTime`, `TimeSpan`, `int32`
2. At method start: capture `DateTime.UtcNow`
3. Before the last instruction: insert timing check and crash logic

## IL Transformation

```
// Injected at method start:
call       DateTime.UtcNow
stloc      dateTimeLocal

// Original method body...

// Injected before the last instruction:
call       DateTime.UtcNow
ldloc      dateTimeLocal
call       DateTime.op_Subtraction(DateTime, DateTime)
stloc      timeSpanLocal
ldloca     timeSpanLocal
call       TimeSpan.get_TotalMilliseconds()
ldc.r8     5000.0
ble.un.s   nop_label              // Skip if elapsed <= 5000ms
ldc.i4.1
ldc.i4.0
stloc      intLocal
ldloc      intLocal
div                                // Divide by zero crash
pop
nop_label: nop
```

## Imported References

The protection imports and checks for the following types to skip methods that legitimately pause execution:

- `Thread.Sleep(int)`, `Thread.Sleep(TimeSpan)`
- `Task.Delay(int)`, `Task.Delay(TimeSpan)`, `Task.Delay(int, CancellationToken)`, `Task.Delay(TimeSpan, CancellationToken)`

## Detection Signatures

- `DateTime.UtcNow` + `op_Subtraction` + `TotalMilliseconds` + `ldc.r8 5000.0` pattern
- `ble.un.s` followed by `ldc.i4.1; ldc.i4.0; div` (intentional divide-by-zero)
- Three extra locals (`DateTime`, `TimeSpan`, `int32`) per protected method
- Fixed 5000ms threshold (never configurable)

## dotscope Handling

Handled by `BitMonoAntiDebug` technique (detection) and `AntiDebugRemovalPass` (reversal). Detection identifies methods containing all three sentinel API calls (`DateTime.UtcNow`, `op_Subtraction`, `get_TotalMilliseconds`). The pass uses forward-only taint analysis seeded from these sentinel calls to identify and remove the injected timing checks and divide-by-zero crash code.
