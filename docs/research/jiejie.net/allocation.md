# Allocation Call Stack Hiding

| Property | Value |
|----------|-------|
| **Protection** | Allocation Call Stack Hiding |
| **Class** | `DCJieJieNetEngine` (`HandleMethod`, line 4941) |
| **Category** | Anti-Analysis (call stack obfuscation) |
| **Targets** | Methods returning `string` |
| **Configuration** | `AllocationCallStack` switch (disabled by default) |
| **Dependencies** | `JIEJIEHelper` class (`CloneStringCrossThead` method) |

## Overview

JIEJIE.NET inserts a cross-thread string clone call before every `ret` instruction in string-returning methods. The returned string object is cloned onto a different thread's memory context, which obscures the allocation call stack in memory profilers and debugging tools.

## Algorithm

Source: `HandleMethod()` (line 4941)

### Conditions

- `AllocationCallStack` switch must be enabled (off by default)
- Method must have a return type of `System.String`
- Not applied in Blazor WebAssembly mode

### Transformation

Before every `ret` instruction in a qualifying method:

```il
// Before:
ldstr      "result"
ret

// After:
ldstr      "result"
call       string __DC20211119.JIEJIEHelper::CloneStringCrossThead(string)
ret
```

### CloneStringCrossThead Implementation

The helper method creates a new thread, passes the string via closure, runs the thread (which simply assigns the string to a shared variable), joins the thread, and returns the "cloned" reference. This creates a new allocation context on a different thread, hiding the original allocation site from profiler call stacks.

## Detection Signatures

- **Method name** (pre-rename): `JIEJIEHelper::CloneStringCrossThead` (note the typo — "Thead" not "Thread")
- **Call pattern**: `call string JIEJIEHelper::CloneStringCrossThead(string)` immediately before `ret` in string-returning methods
- **Performance signature**: Significant overhead from thread creation per string return (rarely enabled in practice)

## dotscope Handling

Handled by the generic cleanup/neutralization pipeline. The `CloneStringCrossThead` call is a no-op wrapper — it can be removed by inlining or call redirection, leaving only the original string value on the stack before `ret`.
