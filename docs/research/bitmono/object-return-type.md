# ObjectReturnType

| Property | Value |
|----------|-------|
| **Protection** | `ObjectReturnType` |
| **Class** | `Protection` |
| **Category** | Metadata (type obfuscation) |
| **Targets** | Method signatures |
| **Attributes** | `[DoNotResolve(MemberInclusionFlags.SpecialRuntime)]` |

## Overview

Changes the declared return type of methods that return `bool` to `object`. The actual runtime behavior is preserved through implicit boxing, but static analysis tools see `object` instead of `bool`, obscuring the method's semantics.

## Algorithm

For each method returning `System.Boolean`:

1. **Skip**: constructors, virtual methods, property getters/setters, async methods, methods with `out`/`in` parameters
2. **Change**: return type from `bool` to `object`

The method body is not modified — `ldc.i4.0`/`ldc.i4.1` values are boxed implicitly by the CLR when returned as `object`.

## Detection Signatures

- Methods whose bodies clearly return bool values (`ldc.i4.0`/`ldc.i4.1` at return points) but declare `object` return type
- Usually combined with other BitMono protections

## dotscope Handling

Not yet implemented. Reversal would analyze method bodies to detect bool return patterns and restore `bool` return type. Low priority — purely cosmetic, does not affect decompilation correctness.
