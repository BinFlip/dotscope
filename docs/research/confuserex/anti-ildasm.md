# Anti IL Dasm Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.AntiILDasm` |
| **Short ID** | `anti ildasm` |
| **Preset** | Minimum |
| **Targets** | Modules |
| **Pipeline Stage** | PreStage of ProcessModule |
| **Dependencies** | None |

## Overview

Marks the module with a custom attribute that discourages Microsoft's IL Disassembler (ILDasm) from opening the assembly. This is a purely metadata-level protection with no runtime component.

## Configuration

No configuration parameters.

## Algorithm

1. Creates a `CustomAttribute` referencing `System.Runtime.CompilerServices.SuppressIldasmAttribute`
2. Uses the parameterless `.ctor` of the attribute
3. Adds the attribute to the module's custom attributes collection

## Effect

When ILDasm encounters this attribute, it displays a warning message and refuses to disassemble the assembly. Other tools (ILSpy, dnSpy, dotPeek) typically ignore this attribute entirely.

## Metadata Changes

- Adds one row to the `CustomAttribute` metadata table
- References the `SuppressIldasmAttribute` type (may add TypeRef if not already present)

## dotscope Handling

Attribute removed during cleanup. No code changes needed — advisory-only metadata.
