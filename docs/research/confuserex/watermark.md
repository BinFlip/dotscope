# Watermarking Protection

| Property | Value |
|----------|-------|
| **ID** | `Cx.Watermark` |
| **Short ID** | `watermark` |
| **Preset** | None (always applied automatically) |
| **Targets** | Modules |
| **Pipeline Stage** | PostStage of EndModule |
| **Dependencies** | None |

## Overview

Embeds a custom attribute identifying the assembly as protected by ConfuserEx. Always applied regardless of configuration. Serves as a signature and psychological deterrent.

## Configuration

No configuration parameters. Cannot be disabled.

## Algorithm

1. **Type creation**: Creates a new `ConfusedByAttribute` class inheriting from `System.Attribute`
2. **Constructor injection**: Creates `.ctor(string)` with body:
   ```
   ldarg.0
   call System.Attribute::.ctor()
   ret
   ```
3. **Attribute application**: Adds `[ConfusedBy("ConfuserEx vX.Y.Z")]` custom attribute to the module, where the version string is `ConfuserEngine.Version`

## Metadata Changes

- Adds one `TypeDef` row for `ConfusedByAttribute`
- Adds one `MethodDef` row for the constructor
- Adds one `CustomAttribute` row on the module

## dotscope Handling

Used as a **detection signature** by `ConfuserExDebug`. The `ConfusedByAttribute` type and attribute are removed during cleanup.
