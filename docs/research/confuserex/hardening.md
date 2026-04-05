# Hardening Protection

| Property | Value |
|----------|-------|
| **ID** | `Cx.Harden` |
| **Short ID** | `harden` |
| **Preset** | Minimum |
| **Targets** | Modules |
| **Pipeline Stage** | PreStage of OptimizeMethods |
| **Dependencies** | Requires other protections to have injected helpers first |

## Overview

Post-processes protection-injected code by inlining helper method bodies directly into the module `.cctor`. This reduces the number of exposed helper methods (reducing attack surface) and makes protection code harder to isolate and remove.

## Configuration

No configuration parameters.

## Algorithm

The `HardeningPhase` scans the module's global type static constructor:

1. **Iterate `.cctor` instructions in reverse** looking for `Call` opcodes
2. **Filter candidates**: Only processes methods that are:
   - Static
   - Declared in the module's global type (`<Module>`)
   - Marked as helper methods by `IMarkerService`
   - Whose parent protection is **not** `ResourceProtection` (incompatible — resources protection needs isolated methods for runtime rewriting)
3. **Inline**: Calls `MergeCall()` to inline the helper method body into `.cctor`
4. **Cleanup**: Removes the now-inlined helper method from the global type

## Incompatibilities

- **ResourceProtection**: Explicitly excluded. Resource protection requires isolated helper methods for its dynamic rewriting mechanism at runtime. Inlining would break this.
- Depends on other protections having already injected their helpers (runs at OptimizeMethods stage, after most injections at ProcessModule)

## Effect

Before hardening:
```
.cctor:
    call AntiDebug::Initialize()
    call AntiDump::Initialize()
    call Constants::Initialize()
    ...user code...
```

After hardening:
```
.cctor:
    [inlined AntiDebug body]
    [inlined AntiDump body]
    [inlined Constants body]
    ...user code...
```

Helper methods `Initialize()` are removed from the type.

## dotscope Handling

Handled by `NeutralizationPass` which uses bidirectional taint analysis to identify and remove inlined protection code from the `.cctor`, even when hardening has merged multiple protection initializations into a single body.
