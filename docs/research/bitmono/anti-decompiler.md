# AntiDecompiler

| Property | Value |
|----------|-------|
| **Protection** | `AntiDecompiler` |
| **Class** | `PipelineProtection` (with phase `AntiDnSpyAnalyzer`) |
| **Category** | Metadata (decompiler confusion) |
| **Targets** | Module type nested types |
| **Compatibility** | Mono only (`[RuntimeMonikerMono]`) |

## Overview

Sets invalid type attributes on nested `<Module>` types to crash or confuse decompilers like dnSpy. This is the only BitMono protection that uses the `PipelineProtection` pattern with a sub-phase.

## Architecture

```
AntiDecompiler : PipelineProtection
└── Phase: AntiDnSpyAnalyzer : PhaseProtection
    └── [ProtectionName("AntiDnSpyAnalyzer")]
```

## Algorithm

The `AntiDnSpyAnalyzer` phase iterates over type definitions and applies invalid attributes:

```csharp
foreach (var type in members.OfType<TypeDefinition>())
{
    if (type.IsModuleType && type.IsNested)
    {
        type.Attributes = TypeAttributes.Sealed | TypeAttributes.ExplicitLayout;
    }
}
```

Nested types of `<Module>` should not normally have `ExplicitLayout`, and the combination with `Sealed` creates an invalid metadata state that causes dnSpy to crash or produce garbage output.

## Detection Signatures

- Nested types of `<Module>` with `Sealed | ExplicitLayout` attributes
- Mono-only — not seen in .NET Framework/.NET Core assemblies

## dotscope Handling

Not specifically handled — this is a Mono-only protection rarely encountered in practice. If needed, resetting the invalid attributes on nested `<Module>` types is a trivial metadata fix.
