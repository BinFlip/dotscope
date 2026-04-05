# NoNamespaces

| Property | Value |
|----------|-------|
| **Protection** | `NoNamespaces` |
| **Class** | `Protection` |
| **Category** | Renaming |
| **Targets** | Type definitions |
| **Attributes** | `[DoNotResolve(MemberInclusionFlags.SpecialRuntime)]` |

## Overview

Removes the namespace from all type definitions by setting the `Namespace` property to an empty string. This flattens the type hierarchy so all types appear in the global namespace.

## Algorithm

```csharp
foreach (var type in members.OfType<TypeDefinition>())
{
    if (type.Namespace is not null)
    {
        type.Namespace = string.Empty;
    }
}
```

## Key Details

- Usually combined with `FullRenamer` for maximum name obfuscation
- The namespace is simply cleared — no record of the original namespace is kept

## Detection Signatures

- All user-defined types have empty namespaces
- Combined with `FullRenamer`'s space-containing names

## dotscope Handling

Namespace removal is a lossy transformation — original namespaces cannot be recovered. Detected as part of `BitMonoRenamer` technique evidence.
