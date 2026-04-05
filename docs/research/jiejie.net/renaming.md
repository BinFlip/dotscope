# Symbol Renaming

| Property | Value |
|----------|-------|
| **Protection** | Symbol Renaming |
| **Class** | `DCJieJieNetEngine` (`RenameClasses`, line 4019) |
| **Category** | Renaming (metadata obfuscation) |
| **Targets** | Types, methods, fields, properties, events, parameters |
| **Configuration** | `Rename` switch (enabled by default) |
| **Dependencies** | Runs after all other protections in the pipeline (step 17) |

## Overview

JIEJIE.NET renames types, methods, fields, and parameters using a configurable prefix + base-26 encoding scheme. Renaming runs late in the pipeline (after all protections that emit named references) so that injected types and methods receive obfuscated names.

## Algorithm

### ID Generation

Base-26 encoding using alphabet `"lkjhgfdsaqwertyuiopmnbvcxz"`:
```
counter → variable-length string
Examples: 0→"l", 1→"k", 25→"z", 26→"kl", 27→"kk", ...
```

Naming conventions:
- **Types**: `PrefixForTypeRename` + base26 → `_jiejiel`, `_jiejiek`, `_jiejielf`, ...
- **Members**: `PrefixForMemberRename` + base26 → `_jjl`, `_jjk`, `_jjlf`, ...
- **Parameters**: Always renamed to `p0`, `p1`, `p2`, ...
- **~2% timestamp suffix**: `_jiejieYYYYMMDDHHmmss` appended randomly

### Intentional Name Collisions

Methods with identical parameter signatures within a class all receive the **same** new name. This creates intentional overload collisions that confuse decompilers while remaining valid IL (overloads can differ only by return type in CIL, unlike C#).

### Preserved Names

- Constructors (`.ctor`/`.cctor`)
- `Main` entry point methods
- P/Invoke methods
- `IAsyncStateMachine` implementing types
- Blazor `JSInvokableAttribute` methods
- COM-imported types
- Types/members with `ObfuscationAttribute(Exclude=true)`
- Enum `value__` field
- Types in the `PreserveTypeNames` list

### Post-Rename Actions

- `specialname` attribute removed from renamed property accessor methods
- Property/event definitions deleted when their accessors are renamed
- `EditorBrowsableAttribute(Never)` added to renamed public members
- `InternalsVisibleToAttribute` removed from assembly
- `.map.xml` file generated for stack trace translation

## Detection Signatures

- **Type name pattern**: `_jiejie[a-z]+` (configurable prefix, default `_jiejie`)
- **Member name pattern**: `_jj[a-z]+` (configurable prefix, default `_jj`)
- **Parameter names**: All `p0`, `p1`, `p2`, ...
- **Many method overloads**: Multiple methods with different return types but same name and parameters

## dotscope Handling

Renaming is inherently irreversible — original names are permanently lost. The `.map.xml` file, if available, could be used to restore names, but this is typically not available for third-party or malware samples. JIEJIE.NET naming patterns (`_jiejie*`/`_jj*`) serve as attribution signals during obfuscator detection.
