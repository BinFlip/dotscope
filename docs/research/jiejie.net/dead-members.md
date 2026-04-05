# Dead Member Removal

| Property | Value |
|----------|-------|
| **Protection** | Dead Member Removal |
| **Class** | `DCJieJieNetEngine` (`RemoveMember`, line 2806) |
| **Category** | Metadata (structural obfuscation) |
| **Targets** | Enum constants, const fields, properties (post-rename) |
| **Configuration** | `RemoveMember` switch (enabled by default, requires `Rename`) |
| **Dependencies** | Requires `Rename` to have run first |

## Overview

JIEJIE.NET removes metadata entries that become unnecessary after renaming. This is a cleanup optimization, not a standalone protection — it only operates on members that have already been renamed.

## Algorithm

Source: `RemoveMember()` (line 2806)

### What Is Removed

- **Enum constants**: Removed from renamed enums (the `value__` field is preserved)
- **Const fields**: Removed if renamed and not in the override inheritance list
- **Properties**: Removed if their getter/setter (or both) have been renamed and are not in override lists

### Conditions

- Target must have been renamed by the prior renaming pass
- Target must not be in the method override inheritance list (virtual method chains)
- Parent class must not implement interfaces (for property removal — interface contract properties must be preserved)

## Detection Signatures

No detection signature — this is metadata absence, not presence. Removed members leave no trace.

## dotscope Handling

Nothing to reverse. Removed metadata cannot be reconstructed — the original names and definitions are permanently lost. This is inherent to the obfuscation.
