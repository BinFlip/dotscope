# Anti Dump Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.AntiDump` |
| **Short ID** | `anti dump` |
| **Preset** | Maximum |
| **Targets** | Modules |
| **Pipeline Stage** | PreStage of ProcessModule |
| **Dependencies** | Must run before `Ki.ControlFlow` |

## Overview

Prevents the assembly from being dumped from memory by corrupting PE headers and CLR metadata structures at runtime. After the module loads and the CLR has parsed the metadata, the protection overwrites critical header fields, making memory-dumped copies unloadable.

## Configuration

No configuration parameters.

## Injection Mechanism

1. Injects `Confuser.Runtime.AntiDump` type into the module's global type
2. Extracts the `Initialize()` static method
3. Inserts `call Initialize` at position 0 of the module `.cctor`
4. All injected members are renamed and have visibility reduced to internal

## Runtime Algorithm

The `Initialize()` method performs destructive PE header manipulation using two code paths based on how the module was loaded.

### Mapped Module Mode

Triggered when `Module.FullyQualifiedName[0] != '<'` (normal file-based loading).

Operates on raw memory at `Marshal.GetHINSTANCE(module)`:

1. **Locate PE headers**: Read PE signature offset from DOS header at `+0x3C`
2. **Read section info**: Extract number of sections from `+0x06`, optional header size from `+0x14`
3. **Change memory protection**: `VirtualProtect` to `PAGE_EXECUTE_READWRITE` (`0x40`)
4. **Corrupt Import Directory**:
   - Module name overwritten to `"ntdll.dll"` (encoded as uint32 constants: `0x6c64746e`, `0x6c642e6c`, `0x006c`)
   - Function name overwritten to `"NtContinue"` (encoded: `0x6f43744e`, `0x6e69746e`, `0x6575`)
5. **Wipe PE Section Headers**: Zero out all section header entries (stride `0x28` per section)
6. **Destroy Metadata Directory**: Zero the CLR Runtime Header directory entry in Optional Header
7. **Corrupt Metadata Header**: Clear the version signature field
8. **Wipe Stream Names**: Iterate all metadata streams and zero their name bytes (up to 8 chars per stream, with 4-byte alignment padding)

### Flat Module Mode

Triggered when `Module.FullyQualifiedName[0] == '<'` (in-memory/resource loading).

Performs the same operations but converts Virtual Addresses (VA) to Raw Addresses (RA):

1. Builds section address tables: `vAdrs[]` (virtual), `vSizes[]`, `rAdrs[]` (raw)
2. For each pointer dereference, finds the containing section and converts: `RA = VA - vAdr + rAdr`

### PE Offset Map

| Offset | From | Field |
|--------|------|-------|
| `+0x3C` | DOS Header | PE signature offset |
| `+0x06` | PE Header | Number of sections (ushort) |
| `+0x14` | PE Header | Optional header size |
| `-0x78` from OptHdr end | Optional Header | Import Directory RVA |
| `-0x16` from OptHdr end | Optional Header | CLR Runtime Header RVA |
| `+0x28` stride | Section Headers | Per-section entry size |

## What Gets Corrupted

| Component | Corruption | Effect |
|-----------|-----------|--------|
| Import Directory | Module/function names replaced | Import resolution fails |
| Section Headers | Zeroed completely | Section mapping impossible |
| Metadata Directory | RVA/size zeroed | CLR metadata unreachable |
| Metadata Header | Version signature cleared | Metadata parser rejects |
| Stream Names | Zeroed | Individual heaps unlocatable |

## dotscope Handling

Handled by `NeutralizationPass` — the injected `.cctor` call and associated types are removed during cleanup. The on-disk PE is unaffected (corruption only happens at runtime in memory).
