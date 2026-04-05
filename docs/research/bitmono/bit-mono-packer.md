# BitMono (Packer)

| Property | Value |
|----------|-------|
| **Protection** | `BitMono` (the packer, same name as the tool) |
| **Class** | `PackerProtection` |
| **Category** | PE (header corruption) |
| **Targets** | PE file (post-write) |
| **Compatibility** | Mono only (`[RuntimeMonikerMono]`) |

## Overview

Corrupts multiple PE optional header fields including data directory entries. This is the most comprehensive of BitMono's three PE-level packers, targeting import tables, debug directories, and the .NET data directory.

## Algorithm

Operates on raw bytes of the written PE file:

1. **Read PE header offset** from DOS header at `0x3C`
2. **Detect architecture**: Check PE optional header magic (`0x20B` = PE32+/x64, else x86)
3. **Modify fields** (offsets vary by architecture):

| Field | Value | Effect |
|-------|-------|--------|
| `NumberOfRvaAndSizes` | `0x00013` (19) | Invalid — standard value is 16 |
| Import directory size | 0 | Hides import table |
| Debug directory VA | 0 | Removes debug data reference |
| Debug directory size | 0 | Removes debug data reference |
| .NET directory size | 0 | Hides CLR header |

## Architecture-Specific Offsets

The import directory, debug directory, and .NET directory entries are at different offsets depending on whether the PE is 32-bit or 64-bit (due to different optional header sizes).

## Impact

- PE parsers that validate `NumberOfRvaAndSizes` reject the file
- Tools relying on data directory entries cannot find imports, debug info, or CLR header
- Mono runtime ignores these fields and locates metadata through other means

## Detection Signatures

- `NumberOfRvaAndSizes` is 19 instead of 16
- Import, debug, and .NET directory entries are zeroed
- Assembly is otherwise structurally valid

## dotscope Handling

Handled by `BitMonoPeRepair` technique — same loader-level repair as the other PE packers. The zeroed data directory entries and invalid `NumberOfRvaAndSizes` are reconstructed from the actual PE structure.
