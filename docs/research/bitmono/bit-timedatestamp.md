# BitTimeDateStamp

| Property | Value |
|----------|-------|
| **Protection** | `BitTimeDateStamp` |
| **Class** | `PackerProtection` |
| **Category** | PE (anti-forensics) |
| **Targets** | PE file (post-write) |

## Overview

Zeros out the PE header's `TimeDateStamp` field to remove the build timestamp. This is an anti-forensics measure that prevents attribution or timeline analysis based on compilation timestamps.

## Algorithm

Operates on raw bytes of the written PE file:

1. **Read PE header offset** from DOS header at `0x3C`
2. **Navigate to TimeDateStamp** at PE header + `0x08`
3. **Write 0** to clear the 4-byte timestamp

## Key Details

- The `TimeDateStamp` field is at a fixed offset (`+0x08`) from the PE signature in the COFF header
- This is a lossy transformation — the original timestamp is permanently destroyed
- No runtime impact — the timestamp is not used by the .NET runtime

## Detection Signatures

- `TimeDateStamp` field is exactly zero
- This alone is not sufficient for BitMono detection (other tools also zero timestamps)

## dotscope Handling

Detected as part of `BitMonoPeRepair` evidence. The original timestamp cannot be recovered — detection only.
