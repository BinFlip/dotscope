# BitDecompiler

| Property | Value |
|----------|-------|
| **Protection** | `BitDecompiler` |
| **Class** | `PackerProtection` |
| **Category** | PE (header corruption) |
| **Targets** | PE file (post-write) |
| **Compatibility** | Mono only (`[RuntimeMonikerMono]`) |

## Overview

Zeros out the CLR runtime header fields to prevent standard .NET tooling from parsing the assembly metadata. Described in the source as a "fixed version of BitDotNet for newer Unity versions" — it performs the same CLR header corruption without modifying the PE signature.

## Algorithm

Operates on raw bytes of the written PE file:

1. **Read PE header offset** from DOS header at `0x3C`
2. **Locate all PE sections** to find the .NET metadata RVA
3. **Convert RVA to raw file offset**
4. **Zero CLR header fields**:
   - CLR header signature (cb) → 0
   - Metadata address → 0
   - Runtime flags → 0

Unlike [BitDotNet](bit-dotnet.md), the PE signature (`"PE\0\0"`) is **not** modified.

## Comparison with BitDotNet

| Aspect | BitDotNet | BitDecompiler |
|--------|-----------|---------------|
| PE signature corruption | Yes (`0x00014550`) | No |
| CLR header zeroing | Yes | Yes |
| Compatibility | Older Mono/Unity | Newer Unity |

## Detection Signatures

- CLR header fields are zeroed but PE signature is valid
- Assembly is otherwise structurally valid .NET

## dotscope Handling

Handled by `BitMonoPeRepair` technique — same loader-level repair as BitDotNet. The zeroed CLR header fields are reconstructed from the actual metadata in the file.
