# BitDotNet

| Property | Value |
|----------|-------|
| **Protection** | `BitDotNet` |
| **Class** | `PackerProtection` |
| **Category** | PE (header corruption) |
| **Targets** | PE file (post-write) |
| **Compatibility** | Mono only (`[RuntimeMonikerMono]`) |

## Overview

Corrupts both the PE header signature and the CLR metadata directory to break standard .NET tooling. The corruption prevents tools from recognizing the file as a valid .NET assembly, while Mono's more lenient runtime can still load it.

## Algorithm

Operates on raw bytes of the written PE file:

1. **Read PE header offset** from DOS header at `0x3C`
2. **Corrupt PE signature**: Write `0x00014550` at the PE header offset
   - Standard PE signature is `0x00004550` ("PE\0\0")
   - The extra byte (`0x01` instead of `0x00`) makes the signature invalid
3. **Locate CLR data directory**: Navigate through PE sections to find the .NET metadata RVA
4. **Zero CLR header fields**:
   - CLR header `cb` (size) → 0
   - CLR runtime version → 0
   - Metadata VA → 0

## PE Layout

```
Offset 0x3C:  PE header offset (4 bytes)
PE header:    [50 45 00 00] → Modified to [50 45 00 01]
              ...
              CLR data directory → RVA to .NET header

CLR header:   [cb:4] [version:4] [metadata_va:4] → All zeroed
```

## Impact

- `goblin` PE parser rejects the modified PE signature
- dnlib/AsmResolver reject zeroed metadata RVA
- dnSpy/ILSpy cannot load the assembly
- Mono runtime ignores these fields and loads successfully

## Detection Signatures

- PE signature is `0x00014550` instead of `0x00004550`
- CLR header size/version/metadata fields are zeroed
- Assembly is otherwise structurally valid .NET

## dotscope Handling

Handled by `BitMonoPeRepair` technique. dotscope's PE loader transparently detects the corrupted PE signature and zeroed CLR header during loading and repairs them before the assembly reaches the deobfuscation pipeline. The repairs are recorded as detection evidence.
