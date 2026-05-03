# Output Compression

Analysis of .NET Reactor 7.5.0 compression based on reverse engineering
`reactor_compression.exe` (19,456 bytes, 55 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 19,456 | +5,120 (35.7%) |
| TypeDef rows | 13 | 30 | +17 |
| MethodDef rows | 35 | 55 | +20 |


## Observation: No Managed-Level Impact

The compression sample is **structurally indistinguishable from the pre-JIT sample** at
the managed metadata level. PE file sizes are identical (19,456 bytes), method counts
match, metadata sizes match.

Compression operates at the **native PE wrapper/loader level** — compressing the .NET
metadata/IL payload and decompressing at load time. The managed assembly that dotscope
parses is the **decompressed** payload after the native loader has already extracted it.


## Injected Infrastructure

Only the standard NR baseline infrastructure (see [shared-infrastructure.md](shared-infrastructure.md)):
- `<Module>::m8DE92F4EFC2E526` — Trial guard
- `<Module>::.cctor` — Calls trial guard
- `ObfuscationAttribute` — Marker attribute
- `AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4` — Delegate proxy
- `UWxvxUSU2ZrCqT9K8B.gttro5yuWySr2hbdEM` — License check


## Deobfuscation Notes

No managed-level deobfuscation needed. Compression is transparent once the native
loader decompresses the payload. The standard NR infrastructure cleanup handles the
injected types.
