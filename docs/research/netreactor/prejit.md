# Pre-JIT Native Code Conversion

Analysis of .NET Reactor 7.5.0 Pre-JIT protection based on reverse engineering
`reactor_prejit.exe` (19,456 bytes, 55 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 19,456 | +5,120 (35.7%) |
| TypeDef rows | 13 | 30 | +17 |
| MethodDef rows | 35 | 55 | +20 |
| CLR flags | 0x00000001 | 0x00000001 | unchanged |


## Observation: No Managed-Level Impact

The pre-JIT sample is **structurally identical to the compression sample** at the
managed metadata level. All original methods are preserved with their original names
and unmodified bodies. The PE file size, method count, and metadata size are identical
to `reactor_compression.exe`.

The CLR flags do NOT include `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` (0x10), confirming
that the managed assembly metadata is standard.

Pre-JIT optimization operates at the **native loader level** — .NET Reactor's native
stub/wrapper handles precompilation, not the managed assembly metadata that dotscope
parses. The managed assembly that dotscope sees is the standard payload after the
native loader has extracted it.


## Injected Infrastructure

Only the standard NR baseline infrastructure (see [shared-infrastructure.md](shared-infrastructure.md)):
- `<Module>::m8DE92F4EF08EEB8` — Trial guard
- `<Module>::.cctor` — Calls trial guard
- `ObfuscationAttribute` — Marker attribute
- `AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4` — Delegate proxy
- `UWxvxUSU2ZrCqT9K8B.gttro5yuWySr2hbdEM` — License check


## Deobfuscation Notes

No managed-level deobfuscation needed. Pre-JIT is transparent once the managed payload
is extracted from the native wrapper. The standard NR infrastructure cleanup handles
the injected types.
