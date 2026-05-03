# SuppressIldasm — Anti-Disassembly (Metadata Invalidation)

Analysis of .NET Reactor 7.5.0 SuppressIldasm protection based on reverse engineering
`reactor_suppressildasm.exe` (19,968 bytes, 55 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 19,968 | +5,632 (39.3%) |
| MethodDef rows | 35 | 55 | +20 |
| Methods with bodies | 35 | 51 | +16 actual new methods |


## Invalid Metadata Injection

The SuppressIldasm protection operates primarily through **metadata corruption** rather
than IL-level transformation. It injects deliberately malformed metadata to break
parsers:

### 1. Duplicate Assembly Table Row

.NET Reactor injects a **second row into the Assembly table**. ECMA-335 mandates at most
1 Assembly row. Microsoft's ildasm refuses to open assemblies with >1 Assembly row.

The second row has an **invalid public key blob reference** (out-of-bounds blob read),
making it impossible to fully parse without error handling.

### 2. Out-of-Bounds GUID Reference

The Module table row 1 has an out-of-range GUID index. The #GUID heap is 32 bytes
(2 GUIDs) but the index points beyond, causing parsers without bounds checking to crash.

### 3. Empty TypeRef Name

Token `0x0100003D` is a TypeRef with a deliberately empty name string. This breaks type
resolution in tools that assume all TypeRefs have non-empty names.

### 4. Anti-Disassembly Branch Prefixes

Several injected methods start with `br.s +5` — an unconditional short branch that
skips 5 bytes of junk. This creates unreachable dead code that confuses linear
disassemblers (those that disassemble sequentially rather than following control flow).

Methods with anti-disassembly prefix:
- `<Module>::m8DE92F4ED95F229` (trial guard)
- `<Module>::.cctor`
- `AsG4wKEPrjKTCY31dc.uy4ZXuP8hhYiKuNrl4::Bo6WBqpvg` (delegate proxy)


## Loading Requirements

This sample **fails to load in strict validation mode** due to the metadata corruption.
Requires `ValidationConfig::analysis()` (lenient mode) for dotscope to parse it.


## Deobfuscation Strategy

1. **Remove duplicate Assembly row**: Delete the second (invalid) Assembly table entry
2. **Fix GUID reference**: Correct the out-of-bounds Module GUID index
3. **Remove empty TypeRef**: Delete or fix token `0x0100003D`
4. **Remove `br.s` prefixes**: NOP out the anti-disassembly branch stubs

These are metadata-level repairs that can be performed in the byte-transform phase,
similar to BitMono's PE repair (`bitmono.pe`).
