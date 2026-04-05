# Invalid Metadata Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.InvalidMD` |
| **Short ID** | `invalid metadata` |
| **Preset** | None (must be explicitly enabled) |
| **Targets** | Modules |
| **Pipeline Stage** | PostStage of BeginModule |
| **Dependencies** | None |

## Overview

Adds invalid and malformed metadata entries to confuse disassemblers, decompilers, and analysis tools. Works by hooking into the module writer's metadata creation events to inject garbage data into metadata tables and heaps.

## Configuration

No user-configurable parameters. Uses `IRandomService` with key `"Ki.InvalidMD"` for deterministic random generation.

## Algorithm

The protection hooks two `ModuleWriterBase` events:

### MDEndCreateTables Event

Executes after all metadata tables are created but before finalization:

1. **Spurious Module row**: Adds a Module table entry with invalid name/MVID indices (`0x7fff7fff`)
2. **Spurious Assembly row**: Adds an Assembly table entry with invalid name index
3. **ENCLog entries**: Adds 8-16 random `ENCLogTable` entries (Edit & Continue log — normally only present in incremental compilations)
4. **ENCMap entries**: Adds 8-16 random `ENCMapTable` entries
5. **ManifestResource shuffle**: Randomizes the order of `ManifestResourceTable` rows
6. **ExtraData**: Sets random `ExtraData` value in `TablesHeap` options (unused field in ECMA-335)
7. **Version string corruption**: Appends null bytes to the metadata version string header
8. **Fake heaps**: Adds custom metadata streams with garbage data:
   - `#GUID` — single new GUID (16 bytes)
   - `#Strings` — single byte array
   - `#Blob` — single byte array
   - `#Schema` — single byte array (non-standard stream name)

### MDOnAllTablesSorted Event

Executes after table sorting:

1. **Invalid DeclSecurity**: Adds a `DeclSecurityTable` row with maxed-out indices (`0x7fff`, `0xffff7fff`)

## What Gets Corrupted

| Component | Corruption | Tool Impact |
|-----------|-----------|-------------|
| Module table | Extra row with invalid indices | Confuses metadata readers |
| Assembly table | Extra row with invalid name | Assembly identity confusion |
| ENCLog/ENCMap | Random entries | Triggers E&C handling paths |
| ManifestResource | Shuffled order | Ordinal-based lookups break |
| TablesHeap | Random ExtraData | Header parsing issues |
| Stream headers | Extra streams with garbage | Heap enumeration confusion |
| DeclSecurity | Invalid row | Permission checking failures |

## dotscope Handling

dotscope's metadata parser handles all invalid entries gracefully (extra table rows ignored, ENCLog/ENCMap skipped, duplicate heaps resolved, out-of-bounds indices rejected).
