# Member Declaration Order Shuffling

| Property | Value |
|----------|-------|
| **Protection** | Member Declaration Order Shuffling |
| **Class** | `DCJieJieNetEngine` (`ObfuseClassMembers`, line 5890) |
| **Category** | Metadata (structural obfuscation) |
| **Targets** | Class member declarations |
| **Configuration** | `MemberOrder` switch (enabled by default) |
| **Dependencies** | None |

## Overview

JIEJIE.NET randomizes the declaration order of members within each class. This has no runtime effect but confuses decompilers that rely on declaration order to present code in a logical sequence.

## Algorithm

1. Groups class members by category: fields, events, methods, properties, nested classes
2. Randomly shuffles each category independently using Fisher-Yates (`DCUtils.ObfuseListOrder`)
3. Reassembles in order: nested classes → fields → properties → events → methods

### Exclusions

Skipped for:
- **COM-exposed interfaces** (classes with `InterfaceTypeAttribute`) — COM requires stable member ordering
- **Structs** (value types) — field order affects memory layout
- **Enums** — member order may be semantically significant
- **Classes implementing interfaces** — skipped to avoid vtable layout issues

## Detection Signatures

No reliable detection signature. Member ordering is non-deterministic and varies per compilation. The only heuristic would be members appearing in a random-looking order compared to a developer's typical convention (fields before methods, etc.), but this is not distinctive.

## dotscope Handling

No deobfuscation needed. Member declaration order has no semantic impact on IL behavior. Decompilers may present members in a non-standard order, but the code is functionally correct.
