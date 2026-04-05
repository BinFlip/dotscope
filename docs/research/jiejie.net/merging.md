# Assembly Merging

| Property | Value |
|----------|-------|
| **Protection** | Assembly Merging |
| **Class** | `DCJieJieNetEngine` (merge pipeline) |
| **Category** | Structural (assembly-level) |
| **Targets** | Multiple input assemblies |
| **Configuration** | Explicit merge list in project configuration |
| **Dependencies** | Runs before all other protections |

## Overview

JIEJIE.NET can merge multiple .NET assemblies into a single output binary. This is handled at the IL text level — after disassembly, types from secondary assemblies are injected into the primary assembly's IL document before obfuscation passes run. Assembly references are updated, and the merged types participate in all subsequent protections (string encryption, renaming, etc.).

## Algorithm

The merge operates at the IL text DOM level:
1. Each secondary assembly is disassembled via `ildasm.exe`
2. Types from secondary assemblies are parsed into `DCILClass` nodes
3. Nodes are inserted into the primary assembly's `DCILDocument`
4. Assembly references and `[assembly: InternalsVisibleTo]` attributes are updated
5. Namespace collisions are resolved by the obfuscator's renaming pass

This is a standard ILMerge-style operation, not a protection technique per se.

## Detection Signatures

No reliable detection signature. Merged assemblies are indistinguishable from a single-assembly application after obfuscation. The only heuristic would be an unusually large number of types/namespaces for the apparent application complexity.

## dotscope Handling

Out of scope. Assembly merging cannot be reversed without knowledge of the original assembly boundaries, which is not preserved in the output binary. Deobfuscation operates on the merged assembly as a single unit.
