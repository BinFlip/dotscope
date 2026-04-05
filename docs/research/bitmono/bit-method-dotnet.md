# BitMethodDotnet

| Property | Value |
|----------|-------|
| **Protection** | `BitMethodDotnet` |
| **Class** | `Protection` |
| **Category** | Junk (decompiler confusion) |
| **Targets** | Method bodies |
| **Attributes** | `[DoNotResolve(MemberInclusionFlags.SpecialRuntime)]` |
| **Dependencies** | `RandomNext` |

## Overview

Inserts an unreachable junk prefix instruction at the start of each method body to confuse decompilers. A `br.s` instruction jumps over the junk, so it never executes, but decompilers that perform linear disassembly may choke on the orphan prefix opcode.

## Algorithm

For each method body (skips constructors):

1. Create a label pointing to the original first instruction
2. Insert `br.s <label>` at position 0 (unconditional jump over junk)
3. Insert a random prefix opcode at position 1 (between the branch and its target)

The random prefix is selected from one of four CIL prefix opcodes:

| Random value | Prefix opcode | Notes |
|:---:|---|---|
| 0 | `readonly.` | Requires `ldelema` following |
| 1 | `unaligned.` (operand `0`) | Requires memory instruction following |
| 2 | `volatile.` | Requires memory instruction following |
| 3 | `constrained.` | Requires `callvirt` following |

These prefix opcodes are invalid without an appropriate following instruction, which is what causes decompiler confusion.

## IL Transformation

```
// Before:
<original first instruction>
...

// After:
br.s       <original_first_instruction>      // Jump over the junk
<random_prefix_opcode>                        // Never executed — confuses decompiler
<original first instruction>
...
```

## Detection Signatures

- Method bodies starting with `br.s` followed by an orphan prefix opcode
- The branch target is the instruction immediately after the prefix
- The prefix opcode is unreachable (dead code)

## dotscope Handling

Handled by `BitMonoJunk` technique (byte-level detection). The junk prefix pattern is automatically eliminated during SSA processing — `BlockMergingPass` inlines the entry block trampoline, and code regeneration drops the unreachable prefix instruction.
