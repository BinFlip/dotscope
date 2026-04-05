# Control Flow Obfuscation

| Property | Value |
|----------|-------|
| **Protection** | Control Flow Obfuscation |
| **Class** | `DCJieJieNetEngine` (`ObfuscateOperCodeListNew2` / `ObfuscateOperCodeList_Rude`) |
| **Category** | Code (control flow flattening) |
| **Targets** | Method bodies with sufficient instruction count |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | `Int32ValueContainer` (switch indices and opaque predicate constants stored as container field loads) |

## Overview

JIEJIE.NET implements two control flow obfuscation algorithms, selected based on method characteristics:

1. **Algorithm A** (Primary): Switch-based dispatcher — shuffles instruction groups, routes via a central `switch` instruction. Used when 2+ groups can be formed.
2. **Algorithm B** (Fallback): Rude mode with opaque predicates — used when Algorithm A can only produce one group (method has >100 instructions but no stack-zero split points).

## Algorithm A: Switch-Based Dispatcher

Source: `ObfuscateOperCodeListNew2()` (line 7824)

### Step 1: Instruction Grouping

- Method IL is split into groups of **20–30 instructions** (size randomized per split)
- Groups can **only be split at stack-level 0 boundaries** — ensures each group is stack-neutral
- Special patterns kept together: `dup/brtrue/pop/br`, branch-over-push patterns
- Prefix instructions (`volatile.`, `constrained.`, `unaligned.`, `tail.`, `readonly.`) stay with their following instruction
- The `ret` instruction is detached from its group and placed at the very end

### Step 2: Null/Bogus Group Injection

- Between `N` and `N * 1.5` null entries are added (where N = real group count)
- The combined list (real + null) is shuffled using Fisher-Yates (`DCUtils.ObfuseListOrder`)
- Null entries serve as **decoy switch targets** — they point to random real groups

### Step 3: Switch Dispatcher Construction

```il
nop
ldsfld int32 __DC20210205._Int32ValueContainer::_N_42    // index of first real group
br IL_SWITCH                                               // jump to switch
IL_POP:
pop                                                        // secondary entry (discards extra value)
IL_SWITCH:
switch (IL_BLK3, IL_BLK1, IL_BLK0, IL_BLK2, IL_BLK1, ...) // real + decoy targets
```

### Step 4: Inter-Group Chaining

Each group (except the last) is appended with a branch back to the switch.

**Direct chain (50% probability):**
```il
IL_BLKn:
    ... original instructions ...
    ldsfld int32 __DC20210205._Int32ValueContainer::_N_7   // next group's index
    br IL_SWITCH
```

**Indirect chain with decoy (50% probability):**
```il
IL_BLKn:
    ... original instructions ...
    ldsfld int32 __DC20210205._Int32ValueContainer::_N_7   // next group's index
    ldsfld int32 __DC20210205._Int32ValueContainer::_N_99  // random decoy value
    br IL_POP                                               // goes through pop first
```

### Step 5: Short-to-Long Expansion

All short branch instructions (`beq.s`, `br.s`, `brtrue.s`, `brfalse.s`, `leave.s`, etc.) are converted to their long forms to avoid offset issues after reordering.

## Algorithm B: Rude Mode with Opaque Predicate

Source: `ObfuscateOperCodeList_Rude()` (line 8168)

Used when Algorithm A produces only 1 group (method has >100 instructions but the evaluation stack never reaches zero at group boundaries — common in expression-heavy code).

### Key Differences from Algorithm A

1. **No stack-zero requirement**: Groups are split at fixed intervals of 20 instructions regardless of stack state
2. **No switch dispatcher**: Groups are chained via direct `br` instructions
3. **Opaque predicate entry**: An extra local variable and shadow code block select the entry point

### Shadow Code Block

The first real group is **cloned** to produce a "shadow" copy with mutated instructions:
- `ldc.i4`/`ldc.i4.s` constants have random offsets added/subtracted
- Branch comparisons (`ble`, `bgt`, `blt`, `bne`) are randomly swapped
- Arithmetic ops (`add`, `sub`, `div`, `mul`, `xor`, `and`) are randomly swapped
- `brtrue` ↔ `brfalse` swapped

### Entry Selection

A known constant `flag` (random 30–100) is loaded from `Int32ValueContainer`:

**50% probability — "greater than" form:**
```il
ldsfld int32 _Int32ValueContainer::_flag          // value = flag
ldc.i4 (flag - 10)                                 // always less than flag
bgt IL_REAL_FIRST_BLOCK                            // always taken
br IL_SHADOW_BLOCK                                 // never taken (dead code)
```

**50% probability — "less than" form:**
```il
ldsfld int32 _Int32ValueContainer::_flag
ldc.i4 (flag + 10)                                 // always greater than flag
bgt IL_SHADOW_BLOCK                                // never taken
br IL_REAL_FIRST_BLOCK                             // always taken
```

### Spurious Conditional Branches

After every comparison branch in the real code:
```il
ldloc extLocalIndex         // opaque predicate local (always 0 or always 1)
brtrue/brfalse IL_END       // always evaluates to false — dead branch
```

## Detection Signatures

### Algorithm A

- Method starts with `nop` + `ldsfld` (from `Int32ValueContainer`) + `br`
- A `pop` instruction before the `switch`
- Central `switch` instruction with many targets (some duplicated — the decoys)
- Each block ends with `ldsfld` + `br` back to the switch
- All `Int32ValueContainer` field loads instead of `ldc.i4` literals
- No short branch forms — everything is long form

### Algorithm B

- Method starts with `ldsfld` + `ldc.i4` + `bgt`/`blt` + `br` (opaque predicate)
- A shadow code block with semantically mutated instructions
- Extra local variable initialized to 0 or 1
- Spurious `ldloc`/`brtrue` or `ldloc`/`brfalse` pairs after every real branch
- Blocks chained via direct `br` instructions (no central switch)

## dotscope Handling

Algorithm A is a classic control flow flattening pattern handled by the generic `CffReconstructionPass`. After `Int32ValueContainerPass` resolves all container field loads to concrete `ldc.i4` constants, the switch dispatcher becomes a standard CFF dispatch table that the existing pass reconstructs. Algorithm B is handled by constant propagation + dead code elimination: the opaque predicate resolves to a constant comparison (always-true/always-false), the shadow block becomes unreachable dead code, and the spurious conditionals are eliminated by constant folding.
