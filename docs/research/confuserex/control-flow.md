# Control Flow Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.ControlFlow` |
| **Short ID** | `ctrl flow` |
| **Preset** | Normal |
| **Targets** | Methods |
| **Pipeline Stage** | PreStage of OptimizeMethods |
| **Dependencies** | Many protections declare "before ControlFlow" |

## Overview

Mangles the control flow of method bodies by replacing straightforward instruction sequences with switch-based or jump-based dispatch tables. This makes decompilation extremely difficult or impossible, as tools cannot reconstruct the original control flow graph. The protection supports two mangling strategies and three predicate types that combine for varying levels of obfuscation strength.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `type` | `Switch`, `Jump` | `Switch` | Mangling algorithm |
| `predicate` | `Normal`, `Expression`, `x86` | `Normal` | Key transformation method |
| `intensity` | 0–100 | 60 | Probability of splitting at each opportunity (%) |
| `depth` | 1–N | 4 | Recursion depth for expression predicates |
| `junk` | `true`/`false` | `false` | Add dead code branches |

## Architecture

### Block Infrastructure

Method IL is parsed into a hierarchical block structure before mangling:

- **ScopeBlock**: Represents exception handling scopes (try/catch/finally/filter/fault). Contains child blocks.
- **InstrBlock**: Leaf nodes containing raw CIL instructions. Maps to basic blocks.

The `BlockParser` creates this hierarchy by tracking exception handler boundaries (`TryStart`/`TryEnd`/`HandlerStart`/`HandlerEnd`/`FilterStart`) and grouping instructions into appropriate scopes.

### Pre-computation: Instruction Trace

Before mangling, a `Trace` struct computes stack depth at each instruction offset:

- `BeforeStack[offset]`: Stack depth before instruction executes
- `AfterStack[offset]`: Stack depth after instruction executes
- `RefCount[offset]`: How many control paths reach this offset
- `BrRefs[offset]`: Which branch instructions target this offset

Special handling:
- Exception handler try blocks: stack = 0
- Catch/filter handler entries: stack = 1 (exception object)
- Finally handler entries: stack = 0

## Switch Mangler (Default)

The primary and most complex mangling strategy. Transforms method bodies into state-machine-driven dispatch loops.

### Algorithm

**Phase 1: Statement splitting**

Breaks each basic block into logical "statements" at boundaries where the stack depth is 0:

- Cannot split when stack != 0 (IL verifier would reject)
- Cannot split before branch targets
- Splitting probability controlled by `intensity` parameter
- Requires minimum 3 statements to proceed

**Phase 2: Constructor handling**

For instance constructors, all statements up to (and including) the `.ctor` call are consolidated into the first statement. .NET requires `.ctor` execution before any other dispatch can occur.

**Phase 3: Key generation**

For N statements, generates N random keys such that:

```
key[i] % N == keyId[i]  (where keyId is a random permutation of [0..N-1])
```

This ensures each key uniquely identifies its target statement via modular arithmetic.

**Phase 4: Switch header construction**

Creates the dispatch header:

```
ldc.i4    predicate.GetSwitchKey(key[1])    // Load encrypted initial key
[predicate.EmitSwitchLoad]                  // Decrypt key
dup
stloc     {stateLocal}                      // Store decrypted state
ldc.i4    N                                 // Statement count
rem.un                                      // Compute dispatch index
switch    {case0, case1, ..., caseN-1}      // Dispatch table
br        lastStatement                     // Fallthrough guard
[optional junk code]
```

**Phase 5: Statement wiring**

Each statement (except the first, which is the switch entry) is wired into the dispatch table:

**Unconditional branch (br/br.s):**
- Removes the branch instruction
- Appends key computation for the target statement:
  - If statement has unknown sources (external jumps): emits literal key `ldc.i4 targetKey`
  - Otherwise: uses XOR-multiply obfuscation: `ldloc state; ldc.i4 r; mul; ldc.i4 (thisKey*r)^targetKey; xor`
- Jumps back to switch header

**Conditional branch (brtrue, beq, etc.):**
- Removes the conditional branch
- Randomly flips branch logic (inverts opcode, swaps targets)
- Both paths (taken/not-taken) compute different keys leading to correct target statements
- Uses the same XOR-multiply pattern for key encoding

**Normal fallthrough:**
- Appends key computation for the next sequential statement
- Jumps back to switch header

**Phase 6: Reordering**

Statements are reordered randomly:
1. First statement (switch header) stays at position 0
2. Last statement stays at end (prevents infinite loops)
3. Middle statements are shuffled randomly

### Complete Transformation Example

```
// Original
ldc.i4.1    // stmt 0
ldc.i4.2    // stmt 1
add         // stmt 2
ret         // stmt 3

// After Switch mangling (conceptual)
[switch_header]        // load key, decrypt, dispatch
  [stmt_2: add]        // shuffled
  [stmt_1: ldc.i4.2]   // shuffled
  [stmt_0: ldc.i4.1]   // wired to case
  [stmt_3: ret]         // always last
```

Each statement ends with a key update + jump back to the switch header.

## Jump Mangler (Lightweight)

A simpler alternative that fragments code and reorders fragments:

1. **Fragment splitting**: Randomly splits at instruction boundaries (respecting intensity). Does not split prefix instructions, delegate patterns, or array initializers.
2. **Fragment linking**: Adds `br next_fragment` after each fragment (except last)
3. **Fragment reordering**: Keeps first and last fragments in place, shuffles middle fragments
4. **Optional junk code**: Adds dead code between fragments

Much less obfuscation than Switch but faster processing and lower overhead.

## Predicates

Predicates transform the switch dispatch key, adding a layer of obfuscation to the state computation.

### Normal Predicate (XOR)

Simplest predicate — single XOR operation:

```csharp
// Compile-time: encrypt key
GetSwitchKey(key) → key ^ xorKey

// Runtime: decrypt
EmitSwitchLoad → { ldc.i4 xorKey; xor }
```

Trivial to reverse with one XOR.

### Expression Predicate (DynCipher)

Uses `IDynCipherService` to generate a random mathematical expression pair:

```csharp
// Compile-time: generate forward expression
expression:  key → encrypted_key
inverse:     encrypted_key → key

// Compile forward as .NET delegate for use during protection
expCompiled = DMCodeGen.GenerateCIL(expression).Compile<Func<int,int>>()

// Emit inverse as IL for runtime decryption
EmitSwitchLoad → { stloc stateVar; [inverse IL...] }
```

The expressions involve nested operations (add, sub, mul, xor, not, negate) to configurable depth. Much harder to reverse than Normal — requires symbolic analysis or emulation.

### x86 Predicate (Native Code)

The strongest predicate — compiles the inverse expression to native x86 machine code:

1. Generates expression pair (same as Expression predicate)
2. Compiles the inverse expression to x86 assembly via `x86CodeGen`
3. Creates a native method in the module:
   ```csharp
   MethodAttributes.PinvokeImpl | MethodAttributes.PrivateScope
   MethodImplAttributes.Native | MethodImplAttributes.Unmanaged | MethodImplAttributes.PreserveSig
   ```
4. Injects native code via `ModuleWriter` event hooks
5. Runtime dispatch calls the native method:
   ```
   EmitSwitchLoad → { call native_method }
   ```

PE modifications:
- Removes `ComImageFlags.ILOnly` flag (required for native code sections)

Reversing requires x86 disassembly and analysis of the native function.

## Exception Handler Preservation

Control flow mangling must not corrupt exception handling:

1. `BlockParser` creates scope hierarchy mirroring `ExceptionHandler` entries
2. Manglers only operate within `InstrBlock` children (never across handler boundaries)
3. After mangling, `ProcessMethod` updates handler boundary references:
   ```csharp
   eh.TryEnd = body.Instructions[body.Instructions.IndexOf(eh.TryEnd) + 1]
   eh.HandlerEnd = body.Instructions[body.Instructions.IndexOf(eh.HandlerEnd) + 1]
   ```
4. Stack depth at handler entries is validated (try=0, catch/filter=1, finally=0)

## Junk Code Generation

When `junk=true` and CLR < 4.0, inserts dead code:

- `pop`, `dup`, `throw`
- Invalid `ldarg`/`ldloc` indices
- `ldtoken` with random tokens
- Unconditional jumps disguised as conditional: `ldc.i4.0; brtrue` or `ldc.i4.1; brfalse`

CLR 4.0+ has stricter verification, so junk is disabled for those targets.

## Strength Assessment

| Configuration | Decompilability | Reversibility |
|---------------|-----------------|---------------|
| Jump (any predicate) | Partially decompilable | Easy |
| Switch + Normal | Cannot decompile | Easy (single XOR) |
| Switch + Expression | Cannot decompile | Medium (symbolic analysis needed) |
| Switch + x86 | Cannot decompile | Hard (native code reversal) |

dotscope implements this via SSA-based constant propagation in the `CffReconstructionPass`.
