# Control Flow Obfuscation (Stage 2)

Analysis of .NET Reactor 7.5.0 control flow obfuscation based on reverse engineering
`reactor_controlflow.exe` (level 5, 84 methods) and `reactor_controlflow_max.exe`
(level 9, 84 methods) against `original.exe` (35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Level 5 | Level 9 |
|----------|----------|---------|---------|
| File size | 14,336 | 38,912 | 41,984 |
| MethodDef rows | 35 | 84 | 84 |
| Methods with bodies | 35 | 80 | 80 |
| Injected methods | — | +45 | +45 |


## Opaque Predicate Container Type

.NET Reactor injects a type with the pattern `<Module>{GUID}` containing 126+ instance
Int32 fields used as opaque predicates. The GUID changes per build:

- Level 5: `<Module>{dafe7df5-289c-4bd3-b0cc-94b92ab54dc9}`
- Level 9: `<Module>{e94693d3-cdca-4513-a2fb-4e5215a00797}`

### Type Structure

- **Static singleton field** (e.g., `0x040000a1` at level 5, `0x0400004a` at level 9):
  Holds the single instance of the container type
- **126 instance Int32 fields** (rows 53-179, excluding the static singleton):
  Each stores a computed constant used as an opaque predicate
- **5 methods**: `.ctor`, `.cctor`, initialization method, null-check predicate, getter

### Field Initialization

The initialization method (e.g., `x6b4a64a3603a4a09987d08ad353c4de2`) is itself
CFF-protected with a **69-case switch dispatcher**. Each case initializes one or more
fields using obfuscated constant arithmetic:

```
ldsfld  0x040000a1          // load singleton instance
ldc.i4  -322276265          // obfuscated constant
ldc.i4  5                   // shift amount
shl                         // left shift
neg                         // negate
ldc.i4  1722905888          // second constant
xor                         // XOR
stfld   0x04000059          // store to field
```

Arithmetic complexity varies:
- **Simple**: `const1 XOR const2`
- **Medium**: `const1; const2; sub; neg; const3; xor`
- **Complex**: `const1; const2; add; const3; shr; const4; xor`

Since all inputs are constants, **every field value is statically determinable**.


## CFF Dispatcher Structure

Every obfuscated method follows this exact pattern:

```
B0: ldc.i4     <initial_state>
B1: stloc      <state_var>         // local 0 or 1
B2: ldloc      <state_var>
B3: switch     [N cases]           // main dispatcher
B4: ldloc <state_var>; ldc.i4 <val1>; beq <target1>  // overflow 1
B5: ldloc <state_var>; ldc.i4 <val2>; beq <target2>  // overflow 2
B6: br         <default>           // unreachable default
```

The two `beq` fallback checks after the switch handle state values exceeding the
switch table range. One is always a large sentinel value (e.g., 988, 1000, 1056)
used as a termination state.


## Opaque Predicate Pattern in Methods

The opaque predicates appear at CFF state transitions to obscure branch targets:

```
ldc.i4     <state_value>         // intended next state
ldsfld     0x040000a1            // load singleton instance
ldfld      0x040000xx            // load instance field (known constant)
brfalse    -> dispatcher         // conditional: always taken (or never)
pop                              // dead code path
ldc.i4     <alt_state>           // fake alternative state
br         -> dispatcher
```

Since the field value is fixed at initialization time, one branch is always taken
and the other is dead code.

### Example from DemoSwitch (Level 5)

```
B16: ldstr "Process"; stloc.s 0;
     ldc.i4(13);                      // real next state
     ldsfld  0x040000a1;              // singleton
     ldfld   0x04000048;              // opaque field (always 0)
     brfalse -> dispatcher            // always taken
B17: pop; ldc.i4(11); br -> dispatcher  // dead code
```


## Level 5 vs Level 9 Comparison

Methods with no control flow (Add, Subtract, Multiply) are **identical in both levels**
— too simple (no branches) to obfuscate.

| Method | Level 5 | Level 9 |
|--------|---------|---------|
| DemoSwitch | 7-case switch, 25 blocks, 3 opaque predicates | 14-case switch, 29 blocks, 7 opaque predicates |
| Fibonacci | 4-case switch, 26 blocks, 3 opaque predicates | 10-case switch, 27 blocks, 6 opaque predicates |
| DemoIfElse | 8-case switch, 31 blocks, 3 opaque predicates | 16-case switch, 31 blocks, 4 opaque predicates |

**Key differences at higher intensity:**
1. **More switch cases** (more fake/dead states)
2. **More opaque predicate insertion points**
3. **Different field tokens** used as singleton reference
4. **GUID in type name** changes between builds


## Per-Type Helper Methods

Two helper methods are injected per original type, plus two on `<Module>`:

**Null-check predicate**:
```
ldsfld     <static_field>
ldnull
ceq
ret                    // returns true if field is null
```

**Getter**:
```
ldsfld     <static_field>
ret                    // returns the field value
```

These are used by the CFF dispatcher for type-level initialization checks.


## Deobfuscation Strategy

1. **Identify the GUID container type**: Pattern `<Module>{GUID}` with 100+ Int32
   instance fields
2. **Resolve the static singleton field**: The field used in `ldsfld` before `ldfld`
   in opaque predicate patterns
3. **Evaluate all field values statically**: Run constant propagation on the
   initialization method (all inputs are constants, arithmetic is simple)
4. **Replace opaque predicates**: The `ldsfld; ldfld; brfalse/brtrue` pattern resolves
   to a known branch direction — remove the dead path
5. **Reconstruct CFF**: Standard CFF reconstruction (switch dispatcher analysis) —
   the dispatcher structure is similar to ConfuserEx CFF and can reuse
   `CffReconstructionPass`
6. **Remove injected artifacts**: GUID type, per-type helpers, trial guard

### dotscope Infrastructure Leverage

- **`OpaqueFieldPredicatePass`**: Already handles field-chain predicates; needs extension
  for bulk field types with 100+ fields and instance field resolution
- **`CffReconstructionPass`**: The switch dispatcher pattern is structurally similar to
  ConfuserEx CFF — the generic pass should handle it with minor adaptation
- **Emulation engine**: Can evaluate the initialization method to resolve all field values
