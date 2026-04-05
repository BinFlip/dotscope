# Integer Constant Hiding

| Property | Value |
|----------|-------|
| **Protection** | Integer Constant Hiding (`Int32ValueContainer`) |
| **Class** | `DCInt32ValueContainer` (line 7613) |
| **Category** | Value (constant encryption) |
| **Targets** | All `ldc.i4` / `ldc.i4.s` / `ldc.i4.0`–`ldc.i4.8` instructions |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | None — this is the foundational protection that all others depend on |

## Overview

JIEJIE.NET replaces all integer literal loads with `ldsfld` instructions reading from static fields in a synthetic container class `__DC20210205._Int32ValueContainer`. This hides integer constants from static analysis and serves as the **critical dependency for nearly all other protections** — control flow dispatcher indices, typeof() array indices, array XOR keys, enum values, and char values all pass through the container.

## Injected Type

**Class**: `__DC20210205._Int32ValueContainer`

Attributes: `private auto ansi abstract sealed beforefieldinit` (static class)

**Fields**: `public static initonly int32` — one per unique integer value.

**Field naming convention** (pre-rename): `_<index>_<value>` for positive, `_<index>_N_<absvalue>` for negative:
- `_3_42` → index 3, value 42
- `_5_N_7` → index 5, value -7

**Member order**: Shuffled after commit (`DCUtils.ObfuseListOrder`).

**Capacity**: Up to 10,000 unique values per container. If exceeded, multiple containers are created.

## Initialization Algorithm (.cctor)

### Commit Code (Obfuscator Side)

Source: `DCJieJieNetEngine.cs`, `Commit()` method (line 7651)

```csharp
int currentValue = Environment.TickCount;     // seed (line 7659)
// emit: ldc.i8 <currentValue>

foreach (field in shuffledFields)
{
    int delta = field.InnerTag - currentValue;  // delta = targetValue - accumulator
    currentValue = field.InnerTag;              // accumulator = targetValue
    // emit: ldc.i8 <delta>; add; dup; conv.i4; stsfld <field>
}
```

### Emitted IL

The obfuscator-time `Environment.TickCount` value is consumed during compilation. The resulting delta values are baked into the IL as deterministic `ldc.i8` constants:

```il
.method private hidebysig specialname rtspecialname static void .cctor() cil managed
{
    ldc.i8     <seed>         // deterministic int64 constant (NOT a TickCount call at runtime)
    ldc.i8     <delta_0>      // delta to first target value
    add                        // accumulator = seed + delta_0
    dup
    conv.i4                    // truncate to int32
    stsfld     int32 __DC20210205._Int32ValueContainer::_0_42
    ldc.i8     <delta_1>      // delta from value_0 to value_1
    add                        // accumulator += delta_1
    dup
    conv.i4
    stsfld     int32 __DC20210205._Int32ValueContainer::_1_7
    ...
    pop                        // discard final accumulator
    ret
}
```

### TickCount Behavior

The source code calls `Environment.TickCount` at obfuscation time and uses it to compute deltas. However, the emitted IL embeds these computed deltas as `ldc.i8` constants — there is **no** `call Environment::get_TickCount()` in the output binary. This means:

- The `.cctor` is **fully deterministic** — static analysis is feasible
- Each compilation produces different seeds (TickCount varies), but within a single binary all values are fixed
- The int64 arithmetic with `conv.i4` truncation means the accumulator can overflow safely — only the low 32 bits matter

### Algebraic Structure

For field `i`: `value_i = (int32)(seed + delta_0 + delta_1 + ... + delta_i)`

The delta chain is cumulative:
- `delta_0 = value_0 - TickCount_obfusc`
- `delta_i = value_i - value_{i-1}` for i > 0

Since `seed = TickCount_obfusc` (baked into `ldc.i8`), the seed cancels with `delta_0` and all values resolve correctly via the chain.

## Call Site Transformation

The `ChangeOperCode()` method replaces all qualifying integer loads:

```
// Before:
ldc.i4     42

// After:
ldsfld     int32 __DC20210205._Int32ValueContainer::_3_42
```

## Where Int32ValueContainer Is Referenced

| Context | What is replaced |
|---------|-----------------|
| Control flow dispatcher | Switch indices / group transition indices |
| Enum parameter values | `ldc.i4` before `call`/`callvirt` with enum params |
| Char comparison values | `ldc.i4` for char-range constants |
| Array sizes | `newarr` size operands |
| typeof() indices | Indices into `RuntimeTypeHandleContainer` |
| Array init XOR keys | XOR decryption key for `MyInitializeArray` |
| Array init handle indices | Indices into `RuntimeFieldHandleContainer` |
| .cctor field initialization | Integer constants within static constructors |
| Opaque predicates (Algorithm B) | Comparison constants in entry selection |

## Detection Signatures

- **Type pattern**: Class with 10+ `public static initonly int32` fields, all with the same naming convention
- **.cctor pattern**: Sequence of `ldc.i8` / `add` / `dup` / `conv.i4` / `stsfld` chains (the delta-chain pattern)
- **Usage pattern**: Widespread `ldsfld int32 <container>::<field>` replacing what should be `ldc.i4` instructions
- **Type name** (pre-rename): `__DC20210205._Int32ValueContainer`

## dotscope Handling

Handled by `JiejieNetConstants` technique (detection + `.cctor` warmup registration) and `Int32ValueContainerPass` (SSA-level field load → constant replacement). The technique detects the container by its structural pattern (all-static-initonly-int32 fields + delta-chain `.cctor`), registers the `.cctor` as an emulation warmup method, and marks the type for cleanup. The pass runs in the **Value phase** — critically before CFF unflattening, since switch dispatcher indices must be concrete constants for CFF reconstruction to work.
