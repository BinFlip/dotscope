# BillionNops

| Property | Value |
|----------|-------|
| **Protection** | `BillionNops` |
| **Class** | `Protection` |
| **Category** | Junk (size inflation) |
| **Targets** | Module type |
| **Dependencies** | `Renamer` |

## Overview

Creates a single dummy method in the module type containing 100,000 NOP instructions. This bloats the assembly size and can crash or significantly slow down decompilers that attempt to analyze the massive method body.

## Algorithm

1. Create a new `public static void` method in `<Module>` with a random word-pool name
2. Insert 100,000 `nop` instructions (each inserted at position 0, shifting others)
3. Add a final `ret` instruction

The method is never called — it exists solely as a size/analysis blocker.

## Key Details

- Fixed count: always 100,000 NOPs (not configurable)
- Method is `public static` in the module type
- Despite the protection name, it's "only" 100K nops, not a billion

## Detection Signatures

- Method in `<Module>` with extremely large instruction count (50K+ nops)
- Method is never referenced from any call site

## dotscope Handling

Handled by `BitMonoNops` technique (detection). The technique identifies methods in `<Module>` with abnormally high NOP counts. Cleanup removes the dead methods during the neutralization phase.
