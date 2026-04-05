# Static Method Collection

| Property | Value |
|----------|-------|
| **Protection** | Static Method Collection |
| **Class** | `DCJieJieNetEngine` (`CollectStatcMethod`, line 2496) |
| **Category** | Code (structural obfuscation) |
| **Targets** | Static methods in classes without constructors or instance members |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | Runs after renaming (step 18) |

## Overview

JIEJIE.NET moves eligible static methods from their original classes into a synthetic collection class `__DC20210205._jiejienet_sm`. This reduces symbol coupling between types and makes method extraction harder for decompilers.

## Algorithm

Source: `CollectStatcMethod()` (line 2496)

### Eligibility Criteria

A static method is collected if ALL of the following are true:
- Method is `static` with no generic parameters
- Parent class has no constructors (`.ctor`) or instance members
- Parent class has no nested classes
- Method is either **renamed** OR **non-public** (assembly/private visibility)
- Method does not call private sibling methods in the original class

### Transformation

1. Creates new class `__DC20210205._jiejienet_sm`
2. Moves eligible static methods to the new class
3. Changes visibility from `private` to `assembly` (internal) — necessary since the method is now in a different class
4. Renames methods if renaming is enabled
5. Updates all call sites to reference the new location

## Detection Signatures

- **Type name** (pre-rename): `__DC20210205._jiejienet_sm`
- **Structural**: A class containing only static methods, all with `assembly` visibility, from diverse original types

## dotscope Handling

The collected methods remain functionally correct in their new location. The `_jiejienet_sm` class is removed during cleanup, but the methods themselves do not need to be moved back — call sites already reference the correct tokens. If the class is removed, all referencing call sites must be updated or the methods inlined.
