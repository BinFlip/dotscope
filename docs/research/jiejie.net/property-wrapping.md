# Property Accessor Wrapping

| Property | Value |
|----------|-------|
| **Protection** | Property Accessor Wrapping |
| **Class** | `DCJieJieNetEngine` (`ChangeCallOperCodes`, line 2646) |
| **Category** | Code (call indirection) |
| **Targets** | Property getter/setter methods called more than 5 times |
| **Configuration** | `ControlFlow` switch (enabled by default) |
| **Dependencies** | Runs late in pipeline (step 20, after CFF and Int32ValueContainer commit) |

## Overview

JIEJIE.NET wraps frequently-called property accessors with synthetic methods. The original getter/setter is demoted to non-public visibility, and a new synthetic wrapper with the original's public signature takes over the property definition. This adds a layer of indirection that hinders decompilers from recognizing property access patterns.

## Algorithm

Source: `ChangeCallOperCodes()` (line 2646)

### Eligibility

A property accessor is wrapped if ALL of the following are true:
- Called **more than 5 times** across the assembly
- Method is **not** `virtual`, `newslot`, or `abstract`
- Method has **20 or fewer instructions**
- Method does **not** contain try/catch/finally handlers

### Transformation

1. **Original accessor** is marked as non-public (`assembly` visibility)
2. **Synthetic wrapper** is created with the original accessor's signature and visibility
3. The **property definition** is updated to point to the synthetic wrapper
4. Wrapper method name follows the pattern `__jiejie_net_get_<name>_<id>` or `__jiejie_net_set_<name>_<id>`

```
// Original property:
.property string MyProp
  .get instance string MyClass::get_MyProp()
  .set instance void MyClass::set_MyProp(string)

// After wrapping:
.property string MyProp
  .get instance string MyClass::__jiejie_net_get_MyProp_15()  // synthetic
  .set instance void MyClass::__jiejie_net_set_MyProp_15()    // synthetic

// Original accessors demoted:
.method assembly string get_MyProp() { /* original body */ }
.method assembly void set_MyProp(string) { /* original body */ }
```

The synthetic wrapper's body is a clone of the original accessor's IL.

## Detection Signatures

- **Method name pattern** (pre-rename): `__jiejie_net_get_*` / `__jiejie_net_set_*`
- **Structural**: Property definitions pointing to methods whose bodies are identical to nearby non-public methods
- **Visibility mismatch**: Public wrapper method + assembly-visible original with identical IL

## dotscope Handling

Handled by the existing inlining pass. The synthetic wrappers are trivial single-call-through methods that inline cleanly. After inlining, the wrapper is dead code and removed during cleanup.
