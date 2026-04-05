# CallToCalli

| Property | Value |
|----------|-------|
| **Protection** | `CallToCalli` |
| **Class** | `Protection` |
| **Category** | Structure (call indirection) |
| **Targets** | Method instructions (`call`) |
| **Attributes** | `[DoNotResolve(MemberInclusionFlags.SpecialRuntime)]` |
| **Runtime** | None (uses BCL reflection APIs) |

## Overview

Converts direct `call MethodDef` instructions to indirect calls via `calli` using runtime method resolution through reflection. The original method token is embedded as an `ldc.i4` constant, and a 10-instruction sequence resolves it at runtime to a function pointer for indirect invocation.

## Algorithm

For each `call` instruction targeting a method within the module:

1. Skip methods in `<Module>` type
2. Skip methods that can't be resolved or lack a signature
3. Create a new `CilLocalVariable` of type `RuntimeMethodHandle`
4. Replace the `call` with the indirect call sequence

Only `call` instructions are converted — `callvirt` is never touched.

## IL Transformation

```
// Before:
call       void SomeClass::SomeMethod(int32)

// After:
ldtoken    <Module>                              // RuntimeTypeHandle of module type
call       Type::GetTypeFromHandle(RuntimeTypeHandle)
callvirt   Type::get_Module()                    // Get System.Reflection.Module
ldc.i4     0x06000XXX                            // Original method's metadata token
call       Module::ResolveMethod(int32)          // Resolve MethodBase at runtime
callvirt   MethodBase::get_MethodHandle()        // Get RuntimeMethodHandle
stloc      <handle_local>
ldloca     <handle_local>
call       RuntimeMethodHandle::GetFunctionPointer()
calli      <original_signature>                  // Indirect call via function pointer
```

## Key Details

- The `ldc.i4` value is the original method's `MetadataToken.ToInt32()` — a valid MethodDef token (0x06XXXXXX)
- Each conversion adds a new `RuntimeMethodHandle` local variable to the method
- The reflection trampoline adds 9 instructions per converted call site
- The original method signature is preserved in the `calli` operand

## Detection Signatures

- `ldtoken <Module>` → `GetTypeFromHandle` → `get_Module` → `ldc.i4 <token>` → `ResolveMethod` → `get_MethodHandle` → `GetFunctionPointer` → `calli` sequence
- `ldc.i4` values are valid MethodDef tokens (table 0x06)
- Extra `RuntimeMethodHandle` local variables per method

## dotscope Handling

Handled by `BitMonoCalli` technique (detection) and `CalltocalliReversalPass` (reversal). The pass traces SSA def-use chains backward from `CallIndirect` through the reflection trampoline to extract the embedded method token, then replaces the entire sequence with a direct `Call`.
