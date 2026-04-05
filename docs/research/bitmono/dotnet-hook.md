# DotNetHook

| Property | Value |
|----------|-------|
| **Protection** | `DotNetHook` |
| **Class** | `Protection` |
| **Category** | Structure (method redirection) |
| **Targets** | Method calls |
| **Dependencies** | `Renamer`, `RandomNext` |
| **Runtime** | `BitMono.Runtime.Hooking` |

## Overview

Redirects method calls through runtime JIT hooking. Each protected method call is replaced with a call to a dummy stub method. At runtime, native code is patched into the dummy method's JIT-compiled body to redirect execution to the real target. This makes static analysis see only the dummy method while runtime execution reaches the real target.

## Algorithm

For each `call TargetMethod` instruction:

1. **Create dummy method**: A new static method in `<Module>` with the same signature as the target. Body returns `null` (reference types) or `default` (value types). Renamed with random word pool name.
2. **Create initialization method**: A new static method that calls `Hooking.RedirectStub(dummyToken, targetToken)` to set up the native redirect at runtime.
3. **Redirect call site**: Replace `call TargetMethod` with `call DummyMethod`.
4. **Register in `.cctor`**: Insert `call InitializationMethod` at a random position in `<Module>.cctor`.

## Runtime Hooking (`Hooking.RedirectStub`)

The `RedirectStub(int from, int to)` method:

1. Resolves both method tokens via `Module.ResolveMethod(token)`
2. JIT-compiles both methods via `RuntimeHelpers.PrepareMethod()`
3. Gets native function pointers via `RuntimeMethodHandle.GetFunctionPointer()`
4. Makes the dummy method's memory writable:
   - **Windows**: `VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &oldProtect)`
   - **Unix/Linux**: `mprotect(page, size, PROT_READ | PROT_WRITE)`
5. Writes a native JMP instruction from the dummy to the real target:
   - **x64** (13 bytes): `mov r11, <target_ptr>; jmp r11`
     ```
     49 BB <8-byte address>    ; mov r11, imm64
     41 FF E3                  ; jmp r11
     ```
   - **x86** (5 bytes): `jmp <relative_offset>`
     ```
     E9 <4-byte relative offset>
     ```
6. Restores memory protection

## Initialization Method Pattern

Each initialization method has a fixed IL pattern:

```
ldc.i4     <dummy_method_token>      // Token of the dummy stub
ldc.i4     <target_method_token>     // Token of the real target
call       Hooking::RedirectStub(int32, int32)
ret
```

## Injected Artifacts

1. **Hooking type** — Cloned from `BitMono.Runtime.Hooking` into `<Module>`, containing:
   - `RedirectStub(int, int)` method
   - P/Invoke declarations for `VirtualProtect` and `mprotect`
   - `Marshal.WriteByte`/`Marshal.WriteInt64` calls for native code patching
2. **Dummy methods** — One per protected call, with trivial bodies (`ldnull; ret` or `ret`)
3. **Initialization methods** — One per protected call, calling `RedirectStub` with both tokens
4. **`.cctor` entries** — Calls to initialization methods at random positions

## Detection Signatures

- Type in `<Module>` containing `RedirectStub(int, int)` method with `VirtualProtect`/`mprotect` P/Invoke
- Static methods with trivial bodies (`ldnull; ret`) whose tokens appear as `ldc.i4` arguments
- Initialization methods with pattern: `ldc.i4; ldc.i4; call RedirectStub; ret`
- Random calls to initialization methods in `<Module>.cctor`

## dotscope Handling

Handled by `BitMonoHooks` technique (detection) and byte-level reversal. The technique identifies the hooking infrastructure type by its `PrepareMethod` + `GetFunctionPointer` + `VirtualProtect` + `Marshal.Write*` pattern. Reversal extracts the dummy→target token mapping from initialization methods and patches call sites using sorted-order matching with direct byte writes.
