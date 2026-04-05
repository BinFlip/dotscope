# UnmanagedString

| Property | Value |
|----------|-------|
| **Protection** | `UnmanagedString` |
| **Class** | `Protection` |
| **Category** | Value (string hiding) |
| **Targets** | Method instructions (`ldstr`) |
| **Attributes** | `[ConfigureForNativeCode]`, `[RuntimeMonikerNETCore]`, `[RuntimeMonikerNETFramework]` |
| **Runtime** | None (uses BCL string constructors) |
| **Compatibility** | Not compatible with Mono — no `[RuntimeMonikerMono]` |

## Overview

Replaces string literals with calls to native methods that return pointers to string data embedded directly in x86/x64 machine code. Strings are invisible to metadata inspection since they exist only as raw bytes within native method bodies.

## Algorithm

For each `ldstr` instruction (skips empty strings):

1. **Determine encoding**:
   - UTF-16 (Unicode) if string contains characters > 0x7F
   - ASCII (7-bit) otherwise
2. **Determine null terminator**:
   - Appended if string doesn't already contain a null character
3. **Create native method** (or reuse cached one for identical strings):
   - Name: random GUID
   - Return type: `sbyte*` (pointer to byte)
   - Attributes: `Native | Unmanaged | PreserveSig | PInvokeImpl`
   - Body: x86 or x64 trampoline code followed by string bytes
4. **Replace `ldstr`** with call to native method + string constructor

## Native Method Bodies

### x64 (8 bytes of code + string data)

```asm
48 8D 05 01 00 00 00    ; lea rax, [rip + 0x1]
C3                       ; ret
; <string bytes follow immediately>
```

`rip + 1` after the `ret` instruction points to the first byte of the string data.

### x86 (20 bytes of code + string data)

```asm
55                       ; push ebp
89 E5                    ; mov ebp, esp
E8 05 00 00 00           ; call <jump1>           (call pushes return address)
83 C0 01                 ; add eax, 1
5D                       ; pop ebp                 <jump2>
C3                       ; ret
58                       ; pop eax                 <jump1> (eax = return address)
83 C0 0B                 ; add eax, 0xb            (adjust to point past code)
EB F8                    ; jmp <jump2>
; <string bytes follow immediately>
```

Uses a `call`/`pop` trick to get the instruction pointer on x86, then adjusts it to point past the code to the string data.

## IL Transformation

### With null terminator (most common)

```
// Before:
ldstr      "hello"

// After:
call       sbyte* <NativeMethod>()
newobj     string::.ctor(sbyte*)
```

Or for Unicode strings:

```
call       sbyte* <NativeMethod>()
newobj     string::.ctor(char*)
```

### Without null terminator (string contains embedded null)

```
// Before:
ldstr      "hel\0lo"

// After:
call       sbyte* <NativeMethod>()
ldc.i4     0                          // startIndex
ldc.i4     6                          // length
newobj     string::.ctor(sbyte*, int32, int32)
```

## Key Details

- Requires `module.IsILOnly = false` (set by `[ConfigureForNativeCode]` attribute)
- Identical strings reuse the same native method (caching)
- Architecture (x86 vs x64) determined by `ProtectionContext.X86` flag
- ASCII vs Unicode encoding determined per-string by character range

## Detection Signatures

- Native methods in `<Module>` with `Native | Unmanaged | PreserveSig` impl flags
- `PInvokeImpl` attribute on methods that are NOT actual P/Invoke declarations
- `new string(sbyte*)` or `new string(char*)` constructor calls following native method calls
- `IsILOnly = false` PE flag

## dotscope Handling

Handled by `BitMonoUnmanaged` technique (detection) and `UnmanagedStringReversalPass` (reversal). Detection identifies fake native methods by their flags and extracts embedded strings via traversal-based x86 disassembly. The pass replaces `call <native> + newobj string::.ctor(ptr)` patterns with `ldstr` constants.
