# Anti-Tamper Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.AntiTamper` |
| **Short ID** | `anti tamper` |
| **Preset** | Maximum |
| **Targets** | Methods |
| **Pipeline Stages** | ModuleWriterSetupPhase: PostStage BeginModule; InjectPhase: PreStage OptimizeMethods; MDPhase: PreStage EndModule |
| **Dependencies** | Must run before `Ki.ControlFlow`, must run after `Ki.Constants` |

## Overview

Encrypts method IL bodies by moving them to a new PE section and applying XOR-based symmetric encryption keyed from hashes of other PE sections. At runtime, the protection decrypts the section in-place before any method can execute. Three modes provide different tradeoffs between complexity and JIT-level granularity.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `mode` | `Normal`, `Anti`, `JIT` | `Normal` | Encryption/decryption strategy |
| `key` | `Normal`, `Dynamic` | `Normal` | Key derivation algorithm |

## PE Section Creation

All modes create a new PE section for encrypted method bodies:

1. **Section name**: 8 ASCII bytes derived from two random 4-byte values (`name1`, `name2`)
2. **Section flags**: `0xE0000040` (readable, executable, no padding)
3. **Section placement**: Moved to position 0 for RVA calculation priority
4. **Metadata relocation**: Existing metadata, .NET resources, and constants sections are removed and re-added to ensure proper alignment after the new section

## Method Body Extraction

For each target method:
1. Get `MethodBody` from the metadata writer
2. Remove from the standard method body chunk
3. Add to the new encrypted section's chunk
4. Result: method IL exists only in the encrypted section

## Encryption Algorithm

### Key Derivation from PE Sections

Initial state: four random `uint32` values `z`, `x`, `c`, `v`

For each non-encrypted PE section, hash all data:
```
for each uint32 word in section:
    tmp = (z ^ word) + x + c * v
    z = x
    x = c
    c = v      // Note: original code reassigns x=c before c=v
    v = tmp
```

### Key Array Generation

From the hash state, generate two 16-element `uint32` arrays via bit rotation:

```
for i in 0..15:
    dst[i] = v
    src[i] = x
    z = (x >> 5) | (x << 27)
    x = (c >> 3) | (c << 29)
    c = (v >> 7) | (v << 25)
    v = (z >> 11) | (z << 21)
```

The final key is produced by applying the key deriver to both arrays.

### Block Encryption

```
for each uint32 at index i in encrypted section:
    encrypted[i] = value[i] ^ key[i & 0xF]
    key[i & 0xF] = (key[i & 0xF] ^ value[i]) + 0x3dbb2819   // Key chaining
```

## Key Derivers

### Normal Deriver

Element-wise combination of two 16-element arrays:

```
for i in 0..15:
    if i % 3 == 0: result[i] = dst[i] ^ src[i]
    if i % 3 == 1: result[i] = dst[i] * src[i]
    if i % 3 == 2: result[i] = dst[i] + src[i]
```

Emitted directly as CIL arithmetic instructions.

### Dynamic Deriver

Uses `IDynCipherService` to generate a random symmetric cipher pair:
- Protection time: applies encrypt cipher to derive key
- Runtime: emits inverse cipher as CIL for key recovery

See [DynCipher](dynciper.md) for cipher generation details.

## Mode: Normal

The baseline mode. Encrypts all method bodies in the new PE section and decrypts the entire section at runtime during module initialization.

### Runtime Decryption Flow

```
Initialize()  [called from .cctor]
├── Parse PE headers from Marshal.GetHINSTANCE(module)
├── Find encrypted section by name hash: name1 * name2
├── Hash all other PE sections (same algorithm as protection time)
├── Generate key arrays via bit rotation
├── Apply key deriver (Normal or Dynamic)
├── VirtualProtect(section, PAGE_EXECUTE_READWRITE)
├── XOR-decrypt all uint32 words with key chaining
└── Return (methods now executable)
```

## Mode: Anti

Identical encryption to Normal mode, with added debugger detection:

### Additional Runtime Checks

Before and during decryption, calls `CheckRemoteDebuggerPresent` (Win32 API):

```csharp
[DllImport("kernel32.dll")]
static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
```

If a debugger is detected at any checkpoint, calls `Environment.FailFast(null)`.

Multiple checks are interspersed throughout the initialization sequence.

## Mode: JIT

The most sophisticated mode. Rather than decrypting the entire section at once, it hooks the JIT compiler and decrypts method bodies on-demand during compilation.

### Method Body Serialization (JITBody)

Each method body is serialized as a `MethodData` structure with 6 `uint32` fields in **randomized order**:

| Field | Description |
|-------|-------------|
| `ILCodeSize` | Size of IL code in bytes |
| `MaxStack` | Maximum stack depth |
| `EHCount` | Exception handler count |
| `LocalVars` | Size of local variable signature |
| `Options` | Body flags (InitLocals, EH present, etc.) |
| `MulSeed` | Per-method random seed |

After the header: IL code bytes, local variable signature, exception handler data.

### Per-Method Encryption

```
state = methodToken * globalEncryptionKey
for each uint32 in serialized body:
    encrypted[i] = value[i] ^ state
    state += value[i] ^ counter
    counter ^= (state >> 5) | (state << 27)
```

### JIT Hook Installation

1. Load `clrjit.dll` (or `mscorjit.dll` for older runtimes)
2. Call `getJit()` to get the JIT VTable pointer
3. Replace `compileMethod` function pointer with hook
4. Install trampoline for calling original JIT

### JIT Hook Handler

```
compileMethodHook(thisPtr, comp, info, flags, nativeEntry, nativeSizeOfCode):
1. Get method token from CORINFO_METHOD_INFO
2. Check if token belongs to current module
3. Binary search token in encrypted method index table
4. Extract encrypted method data from section
5. Decrypt using per-method key: token * globalKey
6. Parse MethodData header (randomized field order)
7. Patch CORINFO_METHOD_INFO with decrypted IL:
   - Set ILCode pointer to decrypted bytes
   - Set ILCodeSize
   - Set MaxStack
   - Set EHCount via separate EH clause hook
   - Set local variable signature
8. Call original JIT compileMethod
9. Free allocated memory
```

### Placeholder Method Bodies

Original method bodies are replaced with:
```
ldnull
throw
```

This prevents direct execution without JIT hook — any attempt to call an un-hooked method throws `NullReferenceException`.

## Section Name Hashing

At runtime, the encrypted section is located by computing `name1 * name2` and comparing against the product of each section's 8-byte name interpreted as two `uint32` values.

## dotscope Handling

Handled by `ConfuserExStateMachine` technique which identifies the encrypted section, replays hash-based key derivation, and restores method bodies before any analysis begins. Normal/Anti modes are supported; JIT mode is not yet implemented (each method has its own key and randomized serialization format).
