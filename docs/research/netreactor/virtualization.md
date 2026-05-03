# Code Virtualization (VM Protection)

Analysis of .NET Reactor 7.5.0 code virtualization based on reverse engineering
`reactor_virtualization.exe` (125,440 bytes, 851 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

This is .NET Reactor's most sophisticated protection. It converts CIL method bodies
into custom bytecode interpreted by an embedded virtual machine. 8 methods were
virtualized; the remaining methods are untouched.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 125,440 | +111,104 (8.7x) |
| TypeDef rows | 13 | 92 | +79 |
| MethodDef rows | 35 | 851 | +816 |
| Methods with bodies | 35 | 694 | +659 |
| .text section | 0x2E00 | 0x1E000 | +118,272 |
| Metadata size | 7,904 | 45,276 | +37,372 |
| #Strings heap | 2,220 | 13,176 | +10,956 |
| #US heap | 2,688 | 4,308 | +1,620 |


## Virtualized Method Stub Format

All 8 virtualized methods follow an identical stub pattern:

```
ldc.i4       <method_id>          // unique integer identifying the VM bytecode
newarr       object[]             // create array for boxed arguments
// ... pack each argument into object[] via box + stelem.ref ...
ldarg.0                           // push 'this' (or null for static)
call         BD6lOYUCm3           // VM entry point (token 0x060000A9)
// ... unbox return value from returned object[] ...
ret
```

### Method ID Mapping

| ID | Original Method | Notes |
|----|----------------|-------|
| 0 | `Calculator::Add` | Simple arithmetic |
| 1 | `Calculator::Factorial` | Recursive |
| 2 | `Calculator::Fibonacci` | Loop-based |
| 3 | `ControlFlowDemo::DemoIfElse` | If/else branching |
| 4 | `ControlFlowDemo::DemoSwitch` | Switch statement |
| 5 | `SecretHolder::GetApiKey` | String return |
| 6 | `SecretHolder::DecryptSecret` | Try/catch + crypto |
| 7 | `SecretHolder::XorEncrypt` | Loop + char ops |

**Non-virtualized methods** (Subtract, Multiply, Divide, DemoLoop, etc.) retain
their original IL completely unmodified.

**Detection**: Find `call 0x060000A9` (the VM entry point) preceded by `ldc.i4 <id>`.


## VM Architecture

### Call Chain

```
Virtualized stub
  -> BD6lOYUCm3 (entry point)
     -> MethodSpec 0x2B000001 (generic VM entry)
        -> j4XlTwXGiJ (body loader: loads/decrypts bytecode, creates context)
           -> lIKxeQZNPA (entry wrapper)
              -> vjuxAdNiYK (execution loop)
                 -> XGtxjqudOH (opcode dispatcher: 176-case switch)
```

### Execution Loop: `vjuxAdNiYK` (308 lines, 12 locals)

| Field | Purpose |
|-------|---------|
| `0x0400009A` | Program counter (instruction pointer) |
| `0x0400009B` | Previous/saved PC |
| `0x0400009E` | Branch flag |
| `0x0400009F` | Return flag (exits loop when set) |
| `0x040000A0` | Halt flag |
| `0x04000093 -> 0x0400008B` | Bytecode array (indexed by PC) |
| `0x0400006F` | Opcode ID field (on fetched instruction) |
| `0x04000096` | Virtual operand stack |

The loop:
1. Reads instruction from bytecode array at current PC
2. Reads opcode ID from the instruction's opcode field
3. Dispatches via `XGtxjqudOH`
4. Wraps execution in try/catch for VM-level exception handling

### Opcode Dispatcher: `XGtxjqudOH` (4,781 lines, 39 locals)

- **176-case switch** statement on the opcode ID
- Maps to **~154 unique handler targets** (some opcodes share handlers)
- Stack operations via polymorphic calls on field `0x04000096`:
  - **Pop**: `callvirt 0x06000344` (row 836)
  - **Push**: `callvirt 0x06000342` (row 834)
  - **Stack Count**: `callvirt 0x06000340` (row 832)
  - **Stack Top**: `callvirt 0x06000341` (row 833)


## VM Type System

### Type ID Classification (19 types)

The type classifier `HEWjGoIVXq` (245 lines) maps .NET types to VM type IDs:

| ID | .NET Type | ID | .NET Type |
|----|-----------|----|-----------|
| 0 | Unknown/default | 10 | Double (Float64) |
| 1 | Boolean | 11 | Decimal |
| 2 | Byte | 12 | Char |
| 3 | Int16 | 13 | Other numeric |
| 4 | Int32 | 14 | String |
| 5 | Int64 | 15 | IntPtr/UIntPtr |
| 6 | UInt16 | 16 | Array type |
| 7 | UInt32 | 17 | Array type (variant) |
| 8 | UInt64 | 18 | Null |
| 9 | Single (Float32) | | |

### 4 Parallel VM Value Types

Four large types implement the polymorphic VM value abstraction, each specialized
for different data widths:

| Type | Methods | Unique Methods | Likely Specialization |
|------|---------|----------------|----------------------|
| `KFLZn1PTyq5gG2AjYpx` | 104 | 12 | Full (64-bit, pointers, `Add`) |
| `KTvJuZPhZohptT4uVf6` | 93 | 2 | Standard (15-case opcode handler) |
| `ShYNHsP3JZ1gO8BRpVH` | 92 | 3 | Variant |
| `aqAvMsP2XIn3GUhf0si` | 88 | 0 | Minimal |

Each shares ~70 identical method signatures (`JfS3vO6qin`, `Th73tWZsCb`,
`FHPTbr88Ae`, `Add`, `ToString`, arithmetic/comparison handlers).
Arithmetic is dispatched polymorphically through these types.

### Value Boxing

`jVsj6JAdhh` (855 lines, 19-case switch): Boxes .NET values into the appropriate
VM value type based on the type ID from the classifier.


## Bytecode Storage and Decryption

### Embedded Resource

Bytecode stored as an embedded assembly resource, loaded via:
```
ldtoken      TypeDef(row 18)           // UhSaWDOYZTgwwgfSO6
call         Type.GetTypeFromHandle()
callvirt     Type.get_Assembly()
ldstr        0x70000BBE                // resource name
callvirt     Assembly.GetManifestResourceStream(string)
```

### Decryption Pipeline

`oYiEKuNrl` (866 lines, 20 locals):
- AES-based decryption with custom key derivation
- Key scheduling: calls rows 57/58 sixteen times each (round key setup)
- Custom padding: `(448 - len*8) % 512` (Merkle-Damgard style)
- Key derivation in `tRelL85we1`: 32-byte key from seed, `ICryptoTransform`

### Method Body Loading: `j4XlTwXGiJ` (1,141 lines, 46 locals)

1. Reads from static cache array (field row 71) indexed by method ID
2. If not cached, reads from decrypted resource stream (field row 74)
3. Uses **compressed integer encoding** (`eKLl9Pieuj` — 6-bit base + continuation bits,
   custom format, not .NET's standard compressed integer)
4. Reads: parameter types, local variable types, instruction count, instruction data
5. Each instruction has an **opcode field** (0-175) and operand data
6. **Token resolution** via `osalebjCgR`: masks with `0x0FFFFFFF`, looks up in
   pre-built token array (field row 79)


## Injected Type Inventory (79 new types)

### Core Infrastructure

| Type | Namespace | Methods | Role |
|------|-----------|---------|------|
| `UhSaWDOYZTgwwgfSO6` | `Dinih72WZsCb9wcqjy` | 23 | VM bootstrap, entry point, bytecode loader |
| `dIB6JIPIiI7GlyxJGUd` | — | 28 | VM execution engine, 176-case dispatcher |
| `oMu6jVbdhHEH79DDhU` | `AoIBWWlDJbaf7LijnA` | 49 | Bytecode decryptor, crypto |
| `jvj3LnPpvxU2erTMeM4` | — | 17 | VM type system, value boxing |
| `uy4ZXuP8hhYiKuNrl4` | `AsG4wKEPrjKTCY31dc` | 3 | Token resolver |
| `gttro5yuWySr2hbdEM` | `UWxvxUSU2ZrCqT9K8B` | 2 | License date check |
| `gEHfEJ9aJKgHNTQig9` | — | 2 | Crypto helper (AES/SHA) |
| `VM792LkqNpj06PcE1F` | — | 6 | Stream wrapper |

### VM Value Types (4 parallel instantiations)

| Type | Methods |
|------|---------|
| `KFLZn1PTyq5gG2AjYpx` | 104 |
| `KTvJuZPhZohptT4uVf6` | 93 |
| `ShYNHsP3JZ1gO8BRpVH` | 92 |
| `aqAvMsP2XIn3GUhf0si` | 88 |

### VM Stack/Reader Variants (5 types, 11 methods each)

`pCcUn2Pk0WRdx9wXGtQ`, `RLZZMSPJ8nNSMssYi0I`, `Y2TQrxPUsKZAuW0CSyH`,
`LmTcB5PZLgTyJV4YP0Z`, `k1MD8LPCkL4TjT0JVvC`

### Helper Types

| Type | Methods | Role |
|------|---------|------|
| `LbcypsPYVeerQlaEm3O` | 6 | Instruction key (Equals, GetHashCode) |
| `NWOcXrPi1WKXw4SWh1B`1` | 8 | Nullable wrapper |
| `C6jel6PFv1y17TI7U6B` | 6 | Opcode descriptor |
| `FwrX5yPtqhsabjCgRnP` | 3 | Static initializer |
| `d8DE92F8305BE09E` | 11 | String interpolation handler |
| 10+ small types | 1-2 each | Enums, structs, exception types |


## Key Findings for Devirtualization

### 1. Uniform Stub Detection

All virtualized methods call the same entry point (`BD6lOYUCm3`, token `0x060000A9`)
with a numeric method ID. Detection is trivial: find `call <entry>` preceded by
`ldc.i4 <id>`.

### 2. Single Central Dispatcher

One 176-case switch handles all VM opcodes. Each case is a distinct handler block
with predictable structure — amenable to semantic analysis.

### 3. Stack-Based VM

Classic operand stack model (push/pop through virtual methods). Operations are
polymorphic calls on the 4 VM value types. This mirrors CIL's own stack model,
which simplifies lifting back to CIL.

### 4. Encrypted Bytecode

Requires emulating AES decryption + key derivation to extract raw bytecode.
The emulation engine's AES BCL support can handle RijndaelManaged.

### 5. Runtime Token Resolution

Token resolver masks with `0x0FFFFFFF` and indexes into a pre-built array.
The array is populated during initialization from the encrypted resource.

### 6. Custom Instruction Encoding

Variable-length: 6-bit base + continuation bits (`eKLl9Pieuj`). Not .NET's
standard compressed integer format — needs custom parser.

### 7. Complexity Assessment

176 opcodes, ~154 unique handlers, 4,781 lines of dispatcher IL, 39 locals.
This is a **full-featured VM**, not a simple wrapper. Devirtualization requires
the generic VM framework described in
[design/vm_devirtualization.md](../../design/vm_devirtualization.md).


## Devirtualization Strategy

Following the layered architecture from `vm_devirtualization.md`:

### Layer 1: Detection & Extraction

1. **Detect VM stubs**: Find methods calling the VM entry point with `ldc.i4 <id>`
2. **Extract encrypted bytecode**: Locate the embedded resource via the `ldtoken` +
   `GetManifestResourceStream` pattern
3. **Decrypt**: Emulate the decryption pipeline (`oYiEKuNrl` + `tRelL85we1`)

### Layer 2: Handler Analysis

1. **Map the 176-case switch**: Each case is a handler block — extract the opcode-to-handler mapping
2. **Classify handlers semantically**: Use SSA pattern matching on each handler to
   determine what CIL operation it implements (add, sub, load, store, branch, call, etc.)
3. **Handle the 4 value types**: Recognize the polymorphic dispatch through the
   value type hierarchy

### Layer 3: SSA Lifting

1. **Parse bytecode**: Implement the custom compressed integer encoding
2. **Resolve tokens**: Reconstruct the token array from the encrypted resource
3. **Build CFG**: Use branch/return flags to identify basic blocks
4. **Lift to SSA**: Map VM opcodes to `SsaFunction` operations, leveraging the
   semantic classification from Layer 2

### Layer 4: Integration

1. **Run through compiler pipeline**: The lifted SSA gets all 21 optimization passes
2. **Emit CIL**: Replace the stub with the devirtualized method body
3. **Cleanup**: Remove VM infrastructure types (79 types, 816 methods)

### dotscope Infrastructure Leverage

- **Emulation engine**: Decrypt the bytecode resource (AES BCL support)
- **SSA framework**: Direct-to-SSA lifting avoids intermediate IR
- **Compiler passes**: All 21 optimization passes apply to lifted code
- **Cleanup pipeline**: Removes the massive VM infrastructure
