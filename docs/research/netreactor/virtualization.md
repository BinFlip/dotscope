# Code Virtualization (VM Protection)

Analysis of .NET Reactor 7.5.0 code virtualization, based on `reactor_virtualization.exe`
(125,440 bytes, 851 methods) and `reactor_virtualization_full.exe` (361,984 bytes,
1181 methods) against `original.exe` (14,336 bytes, 35 methods).

Tokens, field names and IL offsets throughout are from `reactor_virtualization.exe`
unless stated otherwise. Names are the obfuscated ones as they appear in the sample;
they are per-build and carry no meaning across samples — treat them as coordinates
for re-verification, not as identifiers to match on.

This is .NET Reactor's most sophisticated protection. It converts CIL method bodies
into a custom instruction stream interpreted by an embedded interpreter. 8 methods
were virtualized; the remaining methods are untouched.

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

All 8 virtualized methods follow an identical stub pattern. `Calculator::Add`,
verbatim:

```
IL_0000: ldc.i4       2
IL_0005: newarr       System.Object
IL_000a: stloc.0
IL_000b: ldloc.0
IL_000c: ldc.i4       0
IL_0011: ldarg        1
IL_0015: box          System.Int32
IL_001a: stelem.ref
IL_001b: ldloc.0
IL_001c: ldc.i4       1
IL_0021: ldarg        2
IL_0025: box          System.Int32
IL_002a: stelem.ref
IL_002b: ldc.i4       0                  // method id
IL_0030: ldloc.0                          // boxed argument array
IL_0031: ldarg.0                          // 'this' (null for static)
IL_0032: call         object[] BD6lOYUCm3(int32, object[], object)  /* 0x060000A9 */
IL_0037: stloc.1
IL_0038: ldloc.1
IL_0039: ldc.i4.0
IL_003a: ldelem.ref
IL_003b: unbox.any    System.Int32
IL_0040: ret
```

Two properties of this stub matter more than anything else in the VM:

- **The MethodDef signature is untouched.** `Add` is still
  `instance int32 Add(int32, int32)`. Unlike KoiVM, .NET Reactor destroys no
  type information at the method boundary.
- **The `box`/`unbox.any` pairs name the exact parameter and return types.**
  Even if the signature were stripped, the stub itself spells out the boundary
  types.

Together these give a devirtualizer a fully typed entry and exit for every
virtualized method, for free. See [Type Recovery](#type-recovery-is-cheap-here).

### VM Entry Point

```
.method assembly static object[] BD6lOYUCm3(int32, object[], object)   /* 0x060000A9 */
  ldc.i4.0; stloc.0
  ldarg.0; ldarg.1; ldarg.2; ldloca.s 0
  call object[] UhSaWDOYZTgwwgfSO6::j4XlTwXGiJ<int32>(int32, object[], object, !!0&)
  ret                                                    /* MethodSpec 0x2B000001 */
```

**Detection**: find `call 0x060000A9` preceded by `ldc.i4 <id>`. Structurally:
a static method whose only act is to forward all arguments to a generic method,
called from many small methods that box their arguments into an `object[]`.

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

**Non-virtualized methods** (`Subtract`, `Multiply`, `Divide`, `DemoLoop`, …) retain
their original IL completely unmodified.


## VM Architecture

### Call Chain

```
Virtualized stub
  -> BD6lOYUCm3                    0x060000A9  entry point
     -> j4XlTwXGiJ<T>              MethodSpec 0x2B000001
                                   body loader: decrypt, decode, build context
        -> lIKxeQZNPA              0x060002D7  entry wrapper  ← the harvest seam
           -> vjuxAdNiYK                       step/execute loop
              -> XGtxjqudOH        0x060002DE  dispatcher: 175-case switch
```

`j4XlTwXGiJ` calls `lIKxeQZNPA()` exactly once, at `IL_08db`. Everything before
that call is decode; everything after is execution. That single seam is what makes
static-free extraction practical — see
[Extraction Strategy](#extraction-strategy-harvest-the-decoded-program).

### The Program Is an Object Graph, Not a Byte Stream

This is the single most important structural fact about .NET Reactor's VM, and it
is what separates it from KoiVM, EazVM and VirtualGuard.

After decode, a virtualized method is a
`List<pmhFGRPKUN0cv5gbsq2>` — a list of **instruction objects**. The instruction
type (`0x0200002f`) has exactly two fields:

| Field | Token | Type | Role |
|-------|-------|------|------|
| `qLOHqjHEu6` | `0x0400006E` | `guRiCRPRexpb1c3DuN0` (enum, `0x02000045`) | **opcode** |
| `x8xH1QMtT2` | `0x0400006F` | `object` | **operand** |

The operand is a boxed CLR object, and by the time it is stored it has already
been *materialized*: the loader resolves metadata into live `System.Type`,
`MethodBase` and `MethodInfo` instances (122 `System.Type` and 20 `MethodBase`
references in `j4XlTwXGiJ` alone), decodes constants with the custom varint reader
`eKLl9Pieuj`, and stores `null` for operand-less opcodes. A tag byte read with
`ldelem.u1` selects the per-kind decode path.

So there is no persistent "VM bytecode" to disassemble. There is an encrypted
resource, and there is a decoded object graph. Nothing in between survives.

### Fetch–Dispatch

`vjuxAdNiYK` fetches and dispatches:

```
IL_0080: ldfld  MwSjwlZbVA          /* 0x04000093 */   // VM context -> program holder
IL_0085: ldfld  u18xPWpKQV          /* 0x0400008B */   // -> List<instruction>
IL_008a: ldfld  QULjDgrIqA          /* 0x0400009A */   // program counter
IL_0090: callvirt List<T>::get_Item(int32)
IL_0095: stloc.0                                        // fetched instruction
IL_0096: ldloc.0
IL_0098: ldfld  x8xH1QMtT2          /* 0x0400006F */   // operand
IL_009d: stfld  W6nj3gfLbK          /* 0x0400009D */   // -> VM context operand slot
.try {
IL_00a4: call   XGtxjqudOH(instruction)                /* 0x060002DE */
```

The operand is stashed on the VM context *before* dispatch; handlers read it from
there rather than from their argument.

| Field | Token | Purpose |
|-------|-------|---------|
| `QULjDgrIqA` | `0x0400009A` | Program counter |
| `pRejhltIYn` | `0x0400009B` | Previous/saved PC |
| `W6nj3gfLbK` | `0x0400009D` | Current operand |
| `RKyjTXlhNj` | `0x0400009E` | Branch flag |
| `qTqjOcsEDb` | `0x0400009F` | Return flag |
| `i2Ij2Wrl3j` | `0x040000A0` | Halt flag |
| `qeGj0vFdv1` | `0x04000096` | Operand stack (type `C6jel6PFv1y17TI7U6B`) |

The three flag fields are read-and-clear: the loop tests each, resets it, and
either returns or continues. `ItKxx2Gt1k(int32, int32)` performs the branch
bookkeeping when `RKyjTXlhNj` is set. Exception dispatch is handled around the
call site with `List<SlAA3BPujT9MFKtPeno>` handler lists and explicit
`TargetInvocationException` unwrapping.

### Handlers Are Regions, Not Methods

`XGtxjqudOH` (`0x060002DE`, 3,908 lines of disassembly, 39 locals) switches on the
opcode enum read directly off the instruction object:

```
IL_0000: ldarg.1
IL_0001: ldfld    guRiCRPRexpb1c3DuN0 pmhFGRPKUN0cv5gbsq2::qLOHqjHEu6  /* 0x0400006E */
IL_0006: stloc.0
IL_0007: ldloc.0
IL_0008: switch   ( IL_145c, IL_198d, IL_20f6, … )      // 175 entries
```

**175 case entries, plus the default path.** Duplicate targets are common
(`IL_27f6` appears at indices 10, 14, 48, 49; `IL_145c` at 0, 44, 56 …), so the
~154 distinct targets from the earlier count are consistent.

Every handler body is **inline in this one method**. There is no handler table, no
array of delegates, and no per-opcode method. A "handler" is a region of basic
blocks inside `XGtxjqudOH` dominated by one switch-case target.

This defeats the usual detection heuristic — "a type containing many small methods
with similar signatures" — completely. .NET Reactor's VM has zero handler methods.

### Semantics Live Behind Virtual Dispatch

Case 5 (`IL_046d`), a comparison handler, in full:

```
IL_046d: ldarg.0; ldfld qeGj0vFdv1                     // operand stack
IL_0473: callvirt jvj3LnPpvxU2erTMeM4 C6jel6PFv1y17TI7U6B::Ysk3wvblFN()   /* 0x06000344 = pop */
IL_0478: stloc.s 4
IL_047a: ldarg.0; ldfld qeGj0vFdv1
IL_0480: callvirt Ysk3wvblFN()                                            /* pop */
IL_0485: call     wm4NTEPOv5wQhC99DbT dIB6JIPIiI7GlyxJGUd::On9h7vfNJU(jvj3LnPpvxU2erTMeM4)
IL_048a: ldloc.s 4
IL_048c: callvirt bool wm4NTEPOv5wQhC99DbT::ojAOxCx0yc(jvj3LnPpvxU2erTMeM4)
IL_0491: brfalse  IL_04a8
IL_0496: ldarg.0; ldfld qeGj0vFdv1
IL_049d: newobj   KTvJuZPhZohptT4uVf6::.ctor(int32)     // push 1
IL_04a2: callvirt void C6jel6PFv1y17TI7U6B::hYG3VSV4XB(jvj3LnPpvxU2erTMeM4)  /* 0x06000342 = push */
IL_04a7: ret
IL_04a8: … newobj KTvJuZPhZohptT4uVf6::.ctor(int32)     // push 0
IL_04b4: callvirt hYG3VSV4XB(…)
IL_04b9: ret
```

Read structurally, this region says: *pop two values, call something, push 0 or 1*.
It does **not** say which comparison. The actual operation lives in
`ojAOxCx0yc`, resolved at runtime by the concrete type of the popped VM value —
one of the four parallel value types. 152 of the 983 calls in the dispatcher go
directly to those four types.

**Consequence:** SSA pattern matching on a handler region cannot classify .NET
Reactor's opcodes. Structure yields the *stack effect*; it does not yield the
*operation*. Any classifier that works here must be behavioural.

### Execution Is Reflection-Driven

The dispatcher performs CIL-level operations through reflection:
`MethodBase.Invoke` (2 sites), `FieldInfo.GetValue` (14), `FieldInfo.SetValue`
(4), and `Activator`/`ConstructorInfo.CreateInstance` (7). Locals of type
`ConstructorInfo`, `MethodInfo`, `MethodInfo[]` and `List<System.Type>` are
declared at the top of `XGtxjqudOH`.

For a devirtualizer this means a call operand is a *live `MethodInfo`*, not a
metadata token. Emitting `call`/`callvirt`/`newobj`/`ldfld` requires mapping the
reflection object back to its defining token.


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

Every value on the virtual stack carries one of these tags at runtime. That is a
per-value type oracle a devirtualizer can read directly out of emulated state.

### 4 Parallel VM Value Types

Four large types implement the polymorphic VM value abstraction, each specialized
for different data widths. `jvj3LnPpvxU2erTMeM4` is the common base.

| Type | Methods | Unique Methods | Likely Specialization |
|------|---------|----------------|----------------------|
| `KFLZn1PTyq5gG2AjYpx` | 104 | 12 | Full (64-bit, pointers, `Add`) |
| `KTvJuZPhZohptT4uVf6` | 93 | 2 | Standard (15-case opcode handler) |
| `ShYNHsP3JZ1gO8BRpVH` | 92 | 3 | Variant |
| `aqAvMsP2XIn3GUhf0si` | 88 | 0 | Minimal |

Each shares ~70 identical method signatures (`JfS3vO6qin`, `Th73tWZsCb`,
`FHPTbr88Ae`, `Add`, `ToString`, arithmetic/comparison handlers). Arithmetic and
comparison are dispatched polymorphically through these types — which is precisely
what makes the dispatcher's own IL semantics-free.

### Value Boxing

`jVsj6JAdhh` (855 lines, 19-case switch): boxes .NET values into the appropriate
VM value type based on the type ID from the classifier. Called 3 times from the
loader, when marshalling the incoming `object[]` arguments onto the virtual stack.


## Bytecode Storage and Decryption

### Embedded Resource

The encrypted program is stored as an embedded assembly resource, loaded via:

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
- Custom padding: `(448 - len*8) % 512` (Merkle–Damgård style)
- Key derivation in `tRelL85we1`: 32-byte key from seed, `ICryptoTransform`

### Method Body Loading: `j4XlTwXGiJ` (933 lines of disassembly, 46 locals)

1. Reads from a static cache array (field row 71) indexed by method ID
2. If not cached, reads from the decrypted resource stream (field row 74)
3. Uses a **custom compressed integer encoding** (`eKLl9Pieuj`, 16 call sites —
   6-bit base plus continuation bits; *not* .NET's standard compressed integer)
4. Reads parameter types, local variable types, instruction count, instruction data
5. Materializes each instruction as an object: opcode enum + resolved operand
6. **Token resolution** via `osalebjCgR`: masks with `0x0FFFFFFF`, indexes a
   pre-built token array (field row 79) populated during initialization

Step 1 means the program for method *id* is only decoded when *id* is first
invoked. Harvesting all eight requires driving all eight ids.


## Injected Type Inventory (79 new types)

### Core Infrastructure

| Type | Namespace | Methods | Role |
|------|-----------|---------|------|
| `UhSaWDOYZTgwwgfSO6` | `Dinih72WZsCb9wcqjy` | 23 | VM bootstrap, entry point, body loader |
| `dIB6JIPIiI7GlyxJGUd` | — | 28 | VM context + 175-case dispatcher |
| `oMu6jVbdhHEH79DDhU` | `AoIBWWlDJbaf7LijnA` | 49 | Resource decryptor, crypto |
| `jvj3LnPpvxU2erTMeM4` | — | 17 | VM value base type, boxing |
| `uy4ZXuP8hhYiKuNrl4` | `AsG4wKEPrjKTCY31dc` | 3 | Token resolver |
| `gttro5yuWySr2hbdEM` | `UWxvxUSU2ZrCqT9K8B` | 2 | License date check |
| `gEHfEJ9aJKgHNTQig9` | — | 2 | Crypto helper (AES/SHA) |
| `VM792LkqNpj06PcE1F` | — | 6 | Stream wrapper |

### VM Value Types (4 parallel instantiations)

`KFLZn1PTyq5gG2AjYpx` (104), `KTvJuZPhZohptT4uVf6` (93),
`ShYNHsP3JZ1gO8BRpVH` (92), `aqAvMsP2XIn3GUhf0si` (88).

### VM Stack/Reader Variants (5 types, 11 methods each)

`pCcUn2Pk0WRdx9wXGtQ`, `RLZZMSPJ8nNSMssYi0I`, `Y2TQrxPUsKZAuW0CSyH`,
`LmTcB5PZLgTyJV4YP0Z`, `k1MD8LPCkL4TjT0JVvC`

### Helper Types

| Type | Methods | Role |
|------|---------|------|
| `C6jel6PFv1y17TI7U6B` | 6 | **Operand stack** — `hYG3VSV4XB` push (`0x06000342`), `Ysk3wvblFN` pop (`0x06000344`) |
| `pmhFGRPKUN0cv5gbsq2` | — | Instruction: opcode enum + `object` operand |
| `guRiCRPRexpb1c3DuN0` | — | Opcode enum (`0x02000045`) |
| `LbcypsPYVeerQlaEm3O` | 6 | Instruction key (`Equals`, `GetHashCode`) |
| `NWOcXrPi1WKXw4SWh1B\`1` | 8 | Nullable wrapper |
| `FwrX5yPtqhsabjCgRnP` | 3 | Static initializer |
| `d8DE92F8305BE09E` | 11 | String interpolation handler |
| 10+ small types | 1-2 each | Enums, structs, exception types |


## What This Means for Devirtualization

### Extraction Strategy: Harvest the Decoded Program

The obvious approach — reimplement AES key derivation, the custom varint reader,
the resource format and the token array in Rust — is the wrong one. It is a
per-version reimplementation of machinery the sample already contains, and .NET
Reactor changes it between releases.

The alternative uses infrastructure dotscope already has, and mirrors what already
works for NecroBit variant A: **emulate the sample's own loader, then read the
decoded program out of the emulator heap.**

1. Hook `lIKxeQZNPA` (`0x060002D7`) to return immediately. Decode completes;
   execution never starts.
2. Emulate `BD6lOYUCm3(id, args, null)` once per method id, with `args` populated
   from the stub's `box` types.
3. Walk `process.address_space().managed_heap()` for `HeapObject::Object` entries
   whose `type_token` is the instruction type, reading field `0x0400006E`
   (opcode) and `0x0400006F` (operand). Order comes from the backing array of the
   `List<T>` reachable from the VM context.

Every primitive this needs already exists — `HeapObject::Object { type_token,
fields: HashMap<Token, EmValue> }` gives field-token-keyed access, and
`find_variant_a_blob` in `necrobit.rs` is the same harvest applied to an array.

The residual risk is emulator coverage of the crypto and reflection the loader
performs, not the design. That is measurable up front: emulate one method id and
see whether the list materializes.

### Classification Strategy: Probe the VM, Don't Read the Handlers

Since handler regions are semantics-free (see
[Semantics Live Behind Virtual Dispatch](#semantics-live-behind-virtual-dispatch)),
opcodes must be classified behaviourally.

The cheapest behavioural method does not require entering a handler region at all.
Synthesize a **one-instruction program** — a `List` containing a single
instruction object with opcode *k* and a chosen operand — install it on a VM
context with a known virtual stack, run one dispatch step, and diff the resulting
state:

- stack depth delta and the type tags of pushed values → stack effect
- pushed value for known inputs → which arithmetic/comparison operation
- PC delta and branch-flag writes → control flow role
- reflection calls observed during the step → `call` / `newobj` / field access

This exercises the real prologue, the real value-type dispatch, and the real
operand plumbing, and it needs no new emulator capability — no mid-method entry,
no synthetic frames. It also generalizes past .NET Reactor: any VM whose loader
and dispatcher can be emulated can be probed this way, regardless of whether its
handlers are methods, regions, or delegates, and regardless of opcode
randomization.

### Type Recovery Is Cheap Here

Three independent sources of type information survive virtualization:

1. The MethodDef signature, untouched.
2. The stub's `box`/`unbox.any` operands, naming each boundary type exactly.
3. The runtime type tag (0–18) carried by every value on the virtual stack.

Compare KoiVM, where all type information is destroyed and must be reconstructed
by data flow analysis. .NET Reactor's virtualization is significantly friendlier
in this one respect, and it matters: dotscope's `SsaFunctionBuilder::build_with`
rejects any used variable still typed `SsaType::Unknown`, so a lifter must type
every value it creates.

### Ordering Constraint

In `reactor_virtualization_full.exe`, NecroBit encrypts every method body —
including the VM loader and dispatcher. Devirtualization there is strictly
downstream of NecroBit body decryption: until those 562 stubs are recovered, the
VM is not merely unanalysable, it is not present in readable form.

### Complexity Assessment

175 switch cases, ~154 distinct handler regions, 3,908 lines of dispatcher IL, 39
locals, semantics behind polymorphic dispatch on four value types, execution via
reflection. This is a full-featured VM, and it is a poor fit for the byte-stream,
handler-table model that KoiVM and EazVM share.

The generic framework needed to accommodate it is described in
[design/vm_devirtualization.md](../../design/vm_devirtualization.md); the
NET Reactor findings above are what motivate that document's extraction and
classification boundaries.
