# `<PrivateImplementationDetails>{GUID}` — NR Data Container

.NET Reactor injects one or more types named
`<PrivateImplementationDetails>{GUID}` into every protected assembly. They
look like the C# compiler's static-array-initialization helper but are
NR-specific data packaging for the protector's runtime.

## Distinguishability vs the compiler form

The C# compiler emits a single helper type called exactly
`<PrivateImplementationDetails>` (no GUID suffix) the first time it needs
to materialise a constant `byte[]` / `ReadOnlySpan<byte>`. NR keeps the
compiler form (because the user's code may depend on it) and adds its own
container with a deterministic `{GUID}` suffix, e.g.

```text
<PrivateImplementationDetails>                         ← compiler-generated, KEEP
<PrivateImplementationDetails>{AE6CEE16-BBC3-4A62-9EAE-772BD6DEAF46}   ← NR-injected
<PrivateImplementationDetails>{E3CEB5BF-992C-4232-9FCD-5EA0D695CC9F}   ← NR-injected (different sample)
<PrivateImplementationDetails>{556113CE-EF52-4949-A529-597962C3B69E}   ← NR-injected (anti-tamper sample)
```

The GUID suffix is the **structural NR signal**. No production C# / F# /
VB.NET compiler emits a `<PrivateImplementationDetails>` with a GUID suffix
— the standard naming uses no suffix at all. This makes the suffix a safe
gate for NR-specific cleanup.

The GUID itself is randomised per protection run; it is not stable across
samples or across runs of the same input.

## Internal structure

The container is a `private auto ansi sealed` class extending
`System.Object` with `[CompilerGeneratedAttribute]`, mirroring the compiler
form. Inside the container:

- **Fields** named after the SHA-256 hash of their initial bytes:

  ```text
  .field assembly static initonly valuetype <PrivateImplementationDetails>{GUID}/__StaticArrayInitTypeSize=12
      '03DCEB56B5842C722DE2821DA9906CD70AB73267EAB1A3947BFD894D19372BC7'
      at I_00002BF4
  ```

  - The field name is the 64-char hex SHA-256 of the field's initial value
    (content-addressed naming — identical blobs across uses dedupe to one
    field).
  - The field type is one of the nested `__StaticArrayInitTypeSize=N`
    value-types declared inside the same container, where `N` is the byte
    count of the blob.
  - The `at I_xxxx` directive points into a PE data section via the
    `FieldRVA` table; the bytes there are the actual blob.

- **Nested value-types** named `__StaticArrayInitTypeSize=N` for each
  distinct blob size used in the container:

  ```text
  .class nested assembly explicit ansi sealed __StaticArrayInitTypeSize=18
         extends System.ValueType
  { .pack 1   .size 18 }
  ```

  These exist only as size-shims so `RuntimeHelpers.InitializeArray` knows
  how many bytes to copy when materialising the field value into a
  managed `byte[]`. They have no methods, no other fields, and no other
  uses anywhere in the assembly.

Observed sizes across samples: typically 5 – 14 fields per container, with
sizes spanning 12, 16, 18, 22, 24, 30, 32, 34, 40, 64, 256 bytes.

## What NR uses these blobs for

The packed blobs are crypto material and lookup tables consumed by NR's
runtime protections:

| Consumer                          | Blob role                                            |
| --------------------------------- | ---------------------------------------------------- |
| String decryption (Stage 6)       | AES key (32 B), AES IV (16 B), per-call XOR keys     |
| Control flow flattening (Stage 2) | State-table lookups, opaque arithmetic constants     |
| Anti-tamper (Stage 3)             | RijndaelManaged key/IV for body verification         |
| NecroBit (Stage 1)                | Per-method decryption keys (full-protection samples) |
| Resource encryption (Stage 7)     | Per-resource decryption keys                         |

A single container often serves multiple protections — blobs are shared
across consumers via content-addressed deduplication (the SHA-256 field
name guarantees identical blobs collapse to one field).

The compiler-form `<PrivateImplementationDetails>` (no GUID) **never**
holds NR data. NR leaves it untouched so that any user-code references
(e.g. `ReadOnlySpan<byte>` constants the compiler produced) keep working.

## When the container becomes orphaned

After the existing dotscope deobfuscation passes complete:

1. `generic.flattening` reconstructs CFF dispatchers, eliminating their
   state-table `ldsfld`s.
2. `generic.strings` / `generic.constants` emulate decryptors and inline
   the resulting literals, eliminating their key/IV `ldsfld`s.
3. `netreactor.necrobit` emulates the body decryptor and writes restored
   IL into the assembly, eliminating its NecroBit-key `ldsfld`s.
4. The opaque-field passes inline the constant-folded values from CFF
   state arithmetic.

By the time `build_cleanup_request` runs, no surviving method body
references any field of the GUID container, and no method or
custom-attribute references the container's nested
`__StaticArrayInitTypeSize=N` subtypes. Verified empirically against
`reactor_obfuscation_out.exe` and `reactor_necrobit_out.exe`: zero
`ldsfld` / `ldsflda` / `ldtoken` / `InitializeArray` references to any
GUID-suffixed `<PrivateImplementationDetails>{...}` field or subtype.

The container is then pure dead weight — it cannot be dropped by the
existing `find_unreferenced_types` orphan sweep because that sweep
requires "at least one non-cctor method" (`cleanup/analysis.rs:152-160`)
and these containers have **no methods at all**.

## Cleanup approach used by `netreactor.privateimpl`

The `netreactor.privateimpl` technique (Pattern D — DetectionOnly) is the
NR-specific owner for this artifact. Its job is exactly to catch what the
generic orphan sweep cannot:

1. **Structural detection**: enumerate `TypeDef` rows whose name matches
   the GUID-suffix pattern
   `^<PrivateImplementationDetails>\{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX\}$`
   where `X` is a hex character. Pure structural — no version constants,
   no name hardcoding beyond the GUID shape.
2. **NR-context gate**: only mark when an `<Module>` trial guard is also
   present (i.e. `netreactor.antitrial` would also detect). This is the
   same gate `netreactor.licensecheck` uses; it confirms the assembly is
   NR-protected and prevents a hypothetical false-positive on a
   user-defined GUID-suffixed type.
3. **Per-container marking**: add the container's TypeDef token to the
   detection's cleanup. The cleanup pipeline's `expand_type_tokens`
   (`cleanup/analysis.rs:44-76`) automatically cascades to the nested
   `__StaticArrayInitTypeSize` subtypes and all SHA-256-named fields.

If a container still has live references when cleanup runs (which would
indicate one of the upstream passes failed to simplify), the cleanup
executor will refuse to delete it during regeneration validation — a
loud failure rather than silent corruption. In practice this never
fires on the current samples, because the upstream passes always
complete before cleanup.

## Why this artifact, owned by this technique

The container is fundamentally NR's **packaging strategy**, not the
output of any one protection. Multiple NR techniques (string decrypt,
CFF, anti-tamper, NecroBit) share the same container, so attributing
removal to e.g. `netreactor.strings` would be wrong — the container
outlives any single decryption. A dedicated NR technique whose job is
"clean up NR's data packaging once no protection still needs it" is the
correct attribution: the technique result reads
`netreactor.privateimpl: removed N container types` and the per-sample
report shows exactly which packaging artifacts were dropped.

## Cross-references

- [`shared-infrastructure.md`](shared-infrastructure.md) — the trial
  guard / delegate proxy / license check / `ObfuscationAttribute`
  baseline that always co-occurs with the GUID container.
- [`anti-tamper.md`](anti-tamper.md) — names the container as a
  "GUID-Annotated Marker Type" (terminology slightly misleading; the
  container carries crypto material as well as marking).
- [`necrobit.md`](necrobit.md) — table row labels it "Static array data".
- [`NETReactor.summary.md`](NETReactor.summary.md) — sample-by-sample
  inventory of remaining `<PrivateImplementationDetails>{GUID}`
  containers across the deobfuscated outputs.
