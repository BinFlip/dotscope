# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-08-14

A security and correctness release. dotscope parses, emulates and rewrites
hostile input, and this release closes the gap between what the resource limits
claimed to enforce and what they actually did, along with a set of
miscompilations in the SSA back end and layout defects in the PE writer.

### Security

- **Resource limits are enforced before the work happens, not after.** The
  managed-heap ceiling was checked once the object was already materialised;
  unmanaged allocation (`localloc`, `AllocHGlobal`, `AllocCoTaskMem`,
  `VirtualAlloc`) had no budget at all, and `max_unmanaged_bytes` and
  `max_heap_objects` were declared but never read. Allocation
  now runs through a reservation that must succeed first, in-place mutation is
  accounted, and forks inherit the ceiling instead of escaping it.
- **Unbounded and quadratic work on attacker input.** Fixed in the inheritance
  walker (a cyclic `extends` graph caused an uncatchable native stack overflow),
  the x86 traversal (O(n²) to end of file), method-body decoding (disassembled
  past the declared `code_size`), exception-handler association (O(H²·B) at load
  time), DEFLATE/GZIP/LZMA expansion, and the signature parser (a blob could
  build a ~61 000-deep type whose recursive drop overflowed the stack).
- **Argument validation across the BCL hooks.** Negative or oversized lengths
  reaching `Marshal.Copy`, `Stream.SetLength`, `StringBuilder.set_Length`,
  `String.PadLeft`/`PadRight`, the `BinaryReader` readers and the PBKDF2
  constructors reserved `usize::MAX`, ran multi-billion-iteration loops, or
  drove a ~4.3-billion-round KDF. They now reject the value and raise the .NET
  exception.
- **Emulator forks were not isolated.** "Isolated" forks shared one mutable
  runtime state, AppDomain and synthetic-method map while running concurrently.
  `Assembly.Load(byte[])` is now bounded by `max_loaded_assemblies` and
  `max_loaded_assembly_bytes`, and runtime-loaded assemblies parse with minimal
  validation rather than the full pipeline over hostile bytes.
- **Memory protection flags are enforced** on read and write, faulting through a
  new catchable `AccessViolationException`, and region mappings are overlap-checked.
- `deny(unsafe_code)` is enabled. One `unsafe` block remains, for the writer's
  output mapping, with a targeted allow and a SAFETY note.
- `SECURITY.md` now states the supported version, the real `EmulationLimits`
  defaults and what is actually run. The previous text listed DoS protections as
  "ToDo" and claimed Valgrind testing that does not exist.

### Fixed

- **Malformed table rows silently truncated a table.** The row iterators
  reported a parse failure as end-of-iteration, and because the writer rebuilds
  tables by iterating them, an unreadable row became *missing output* rather
  than an error. Iterators now yield `Result`, `get` returns
  `Result<Option<T>>`, and `MetadataTable::new` validates and truncates to the
  declared extent.
- **`MethodPtr`, `EventPtr` and `PropertyPtr` tokens used the wrong table id**,
  so any assembly carrying a `*Ptr` table lost its method-bearing types.
- **Three back-end miscompilations.** Full inlining placed the return-value copy
  before the instruction defining it; switch and conditional-branch phi
  trampolines fell through into the next edge's copies. Critical edges are now
  split into real blocks by a dedicated out-of-SSA pass.
- **Handler SSA used a "last block wins" snapshot** of try-scope definitions
  because the CIL CFG carried no exception edges. Real EH edges make handler
  entries ordinary join points.
- **Linear-scan allocation computed live intervals with no liveness solve**, so
  a value live across a back edge could have its slot clobbered.
- **Four exception-unwind defects**: the caller's `finally` ran against the
  grandparent frame, queued `finally` blocks were never drained once a catch was
  selected, a `leave` out of nested `finally`s spun on `endfinally`, and a filter
  returning zero terminated emulation instead of resuming the handler search.
- **PE writer layout.** Heap offsets were computed twice from different inputs,
  so offsets baked into tables and IL disagreed with where data was written;
  heap index widths were inherited from the input and truncated above 0xFFFF;
  section `SizeOfRawData` came from the virtual extent; and the input's
  certificate directory offset was applied to the output, zeroing live `.text`
  before the checksum was computed over the damage. `Output` now writes to a
  temp file and renames.
- **Cleanup deleted live metadata**: TypeRef liveness ignored `ResolutionScope`,
  and the opaque-field pass folded any static-to-instance load and deleted the
  owning type with no immutability precondition.
- Byte-offset slicing of string literals panicked on multi-byte UTF-8;
  `clippy::string_slice` is now denied, which surfaced ten genuine sites.
- The fuzz crash-corpus regression test passed on any checkout without the
  corpus, and CI ran `cargo test --lib`, so the integration tests never executed
  on Windows or macOS. Both are fixed, and the 72 crash artifacts are committed.

### Performance

- `EmValue` drops from 200 to 104 bytes on x86-64 by boxing `CilFlavor::FnPtr`,
  halving every value in the interpreter. Pinned by a static assertion.
- `Method`, `CilType` and `Param` no longer eagerly allocate 8–11 `Arc<boxcar::Vec<_>>`
  each; `LazyList<T>` defers to first use.
- Type resolution: `get_by_fullname` no longer falls back to a linear scan of
  every registered type (reachable once per custom-attribute argument), and
  `fullname()` returns `Arc<str>` instead of allocating a fresh `String` at every
  call site.
- Declaring-type lookups are indexed rather than brute-force scans over every
  type and member — they sat on the emulator's hottest paths.
- Table loaders no longer take a shared `Mutex` once per row inside the rayon
  loop; an inherent `try_for_each` had been shadowing rayon's in every loader.
- Handler SSA no longer rebuilds a version-stack snapshot per exception
  successor per block, and unmanaged access is a `BTreeMap` lookup rather than a
  linear region scan that allocated a `Vec` for a 1–8 byte read.

### Changed

- **BREAKING**: `Error` is `#[non_exhaustive]` and derives `Clone`. The previous
  hand-written `Clone` rewrote most variants into `Error::Other(String)`,
  destroying the taxonomy for any caller that cloned.
- **BREAKING**: `MetadataTable::get` returns `Result<Option<T>>` and the table
  iterators yield `Result<T>`.
- **BREAKING**: `CilType::fullname()` returns `Arc<str>`; `UserStrings::get`
  returns an owned `U16String`; `derive_pbkdf2_key` returns `Result` and errors
  on an unavailable algorithm instead of silently substituting SHA-256 for SHA-1.
- `CaptureConfig` gains `max_items` and `max_total_bytes` ceilings (10 000 and
  256 MB), and buffer capture is off under a default config, honouring the
  documented "no capture by default" contract. `CaptureContext::new()` sets it
  explicitly, so the "capture what is useful" constructor is unchanged.
- Stale rustdoc `# Errors` contracts across the crate referenced `Error` variants
  that had been deleted. They are rewritten to what the code returns, and
  `deny(rustdoc::broken_intra_doc_links)` plus `RUSTDOCFLAGS: -Dwarnings` in CI
  keeps them accurate — `RUSTFLAGS` does not reach rustdoc, which is why the
  existing `-Dwarnings` never caught them.
- Doc tests run under a concurrency cap: each fenced example is a whole-crate
  fat-LTO link, and one per core exhausts memory on a many-core machine.
- Five new fuzz targets beside `cilobject`, covering the assembly view, the
  signature and custom-attribute blob parsers, method-body decode and bounded
  emulation.

## [0.8.5] - 2026-08-09

### Fixed

- **No licence text was shipped with the crate.** `LICENSE` and `NOTICE` live at the
  workspace root, but the package root is `dotscope/`, and cargo only packages files
  under the package directory — so every published version declared
  `license = "Apache-2.0"` while shipping neither the licence nor the NOTICE.
  Both files now exist inside the package and are included in the published crate.
- `LICENSE` was a symlink to `LICENSE-APACHE`. Symlinks do not survive packaging
  cleanly; `LICENSE` is now a regular file and the duplicate `LICENSE-APACHE` is gone,
  with the README badge and the crate-level doc badge repointed at it.

### Dependencies

- Upgraded `analyssa` 0.4.1 → 0.5.0, which fixes SSA rebuild and phi-transform
  correctness: on a 125 MB reference binary the upstream pass rollbacks went from
  6,094 to 0 and verifier-reported undefined uses from ~28,960 to 0. No API changes
  were needed here.
- Upgraded `comfy-table` 7.2.2 → 8.0.0. The preset-string API was removed in v8;
  `Table::load_preset(presets::NOTHING)` becomes `Table::load_style(presets::NOTHING)`,
  where presets are now `TableStyle` constants. Rendering is unchanged.
- Refreshed all remaining dependencies (`cargo update`), including `aes`, `clap`,
  `thiserror`, and `smallvec`.

### Changed

- Recorded ATRAPS LLC as copyright holder in `LICENSE` and `NOTICE`.
- Dropped the deprecated `authors` field from both workspace members and repointed
  `repository` / `homepage` at the organisation.
- Default branch renamed from `master` to `main`; CI triggers and the fuzzing and
  security-audit job conditions were updated to match.
- Publishing now uses crates.io trusted publishing instead of a stored registry token,
  and refuses to publish a release whose commit is not contained in `main`.

## [0.8.4] - 2026-07-26

### Added

- **Memory optimization pass** (`compiler::MemoryOptimizationPass`): store-to-load forwarding, redundant load elimination, and block-local dead store elimination, every rewrite gated on a Memory SSA alias proof. Registered in the deobfuscation pipeline's normalize phase and enabled by default; disable with `PassConfig::memory_optimization = false`. This reaches the field and array traffic obfuscators use to keep values out of SSA registers, which the register-level passes cannot see through
- **Field-sensitive points-to for CIL** (`CilTarget::field_member_index`): the field's metadata token supplies the stable per-field cell identity Andersen's analysis keys on, so `&o.a` and `&o.b` no longer alias. An unresolved (null) field token falls back to the sound whole-object approximation
- **x86 segment overrides reach the IR**: `X86Memory` gained a `segment` field, decoded from the instruction's explicit prefix, and `fs:`/`gs:`-qualified accesses now lower to `LoadIndirect`/`StoreIndirect` with a distinct `address_space` (257/256, following LLVM's numbering). Alias analysis treats the spaces as disjoint, so TEB/PEB and stack-cookie accesses stop colliding with flat memory at the same displacement. `cs:`/`ds:`/`es:`/`ss:` deliberately stay in the flat default — in flat user mode they share a base, and marking them would let alias analysis prove two names for one cell disjoint
- **Re-exports for analyssa's new alias machinery**: `analysis::{pointsto, address}` modules plus `MemorySsa`, `IndirectLocation`, `ArrayIndex`, `AliasResult`, `MemoryDefSite`, `MemoryPhiOperand`, and `MemorySsaStats`
- **Cross-block value promotion before CFF restructuring** (`deobfuscation::passes::unflattening::spill`): unflattening rewires the CFG, so the SSA has to be reconstructed afterwards — and reconstruction is a reaching-definition problem that can only be solved for values with a storage location. Arguments and locals have one; a stack temporary produced in one block and consumed in another exists only as an SSA name, and the sole record that two names denote the same value is the phi that merges them. Rewiring discards exactly that record, and for an edge the patch *creates* no phi ever described it. Every value crossing a block boundary is now promoted to a local slot before any terminator is touched — the classical "spill temporaries before restructuring" step — so rebuild can recover versions and phi placement for all of them by the ordinary algorithm. This is what makes .NET Reactor NecroBit samples reconstruct at all, and it is correct for any rewiring rather than only the shapes whose phis happen to survive
- **Zero-initialization for undefined SSA definitions** (`SsaConverter`): a new construction phase materializes definitions for variables that had none, following ECMA-335 §I.12.3.2.2 — a typed zero `Const` for primitives and references, and `LoadLocalAddr; InitObj; LoadLocal` for value types. Previously such variables were registered with no defining instruction, so they survived initial construction but vanished the moment the variable table was rebuilt from real definitions
- **Emulation and CFF smoke tests** (`tests/emulation_smoke.rs`): five samples whose deobfuscation depends on emulation or the unflattening tracer producing byte-identical results, each checked for semantic preservation against `original.exe`. The full packer suites take hours; this runs in seconds, so a change to the emulation layer or the tracer is validated against real output rather than only wall-clock time
- **Deobfuscation benchmark** (`benches/deobfuscation.rs`): ConfuserEx and .NET Reactor groups plus a detection-only control, behind `--features deobfuscation`

### Fixed

- **Taint-driven neutralization could produce IR with dangling reads**: `SentinelTaintRemovalPass` and `NeutralizationPass` rewrote every tainted instruction to `Nop` and dropped every tainted phi, destroying definitions that surviving code still read. `PhiTaintMode::NoPropagation` makes phis taint barriers by design, so a phi routinely merges a tainted definition into code the analysis never marks. Both passes now shrink the removal set to a fixpoint (`utils::retain_removable`) — a candidate whose result still has a reader is kept rather than the removal widening into legitimate code. `NeutralizationPass` also excludes its protected `DecryptedString` constants from the candidate set rather than at rewrite time, so branch-target selection sees what is actually removed
- **`AssemblyDependencyGraph::find_cycles` reports participants, not a closed walk**: following analyssa's switch to a single deterministic Tarjan pass, a self-dependency now names the assembly once rather than twice. The stale "modified DFS with three-color marking" documentation was corrected to match
- **CIL emulation fetched instructions in O(n)** (`emulation::engine::context::MethodCode`): every executed instruction cloned the method's entire instruction vector and scanned it linearly for the current offset. A 3-million-instruction run performed 3.2 billion `Instruction` clones — about 1052 per step. Method bodies are now cached per token with an offset-to-index map, and the execution loop borrows the instruction instead of cloning it. Synthetic bodies bypass the cache, since `ILGenerator` can mutate them
- **Emulation rebuilt the assembly context on every instruction**: `loaded_assembly_context` constructed a fresh `EmulationContext` and took an `RwLock` per executed instruction; contexts are now memoized per assembly index
- **`optimize_locals` split values it renumbered** (`SsaFunctionCilExt`): renumbering a local moved its origin but left its rename group pointing at the old slot. `rebuild_ssa` groups variables by rename group while resolving argument/local representatives by origin, so the two views disagreed about which names denote the same local and the value ended up with no reaching definition. Both now move together
- **CFF tracer could escape its visit budget**: entering an expression-switch false arm deliberately resets `total_visits` so each arm gets its own budget. On heavily nested methods that reset fired often enough to make the budget unbounded — a 348-block ConfuserEx method reached 3.3 million block visits against a 50,000 cap. A monotonic counter now bounds total work per trace without changing the per-arm semantics
- **CFF reconstruction produced invalid SSA after block cloning**: cloned blocks duplicated every definition they contained, phi operands survived pointing at predecessors the patched CFG no longer has, and operands were left naming redirected blocks. Clones now allocate fresh variable ids (after state-tainted filtering, which keys on the original ids), phi operands are pruned against the patched predecessor sets and definedness, and redirected operands are resolved through a bounded hop limit
- **Cleanup deleted live types reachable only through another deletion candidate** (#249, fix contributed in #248 by [@agski331](https://github.com/agski331)): `find_unreferenced_types` computed a single step of what is a transitive reachability problem. A candidate rescued partway through a pass never propagated that liveness onwards, so any cluster reachable solely through it was still read as isolated infrastructure — on `reactor_virtualization` that cut the assembly from 854 methods to 45, deleting a VM interpreter whose stubs remain live because nothing devirtualizes it. Reachability is now a worklist drain over a type-level call graph, in `O(V+E)` rather than `O(depth × edges)`. CustomAttribute constructor types are seeded as roots before propagation rather than filtered afterwards, so the types those constructors call survive too, and liveness propagates from a nested type to its enclosing type — deleting an enclosing type cascades to its children through `expand_type_tokens`, which was dropping nested types that live code still called. The deletion set is sorted for a reproducible order
- **Technique cleanup ran whether or not the transformation it implies succeeded**: a technique builds its cleanup request from detection findings alone, so it scheduled the decryptor, its infrastructure type, the initializer and the encrypted data for deletion even when no call site was reversed, leaving those call sites pointing at metadata that no longer exists and emptying the methods holding them. Removal now requires that nothing still calls the decryptor — a successful decryption rewrites its call site to the constant, so the absence of remaining callers is the evidence of reversal. Absence of recorded failures is not, since a decryptor that was never exercised has none either. Note that the caller check reads the SSA call graph, which covers only methods that converted successfully
- **ConfuserEx constant decryption missed builds that differ from stock 1.6.0** (#249): four defects, each masking the next. The blob index was matched against `int32` alone, so builds emitting `T Get<T>(uint32)` yielded no decryptor at all — any integer width is now accepted, the surrounding constraints carrying the selectivity. `stobj` rejected reference types, though ECMA-335 §III.4.29 defines it over any `typeTok` and makes it equivalent to `stind.ref` for reference types, which is what `stobj !!T` becomes at `T = string`. `ldelema` hand-rolled its index match to `I32`/`NativeInt` while `ldelem`/`stelem` share a helper accepting every width, so a `native uint` index aborted emulation. And `stfld` through a pointer to a value-type array element replaced the whole element with the field's value instead of updating the field inside it, which is the path LZMA's bit-decoder struct arrays take
- **ConfuserEx LZMA blobs were rejected or misparsed** (#249): the sniffer required the compressed payload to be smaller than its declared output, but LZMA expands small high-entropy input and the constants blob is XOR-encrypted before compression — a 44-byte blob compresses to 51 and was refused. The header was also modelled as 5 property bytes plus a 4-byte size, while builds calling the LZMA SDK's stream API write the standard 13-byte header with an 8-byte size; reading that as 9 bytes shifts the payload and corrupts the range coder. Both layouts are now attempted and held to the size each declares, and the size ceiling is documented as an allocation guard rather than a property of the format

### Changed

- **Deobfuscating heavily flattened methods is roughly 25× faster**, through changes that leave what the tracer computes unchanged:
  - Forks mark the evaluator instead of copying it, using analyssa 0.4.1's new `checkpoint`/`rollback`. A flattened method forks millions of times and the evaluator's state grows with everything the trace has learned, so copying it per fork was measured at 99% of tracer time. The same journal treatment is applied to the tracer's own visited-state set, whose sole writer only ever inserts
  - Per-block structural facts — dispatcher-target and foreign-dispatcher membership, constant-producer targets, and the overflow-dispatch-site predecessor walk — are computed once per trace rather than per block visit
  - The cross-scope local bridge indexes variables by local slot instead of scanning the whole variable table inside the per-instruction loop
  - `PatchPlan` keeps membership and redirect-target indexes beside its ordered vectors, replacing linear scans that ran once per block of every node in the trace tree
  - Trace nodes store their visited blocks inline (`SmallVec`); a 1200-block method produced 92 million nodes averaging about one block each, so the per-node heap allocation dominated the allocator
  - The per-node instruction log was removed: it recorded operand values nothing read, and its only consumer needed opcodes that are available from the SSA
- **Dependencies**: bumped `analyssa` (0.3.0 → 0.4.1) and added `smallvec` (1.15)

Measured end-to-end on the packer samples, deobfuscating the whole assembly: ConfuserEx `maximum` 63.6 s → 2.0 s, and .NET Reactor `necrobit` — which previously failed to reconstruct at all — 385 s → 15.1 s. Part of that comes from analyssa 0.4.1 rather than from dotscope: alongside the evaluator's `checkpoint`/`rollback`, it batches the rebuild-mode substitution in `eliminate_trivial_phis`, which had been applying one whole-function scan per trivial phi. A rebuild produces trivial phis in proportion to the function, so the round was quadratic — on a 1200-block method it was the single largest cost in the pipeline.

## [0.8.3] - 2026-07-16

### Changed

- **Dependencies**: bumped `analyssa` (0.2.0 → 0.3.0), `num-bigint` (0.5.0 → 0.5.1), `tokio` (1.52.3 → 1.52.4), `clap` (4.6.1 → 4.6.2), `anyhow` (1.0.102 → 1.0.103), and `env_logger` in `dotscope-cli` (0.11.10 → 0.11.11, aligning it with the version `dotscope` already used)

This is a patch release: dotscope's own public API is unchanged. `SsaOp` is not re-exported, `conv_op_for_target` is crate-internal, and the analyssa types dotscope *does* re-export (`BinaryOpKind`, `CmpKind`, `UnaryOpKind`, `PhiNode`, `PhiOperand`, `Target`, `PointerSize`, and the loop/symbolic/dataflow types) are all unchanged in analyssa 0.3.0.

Most of analyssa 0.3.0's correctness fixes target native lifters and do not apply to the CIL frontend: the `ld2r`/`setffr`/`dmb` effect corrections concern AArch64/x86 ops dotscope never emits, and the GVN `ComputeFlags`/`CallClobber` fixes concern native flag and call-clobber markers with no CIL equivalent. Likewise the pointer-conversion signedness fix has no observable effect here — dotscope never emits `PtrToInt`, and `CilTarget::convert_const` declines pointer targets, so `IntToPtr` does not constant-fold. What dotscope does inherit is analyssa's structural GVN value key (replacing a per-candidate `Debug`-string key) and the `SsaEditor::nop_instruction` fix that no longer leaves a dead `result_type` on a removed instruction.

## [0.8.2] - 2026-07-02

### Fixed

- **Fat exception-section header size** (#218): `encode_exception_handlers` emitted the fat exception-handling section header as 6 bytes (`Kind` + 2 reserved bytes + `DataSize`) instead of the 4 bytes mandated by ECMA-335 §II.25.4.5 (`Kind` (1 byte) + `DataSize` (3 bytes)). The two extra bytes shifted the `DataSize` field, so a method written back to disk reported a garbage handler count (e.g. `0x1C0000 / 24 = 76458`) and downstream runtimes (Mono/IKVM) crashed resolving a bogus catch-type token. The header is now exactly 4 bytes and survives a write/parse round-trip

### Changed

- **Dependencies**: bumped `num-bigint` (0.4.6 → 0.5.0), `z3` (0.20.1 → 0.20.2), `quick-xml` (0.40.1 → 0.41.0), `memmap2` (0.9.10 → 0.9.11), `rustc-hash` (2.1.2 → 2.1.3), and `env_logger` (0.11.10 → 0.11.11)
- **CI/CD**: fixed z3 link errors in the CI workflow and corrected the docs.rs / release workflow configuration

## [0.8.1] - 2026-06-24

### Fixed

- **Exception handler encoding — fat-format promotion for many clauses**: `encode_exception_handlers` only switched to the fat exception-handling section format based on per-clause offset/length sizes, ignoring the 1-byte `DataSize` field. With more than 20 clauses (4-byte header + 12 bytes/clause > 255) the small-format `DataSize` byte overflowed, producing a corrupt section. The encoder now also forces fat format when `handlers.len()` exceeds the small-format clause limit (ECMA-335 §II.25.4.5/.6)

### Changed

- **Dependencies**: bumped `log` (0.4.31 → 0.4.33) and `z3` (0.20.0 → 0.20.1)

## [0.8.0] - 2026-06-03

### Changed

- **SSA functionality extracted into the standalone [`analyssa`](https://crates.io/crates/analyssa) crate**: the target-agnostic SSA IR, analyses, and optimization/deobfuscation pass framework now live in `analyssa`, with dotscope providing the CIL-specific host (lifting, type system, codegen). dotscope builds on `analyssa` 0.2.0, which adds the native SSA substrate (SIMD/vector ops, native atomics, wide arithmetic, boolean ops), a fluent SSA builder and verifier-checked editor, and ~3–4× smaller core IR types. The CIL pass scheduler is built on `analyssa`'s `PassScheduler::empty` so the deobfuscation pipeline keeps full control over which passes run
- **Structured parse errors** (**breaking**): parse failures are now reported through `Error::Parse(ParseFailure)` with a `ParseStage`, replacing the stringly-typed `Error::Malformed` / `Error::OutOfBounds` / `Error::HeapBoundsError` variants at parse sites. The `malformed_error!` / out-of-bounds helper macros and `#[non_exhaustive] ParseFailure` give callers categorizable, source-located errors. Code that matched the removed variants must migrate to `Error::Parse(..)`
- **Fallible metadata lookups** (**breaking**): metadata lookup APIs such as `CilObject::method()` now return `Result<_, Error>` instead of `Option<_>`, so a missing or unresolvable token reports a typed error rather than a bare `None`. Callers using `if let Some(..)` / `?`-on-`Option` must switch to the `Result` forms
- **Hardening against malformed/adversarial input**: enabled strict crate lints (`unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`, `indexing_slicing` set to `deny`) and reworked the metadata parsers (custom attributes, marshalling, resources, signatures), the validation layer (scanner, schema, raw/owned constraints), and the deobfuscation passes to use fallible, bounds-checked, overflow-safe access. The parser no longer panics on crafted inputs

### Fixed

- **SSA construction — operand corruption**: the placeholder→final variable rename in `SsaConverter` applied cascading by-value replacements, which under `analyssa` 0.2.0's variable-id encoding could collapse a binary operation's operands (e.g. `a - b` becoming `b - b`). The rename is now applied atomically/position-wise, so it is correct regardless of id numbering (handles operand aliasing, swaps, repeated operands, and the reserved placeholder id). This only affected method bodies regenerated from SSA (deobfuscation output)
- **CFF unflattening — expression-obfuscated dispatchers**: state-variable backward tracing (`trace_to_phi`) now follows `neg`/`not`/`conv` wrappers, so ConfuserEx "expression" control-flow flattening (`-(!!state)`-style transforms) no longer hides the dispatcher state phi. `Dispatcher::refresh` reuses the same tracer instead of a shallow, fixed-depth walk
- **CFF unflattening — nested/exception-handler dispatchers**: when a dispatcher's state-setup block is also one of its own switch case targets (common for handler-region CFF), the initial state was not recovered, so the tracer could not seed the state machine and explored every path until hitting its limits — leaving a residual switch and dropping code. The initial state is now recovered from the state phi's constant operand; ConfuserEx control-flow + expression samples fully unflatten again

## [0.7.0] - 2026-05-03

### Added

- **JIEJIE.NET Support**: Full deobfuscation pipeline — control flow flattening, string encryption, constant encoding, resource encryption, typeof obfuscation, array initialization, and infrastructure cleanup. 10/10 test samples pass
- **BitMono Support**: 16 protections covered with PE repair; 18/18 test samples pass. String decryption gated behind the `legacy-crypto` feature (PBKDF2-HMAC-SHA1)
- **.NET Reactor 7.5.0 Support** (partial): basic protections supported; full feature set and virtualization remain in progress
- **Deobfuscation Architecture Overhaul**: moved from obfuscator-focused to technique-based design; added `DelegateProxyResolutionPass`, `OpaqueFieldPredicatePass`, `StaticFieldResolutionPass`, and `SentinelTaintRemovalPass`
- **Emulation Engine Decomposition**: split into `callresolver`, `exhandler`, `typeops`, `dispatch`, `generics`, and `tracefilter` modules; extended BCL runtime with 600+ stubs
- **ILDasm Formatter Library**: full ILAsm-compatible text output in `dotscope::formatting` (~16 submodules) covering structural directives, type system, members, exception handlers, custom attributes, security, generics, resources, COM interop (`.vtfixup`/`.vtentry`/`.export`), and section-aware `.data` directives
- **VtFixup Parsing**: support for mixed-mode assemblies via vtable fixup table parsing
- **AssemblyRef and MemberRef Cleanup**: cleanup pipeline now removes unused `AssemblyRef` and `MemberRef` entries
- **Cascading Output Cleanup**: improved cleanup system for better cascading removal of dead metadata in output binaries
- **Metadata and Type System API Extensions**: `CilFlavor::byte_size`, `FieldQuery`, and the `wellknown` module

### Changed

- **File Backend Migration**: `File` now uses [`cowfile`](https://crates.io/crates/cowfile) (0.2.1) for OS-level copy-on-write memory maps (`MAP_PRIVATE` / `PAGE_WRITECOPY`); PE repairs are applied in place to the mmap with only touched pages copied by the OS
- **Metadata Flags Refactor**: migrated metadata flag types to a type-safe `metadata_flags!` macro
- **SSA Rebuild Refactor**: reworked `SsaRebuild`-related logic to improve SSA construction reliability and stability
- **CI/CD**: removed macOS Intel from the CI/CD pipeline
- **Dependencies**: replaced the `rsa` crate temporarily due to a published CVE; bumped other dependencies

### Fixed

- **Codegen — Address-Taken Locals**: codegen no longer erases required address-taken locals
- **CFF Unflattening**: missing `BranchCmp` cases caused traces to abort early; now handled
- **CFF Unflattening**: regressions from earlier refactoring resolved
- **Inlining Race**: parallel pass execution could miss inlining candidates due to a race; fixed
- **CALLI in SSA Construction**: now uses metadata for correct stack handling
- **CALLI in `SsaConverter`**: previously missing handling added
- **Exception Handler Hardening**: improved validation/handling of malformed handlers
- **Exception Handler Encoding**: corrected size encoding for exception handlers
- **Exception Handler Codegen**: fixed handler generation in codegen
- **String Heap Compaction**: substrings within removed strings no longer cause incorrect compaction
- **DeobfuscationConfig**: `detection_threshold` was not being applied properly
- **Lenient Mode**: lenient flag is now properly propagated for force analysis
- **x86 Decoder**: added support for `call $+5` trampolines
- **PureLogs Reliability**: multiple analysis fixes
- **.NET 10 Compatibility**: improvements for .NET 10 assemblies
- **Feature Gating**: resolved unused warnings for feature-gated APIs

## [0.6.0] - 2026-02-12

### Added

- **Analysis Module**: Control flow graph (CFG), SSA form, dataflow analysis (SCCP, liveness, reaching definitions), callgraph construction, def-use chains, range analysis, taint analysis, algebraic simplification, x86 native analysis, and symbolic execution
- **Emulation Engine**: Full CIL interpreter supporting 200+ opcodes, copy-on-write memory model with fork support, 200+ BCL method stubs, exception handling, thread model, and process builder
- **Deobfuscation Pipeline**: 20 optimization passes, SSA-to-CIL code generation, detection framework, state machine analysis, and ConfuserEx obfuscator support
- **ConfuserEx Support**: Anti-tamper, anti-debug, anti-dump, constants (normal, dynamic, CFG, x86 cipher modes), control flow (normal, expression, x86 predicates), reference proxy (mild + strong), marker cleanup, invalid metadata repair, resource decryption — covers all standard preset protections (Minimum through Maximum)
- **Obfuscar Support**: Detection (scoring-based identification via helper type structure, XOR decryption loop, null parameter names), string decryption (emulation-based via `DecryptionPass` pipeline), SuppressIldasmAttribute removal, infrastructure cleanup (helper types, nested types, fields, accessor methods) — 6/6 test samples pass covering default, strings-only, rename-only, unicode, and maximum configurations
- **Writing Pipeline**: Streaming PE generation, heap compaction, token remapping, IL patching, resource section generation, import/export tables
- **Codegen Pipeline**: Complete SSA destruction, register allocation, phi elimination, instruction selection, exception handler remapping, local variable signature generation
- **TypeQuery and MethodQuery System**: Structured query system for type and method resolution
- **Workspace and CLI Tool**: Migration to Cargo workspace with first prototype of the `dotscope-cli`

## [0.5.1] - 2025-11-28

### Fixed

- **Package Size**: Excluded legacy Mono test directories (mono_2.0, mono_3.5, mono_4.0, mono_4.5) from crate package to reduce size from ~160MB to ~6MB compressed, staying within crates.io limits
- **Documentation Examples**: Updated all doc examples to use mono_4.8 test samples for consistency
- **Blob Heap Modification Remapping**: Fixed table index remapping when modifying existing blobs that grow larger than their original size. Previously, blob modifications that didn't fit in place were appended to the heap but table references weren't updated, causing validation failures

## [0.5.0] - 2025-11-27

### Added

- **Multi-Assembly Project System**: New `ProjectLoader` for loading and analyzing multiple assemblies with automatic dependency resolution
- **Assembly Dependency Analysis**: Comprehensive dependency graph analysis with cycle detection and topological sorting
- **Assembly Identity System**: Cryptographic identity tracking with strong name and public key support
- **Zero-Copy Resource Parsing**: New `ResourceTypeRef<'a>` and `ResourceEntryRef<'a>` types for memory-efficient resource access
- **Additional Resource Types**: Support for `Stream`, `Decimal`, `DateTime`, and `TimeSpan` resource types
- **Nested Class Cycle Detection**: Validation system now detects circular nesting relationships in metadata
- **Parser Enhancements**: Transactional parsing with `transactional()` and non-advancing `peek_*` methods
- **Performance Benchmarks**: Extended benchmark suite covering COR20 header, method bodies, signatures, streams, and security parsing

### Changed

- **Error System Redesign**: Comprehensive refactoring of error types for clarity and consistency
  - `Error::Error` → `Error::Other`
  - `FileError` → `Io`
  - `GoblinErr` → `Goblin`
  - `BranchTarget*` errors consolidated into `BranchTargetOutOfRange`
  - Validation errors renamed for consistency (e.g., `InvalidFieldType` → `FieldTypeInvalid`)
  - Unused error variants removed
- **MethodAccessFlags**: Changed from bitflags to a pseudo-enum to correctly represent mutually exclusive access modifiers per ECMA-335
- **Inheritance Validator**: Optimized algorithm for significantly faster validation on large assemblies

### Fixed

- **Resource Encoder Bug**: Fixed string length encoding using incorrect format (ECMA-335 compressed uint instead of .NET BinaryWriter 7-bit encoded int)
- **ECMA-335 Compliance**: Added handling for I.8.5.3.2 narrowing accessibility restriction exception
- **OOM Prevention**: Added checks to prevent out-of-memory crashes from corrupted or invalid counts in malformed assemblies
- **CI/CD Improvements**: Fixed cross-platform test compilation for Windows, macOS, and Linux with proper architecture detection

### Improved

- **Documentation**: Extensive documentation improvements across all modules with better examples and ECMA-335 references
- **ECMA-335 Correctness**: Multiple fixes to improve spec compliance throughout the codebase
- **Test Infrastructure**: Enhanced test support for different runtimes (CoreCLR, Mono) and platforms
- **Performance**: Various optimizations for parsing and validation operations

## [0.4.0] - 2025-08-19

### Added

- **Assembly Encoder and Builder System**: Complete CIL assembly encoder and builder implementation with high-performance benchmarks
- **High-Level Builders**: Added builders for classes, enums, events, interfaces, properties, and methods with full CIL method body support
- **Binary Modification Capabilities**: Full binary modification support with method injection and exception handler support using label-based targeting
- **PortablePDB Support**: Complete PortablePDB parsing implementation for enhanced debugging information
- **EnC (Edit and Continue) Tables**: Support for Edit and Continue metadata tables
- **Validation System**: Comprehensive validation framework to ensure modified binaries remain valid and loadable
- **Binary Serialization**: Capability to write modified assemblies back to disk

### Changed

- **Module Organization**: Renamed `disassembler` module to `assembly` in preparation for encoder implementation
- **File Structure**: Removed `self_reflecting` from File structure, storing PE information locally for improved performance

### Fixed

- Fixed regression in size field length calculation
- Fixed multiple issues causing modified binaries to be invalid
- Fixed clippy warnings for latest Rust versions
- Various binary modification stability improvements

### Improved

- Enhanced integration testing with Mono runtime verification
- Improved PE file handling and structure
- Better separation between parsing and encoding functionality
- Updated examples and documentation

## [0.3.2] - 2025-06-17

### Fixed

- Wrong release sequence for 3.1, this corrects the changes necessary

## [0.3.1] - 2025-06-17

### Improved

- Enhanced overall documentation across the codebase with better examples and clearer explanations

## [0.3.0] - 2025-06-14

### Added

- Implemented missing pointer tables (FieldPtr, MethodPtr, ParamPtr, EventPtr, PropertyPtr)
- New builder system and test scenarios for complex .NET features
- Support for parsing XML-based security permission sets

### Changed

- Reorganized metadata table structure for better maintainability
- Better separation of raw tables, loaders, and owned types

### Improved

- Extended marshaling support for native interop scenarios
- Improved validation of various entries while loading the binary
- Performance optimizations
- Improved type resolution and generic parameter handling
- Expanded test coverage with crafted test cases

## [0.2.1] - 2025-06-11

### Fixed

- **Type System Issues**: Resolved critical issues with type flavor classification and inheritance resolution
- **Method-to-Type Associations**: Fixed method discovery and association with declaring types  
- **Interface Relationships**: Improved interface inheritance chain resolution
- **Type Flavor Determination**: Added proper logic to classify value types, interfaces, and classes correctly
- **Parser Stability**: Enhanced robustness and error handling in metadata parsing

### Added

- **Enhanced Test Coverage**: Expanded test coverage analysis and validation for complex .NET features

### Improved

- **Type System Validation**: More accurate type classification and inheritance analysis
- **Test Infrastructure**: Enhanced validation and coverage analysis

## [0.2.0] - 2025-06-10

### Added

- **Custom Attribute System**: Complete implementation with constructor/property resolution and support for complex parameter types
- **Enhanced Generic Type System**: Improved MethodSpec handling, corrected generic parameter resolution (`T -> System.Int32`), improved type builder and resolver
- **Method Analysis Framework**: Improved IL disassembly + API

### Fixed

- **Type Safety**: Replaced unsafe casting with proper bounds checking and overflow detection
- **Memory Management**: Improved method-to-type associations and type flavor classification
- **Dependencies**: Updated all dependencies to address security advisories #4, #5, #6

### Changed

- **Breaking**: MethodSpec architecture - `CilType.generic_args` now contains MethodSpec instances instead of direct CilTypeRc
- **Performance**: Replaced RwLock with `boxcar::Vec` for better lock-free concurrency
- **Security**: Enhanced input validation and overflow protection for malformed assemblies

## [0.1.0] - 2025-06-08

### Added

#### Initial Release

dotscope is a Rust library for parsing and analyzing .NET assemblies (PE files with CLI metadata).

#### Core Features

- **PE File Parsing**: Read .NET assemblies from files or memory buffers
- **Metadata Analysis**: Parse ECMA-335 metadata tables, strings, and blob heaps
- **CIL Disassembly**: Decode IL bytecode into readable instructions with basic block analysis
- **Type System**: Access type definitions, method signatures, and field information
- **Resource Extraction**: Read embedded resources and manifest data

#### API Highlights

- `CilObject::from_file()` and `CilObject::from_buffer()` for loading assemblies
- Access to metadata tables (TypeDef, MethodDef, Field, etc.)
- CIL instruction decoding with control flow analysis
- Type resolution and signature parsing
- Comprehensive error handling with detailed context

#### Quality & Testing

- 90%+ test coverage with 400+ unit tests
- Fuzzing infrastructure for robustness testing
- Integration tests with real .NET assemblies
- Memory-safe parsing with bounds checking

#### Known Limitations

- Custom attribute parsing is not fully implemented
- Some advanced signature types need refinement
- Resource limits for DoS protection not yet implemented
