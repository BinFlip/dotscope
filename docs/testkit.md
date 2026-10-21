# dotscope testkit

The test support shared by dotscope's unit tests and integration tests lives in the crate itself,
as `dotscope::testkit` (`dotscope/src/testkit/`).

## Why in the crate, not a separate crate

A separate `dotscope-testkit` crate would depend on `dotscope`, and dotscope's own unit tests
would then need it as a dev-dependency. That makes a cycle Cargo resolves by linking a second
`dotscope` instance into the unit-test binary: the testkit's `dotscope::CilObject` and the unit
tests' `crate::CilObject` are different types, so nothing built by the testkit can be handed to
the code under test. The integration tests would work; the unit tests, the larger half, would not.

## How it is reached

```rust
// dotscope/src/lib.rs
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit;
```

```toml
# dotscope/Cargo.toml
[features]
testkit = []

[dev-dependencies]
dotscope = { path = ".", features = ["testkit"] }
```

- **Unit tests** (`cargo test --lib`) compile the crate with `cfg(test)`, so `crate::testkit`
  exists and is the same crate.
- **Integration tests** (`tests/*.rs`) link the library as an ordinary dependency. The crate's
  dev-dependency on itself turns the `testkit` feature on, and Cargo unifies that dependency
  with the crate under test: `dotscope::testkit` and the tested types are one crate instance.

Compiled through the feature, the testkit is library code, not test code: it uses only the
crate's normal dependencies (`tempfile`, `rayon`, ...), never its dev-dependencies. The module
allows the panicking and indexing lints the library denies: test support panics on what it cannot
set up. It is `#[doc(hidden)]`, unstable, and outside the semver surface.

## Contents

| Module | What it holds |
|---|---|
| `fixtures` | `fixture(rel)`, `fixture_bytes(rel)` and `samples_dir()`: the committed fixtures under `tests/samples` |
| `builders` | Fluent builders for metadata objects: types, methods, fields, references |
| `factories` | Assemblies and rows crafted for validator and table tests |
| `helpers` | Sample loading (`load_sample`, `load_test_assembly`) and small utilities |
| `framework` | The obfuscator sample harness: deobfuscate, verify, summarize; `engine()`, `engine_with(config)`, and `deobfuscated(sample)`, each sample's run shared by every test (feature `deobfuscation`) |
| `verification` | SSA-based semantic comparison of original and deobfuscated assemblies |
| `compatibility` | Loading and comparing whole runtime corpora (Mono, .NET) |
| `analysis`, `mono` | Analysis and runtime harnesses |
| `tools` | `require_tool` and `run_with_timeout`: which external tools a test may go without, and running them |
| `emulation` | Emulator test setup: `emulation_config()`, `emulation_limits()`, `process_builder()` (feature `emulation`) |
| crate root | `TestTypeProvider`, and `build_cfg` / `build_ssa` / `build_ssa_with_handlers` for SSA from assembled CIL |

There is one copy of each: `tests/common/` is gone, and so is the never-declared
`src/test/verification.rs` the integration tests had drifted away from.

## Fixtures

A fixture is named by its path relative to `tests/samples`: `fixture("crafted_2.exe")`,
`fixture(&format!("packers/bitmono/{version}/original.exe"))`. `fixture` resolves it through
`CARGO_MANIFEST_DIR`, so a test passes from any working directory, and panics when the file is
missing: a committed fixture is never skipped, and deleting one fails every test that uses it.
`fixture_bytes` reads one once per test binary; `load_sample(rel)` loads one as a `CilObject`.

`tests/samples/MANIFEST.toml` lists every file under `tests/samples` with its `sha256`,
`source`, `license` and `suites`, and `testkit::fixtures`' unit test fails on an unlisted file, a
listed file that is gone, or a changed hash. "Every file" is what git would commit (`git
ls-files --cached --others --exclude-standard`): files the repository ignores, like a
`.DS_Store`, are not fixtures. After adding, changing or removing fixtures,
refresh it with

```sh
DOTSCOPE_WRITE_MANIFEST=1 cargo test --profile ci-test -p dotscope --lib -- testkit::fixtures
```

The refresh updates paths and hashes and keeps what is edited by hand: `source` and `license`
(a new file takes them from where it lives), `suites`, the tags that select a fixture for a
tier or a sweep, and `reject`.

`reject` marks a fixture that is malformed by design, one that ECMA-335 or the CLR refuses, and
names the error loading it must fail with, as dotscope states it without the `(file.rs:line)`
locations an error carries. It is never written by a refresh: it says what the file is, and the
corpus sweep holds the file to exactly that error. A file that must load has no `reject`.

## Corpus sweep

`testkit::corpus` runs checks over every `.dll` and `.exe` the manifest lists. Each assembly is
loaded once, as `CilObject::from_mem` loads it by default, and handed to every check in turn on
one thread; assemblies run on up to eight threads at once. A check states a property and
reports, a line per finding, what one assembly gets wrong; a check that panics reports the
panic. The sweep passes when nothing is reported: there is no list of failures to expect.

`full::corpus` runs two checks: `Loads` (every assembly loads, and a `reject` fixture fails
with exactly the error it names) and `Lifts` (every method with a body lifts to SSA that
`SsaVerifier` accepts at the standard level). `DOTSCOPE_CORPUS_FILTER=part,part` narrows a
sweep to the fixtures whose path contains one of the parts.

## Validator tests

A validator's test runs `validator_test` (raw) or `owned_validator_test` (owned) over a factory
of `TestAssembly` cases: the clean assembly the validator accepts, and crafted ones that each
break one rule. A crafted case states what must happen to it:

```rust
create_test_assembly(get_testfile_mscorlib, Expect::fail("must also be virtual"), |assembly| {
    // build a method that is abstract but not virtual
    Ok(())
})
```

- `Expect::Pass`: the validator accepts it.
- `Expect::fail(text)`: the validator rejects it with a message containing `text`, which
  names the broken rule. An `ExpectedError` is never blank: matching any error let cases pass
  on failures that had nothing to do with their rule.
- `Expect::refused(text)`: the loader refuses it before any validator runs, with a message
  containing `text`: the rule is enforced at load. Such a case moves to `Expect::fail` when a
  lenient load lets it through.

The harness sets every case up first (load the bytes, scan references, load the project for an
owned validator). A case it cannot set up fails the test whichever way it was expected to go,
because the validator never ran. Every case runs, and the failure lists every mismatch by the
factory line that made the case (`TestAssembly` records it through `#[track_caller]`). The
validators share one thread pool.

A crafted case breaks one rule and keeps the rest of the metadata valid: list columns start
at the next row (the table builders' default), signatures are complete, mscorlib types extend
`System.Object` (`MSCORLIB_OBJECT_TYPEDEF`), and a method that needs a body points at a real
one (`MSCORLIB_OBJECT_CTOR_RVA`).

## SSA from assembled CIL

Converter and pass tests assemble CIL with `InstructionAssembler`, which has no metadata
behind it: no signature types the arguments, and no local signature types the locals. The test
states each slot's type with a `TestTypeProvider`:

```rust
let (_, cfg) = build_cfg(asm)?;
// two int32 slots of each kind
let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 2))?;
// an instance method: `this` is an object
let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 4).arg(0, SsaType::Object))?;
// slot by slot
let types = TestTypeProvider::typed([SsaType::I64], [SsaType::F64, SsaType::I32]);
```

The provider declares how many arguments and locals the body has, so `build_ssa` and
`build_ssa_with_handlers` take only it. `arg(idx, ty)` and `local(idx, ty)` change a declared
slot and panic on one that is not declared; a slot past the declared ones is typed `Unknown`.
`without_locals_init()` declares a body without `.locals init`. Calls, indirect calls and fields
are typed `I32` and `newobj` results `Object`: a test that needs other types for them builds a
real assembly. There is no all-`I32` default: a test that keeps an `int64` or a float in a slot
declares it, so the converter sees the types the method's signatures would give it.

## Results independent of machine load

How busy the machine is must never decide whether a test passes. A test orders threads with
channels, joins or barriers, never with sleeps, and asserts on outcomes, never on elapsed time.

Emulation has wall-clock limits in the library's defaults (a deobfuscation run's per-method
`timeout` and `warmup_timeout`, `EmulationLimits::timeout_ms`): under load an emulation stops
earlier and a string it would have decrypted stays encrypted. Tests switch them off and rely
on the deterministic limits (instructions, call depth, memory):

- a deobfuscation engine comes from `engine()` or `engine_with(config)`, which apply
  `without_wall_clock`; the sample harness does the same for every sample;
- an emulation comes from `process_builder()`, `emulation_config()` or `emulation_limits()`
  in `testkit::emulation`.

The timeouts on external tools (`run_with_timeout`) are the exception: they stop a hung
`dotnet build` or `mono`, and are sized to pass in CI and locally.

## Test tiers

The tiers are cargo aliases in `.cargo/config.toml`, run by name from the Makefile, GitHub CI
and GitLab, all in the `ci-test` profile with the z3 feature:

| Tier | Command | What runs |
|---|---|---|
| quick | `cargo test-quick`, `make test-quick` | unit tests and the integration tests outside a `full` module |
| full | `cargo test-full`, `make test-full` | every test: also the `full` modules (the corpus sweep among them) and `fuzzer` |
| oracle | `make test-oracle` | full with `DOTSCOPE_REQUIRE_TOOLS=1` |

The integration tests are one binary, `tests/it/main.rs`, with a module per suite. A test
belongs to the full tier when it sits inside a module named `full`: a whole suite under `mod
full` in `main.rs` (the packer suites, the Mono corpus, the corpus sweep, the codegen validation sweep), or a
single slow test in a `mod full` of its own file (the .NET 10 corpus in `dotnet10.rs`). The
quick tier skips them by name (`--skip full::`), so they are not run, not reported as
passed. Linux CI runs the oracle tier; macOS and Windows run the quick tier, which shows the
platform works, while Linux carries the full coverage.

## Packer samples

Each packer suite describes its samples once (`all_samples()`, a `SampleSpec` per file with
the protections it carries) and has one test per sample, generated by `sample_tests!` in
`tests/it/main.rs`:

```rust
sample_tests! {
    all_samples(), check_sample;
    original => "original.exe",
    default => "obfuscar_default.exe",
}
```

`check_sample(filename)` runs the sample through `run_deobfuscation_test` and asserts what its
description promises. A failure names its sample (`full::obfuscar::default`), the samples run
in parallel, and the macro's `every_sample_has_a_test` fails when the list and `all_samples()`
disagree, so a sample added to one and not the other is never silently left out.

Deobfuscating a sample is the expensive part, and several tests check the same one: the sample
test, and the tests of one property (resource order, call targets, the trial check). They all
read `testkit::deobfuscated(path)`, the sample run once per test binary through `process_file`
with the default engine; a test asking while the run is in progress waits for it. A test with
another configuration builds its own engine with `engine_with(config)`.

## External tools

Some tests compile C#, run it on Mono or .NET, disassemble it, or verify it with `peverify`.
Such a test asks for what it needs first:

```rust
let Some(caps) = require_tool(ToolKind::Toolchain) else {
    return Ok(());
};
```

`require_tool` returns the machine's capabilities (detected once per test binary) when it has
the tool. When it has not, the test skips, unless `DOTSCOPE_REQUIRE_TOOLS=1` is set: then the
test fails, naming what is missing. The Linux CI, coverage and release jobs install the .NET
SDK and Mono and set it, so no tool-dependent test passes there without running.
`TestRunner::new()` and `AnalysisTestRunner::new()` follow the same rule and return
`Result<Option<_>>`. A check that is one of several, like the disassembly step of
`run_complete_test` or the `peverify` comparison of the codegen roundtrip, is left out the same
way and reported as not run (`None`), never as passed.

The kinds are `Toolchain` (a C# compiler and a runtime that runs what it builds),
`Disassembler`, `Verifier` (`peverify`) and `Mono`, which the packer samples need: they are
.NET Framework executables, which `dotnet` does not run.

`full::runtime` deobfuscates every sample of each packer family and runs its output and the
family's unprotected original under Mono (`tests/it/full/runtime.rs`). Each family is held to
the harness's preconditions: the original runs, and every sample is deobfuscated, written and
run, or refused as not supported.

Every tool runs through `run_with_timeout(command, timeout)`: stdout and stderr are drained on
their own threads while it runs, so a chatty tool cannot block on a full pipe, and one that
overstays is killed and reaped.

## Conventions

- Unit tests import `crate::testkit::...`; integration tests import `dotscope::testkit::...` in
  the same `use dotscope::{ ... }` block as the rest of the crate.
- Test support is added here, never copied into a test file.
- A test reaches a sample through `fixture`, never a `"tests/samples/..."` path, and never
  skips when one is missing.
- A test builds deobfuscation engines and emulations through the testkit, so none of them
  has a wall-clock limit.
- Every documentation example is real code. One that uses only public API is a doc test,
  `no_run` when it needs a file; one that needs crate-private API is a test in a
  `#[cfg(test)] mod examples` beside the item, which its documentation names.
  `docs::no_doc_example_is_ignored` fails on any `ignore` fence.
