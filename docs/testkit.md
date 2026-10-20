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
| `framework` | The obfuscator sample harness: deobfuscate, verify, summarize (feature `deobfuscation`) |
| `verification` | SSA-based semantic comparison of original and deobfuscated assemblies |
| `compatibility` | Loading and comparing whole runtime corpora (Mono, .NET) |
| `analysis`, `mono` | Analysis and runtime harnesses |
| `tools` | `require_tool` and `run_with_timeout`: which external tools a test may go without, and running them |
| `emulation` | Emulator test setup (feature `emulation`) |
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
(a new file takes them from where it lives), and `suites`, the tags that select a fixture for a
tier or a sweep.

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

Every tool runs through `run_with_timeout(command, timeout)`: stdout and stderr are drained on
their own threads while it runs, so a chatty tool cannot block on a full pipe, and one that
overstays is killed and reaped.

## Conventions

- Unit tests import `crate::testkit::...`; integration tests import `dotscope::testkit::...` in
  the same `use dotscope::{ ... }` block as the rest of the crate.
- Test support is added here, never copied into a test file.
- A test reaches a sample through `fixture`, never a `"tests/samples/..."` path, and never
  skips when one is missing.
