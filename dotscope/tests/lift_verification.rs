#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Every method this crate lifts is well-formed SSA.
//!
//! The lift is the input to everything else: the passes, the interprocedural
//! solve, the code generator. IR that does not verify is not rejected anywhere
//! downstream - a pass group that touches such a method fails its boundary
//! check, is rolled back, and reports that it changed nothing. The method is
//! then simply never improved, and the only trace is a rollback nobody counts.
//!
//! So the check belongs here, at the source, over the whole sample corpus
//! rather than a chosen method: the defects this catches are in the shapes a
//! real compiler emits and a hand-written fixture does not - deep protected
//! regions, filters, `switch` dispatch, methods with a thousand blocks.
//!
//! # Reading a failure
//!
//! The breakdown is by error kind, because the kinds are the diagnosis. A
//! `StaleUseList` is a construction that forgot to recompute an index; an
//! `OrphanVariable` is a value registered and never defined; a
//! `PhiWithoutPredecessors` at a handler entry is the exception model; an
//! `UndefinedUse` is a read of something no path produces. Each has a different
//! repair, and counting them apart is what says which one to make.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use dotscope::{
    analysis::{SsaVerifier, VerifyLevel},
    CilObject,
};

/// Every `.dll` and `.exe` under `root`, recursively, sorted.
fn sample_assemblies(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|ext| ext == "dll" || ext == "exe")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// What a sweep of the corpus found.
#[derive(Default)]
struct Findings {
    /// Assemblies that loaded.
    assemblies: usize,
    /// Methods whose lift produced SSA.
    methods: usize,
    /// Methods whose lift returned an error, which is not a verifier finding.
    lift_errors: usize,
    /// Methods with at least one finding.
    failing_methods: usize,
    /// Findings by error kind.
    by_kind: BTreeMap<String, usize>,
    /// The first few failures, as `assembly::method: finding`.
    examples: Vec<String>,
}

impl Findings {
    /// The kind name of one finding, without its fields.
    fn kind_of(error: &str) -> String {
        error.split([' ', '{']).next().unwrap_or(error).to_string()
    }

    /// Records one method's findings.
    fn record(&mut self, assembly: &str, method: &str, errors: &[String]) {
        self.methods += 1;
        if errors.is_empty() {
            return;
        }
        self.failing_methods += 1;
        for error in errors {
            *self.by_kind.entry(Self::kind_of(error)).or_default() += 1;
            if self.examples.len() < 20 {
                self.examples.push(format!("{assembly}::{method}: {error}"));
            }
        }
    }

    /// The breakdown, as a report.
    fn report(&self) -> String {
        let mut out = format!(
            "{} assemblies, {} methods lifted, {} lift errors, {} methods with findings\n",
            self.assemblies, self.methods, self.lift_errors, self.failing_methods
        );
        let mut kinds: Vec<(&String, &usize)> = self.by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in kinds {
            out.push_str(&format!("  {count:>8}  {kind}\n"));
        }
        for example in &self.examples {
            out.push_str(&format!("  e.g. {example}\n"));
        }
        out
    }
}

/// Lifts every method of every sample and verifies the result.
///
/// Ignored by default is not an option here - a check that does not run is not
/// a check - but the corpus is 229 MB and the sweep is minutes, so it runs in
/// release like the rest of this crate's suite.
#[test]
fn every_lifted_method_is_well_formed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    let assemblies = sample_assemblies(&root);
    assert!(
        !assemblies.is_empty(),
        "no samples under {}",
        root.display()
    );

    let mut findings = Findings::default();
    for path in &assemblies {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        // An assembly this crate cannot load is a different test's business;
        // the corpus deliberately includes malformed inputs.
        let Ok(assembly) = CilObject::from_mem(data) else {
            continue;
        };
        findings.assemblies += 1;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        for entry in assembly.methods().iter() {
            let method = entry.value();
            let ssa = match method.ssa(&assembly) {
                Ok(ssa) => ssa,
                Err(_) => {
                    findings.lift_errors += 1;
                    continue;
                }
            };
            let errors: Vec<String> = SsaVerifier::new(&ssa)
                .verify(VerifyLevel::Standard)
                .iter()
                .map(|error| format!("{error:?}"))
                .collect();
            findings.record(&name, &method.name, &errors);
        }
    }

    assert_eq!(
        findings.failing_methods,
        0,
        "the lift produced IR the verifier rejects:\n{}",
        findings.report()
    );
}
