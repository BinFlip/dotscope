#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Every assembly the fixture manifest lists loads as its entry says, and every method with a
//! body lifts to SSA the verifier accepts.
//!
//! The lift is the input to everything else: the passes, the interprocedural solve, the code
//! generator. IR that does not verify is not rejected anywhere downstream: a pass group that
//! touches such a method fails its boundary check, is rolled back, and reports that it changed
//! nothing. So the check belongs here, at the source, over the whole corpus rather than a
//! chosen method: the defects it catches are in the shapes a real compiler emits and a
//! hand-written fixture does not (deep protected regions, filters, `switch` dispatch, methods
//! with a thousand blocks, function pointers, `ref` returns).

use dotscope::testkit::corpus::{sweep, Lifts, Loads};

#[test]
fn every_corpus_assembly_loads_and_lifts() {
    sweep(&[&Loads, &Lifts]).assert_clean();
}
