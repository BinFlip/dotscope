//! Symbolic execution and constraint solving using Z3.
//!
//! This module provides symbolic execution capabilities for SSA analysis,
//! powered by the Z3 SMT solver. It enables:
//!
//! - Building symbolic expressions from SSA operations
//! - Solving constraints to find values that satisfy conditions
//! - Enumerating all solutions within a range
//! - Control flow unflattening by inverting state encodings
//!
//! # Architecture
//!
//! The module uses [`SymbolicExpr`] as an intermediate representation that
//! maps directly to SSA operations. When solving is needed, expressions are
//! translated to Z3's AST and solved using Z3's powerful SMT solver.
//!
//! ```text
//! SSA Operations → SymbolicExpr (our IR) → Z3 AST → Z3 Solver → Solutions
//! ```
//!
//! # Module Structure
//!
//! - [`ops`] - Symbolic operation types ([`SymbolicOp`]: add, xor, comparison, etc.)
//! - [`expr`] - Symbolic expression tree representation ([`SymbolicExpr`])
//! - [`solver`] - Z3-based constraint solver ([`Z3Solver`])
//! - [`evaluator`] - Builds expressions from SSA operations ([`SymbolicEvaluator`])
//!
//! # Use Cases
//!
//! ## Control Flow Unflattening
//!
//! The primary use case is inverting state encodings used by control flow
//! flattening obfuscators like ConfuserEx. These obfuscators use a pattern:
//!
//! ```text
//! switch_idx = f(state)  // e.g., (state XOR C1) % N
//! switch (switch_idx) {
//!     case 0: ...; state = g0(state); break;
//!     case 1: ...; state = g1(state); break;
//!     ...
//! }
//! ```
//!
//! Given `f(state)` as a symbolic expression and a target case index, we use
//! Z3 to solve for all state values that reach that case:
//!
//! ```text
//! solve: f(state) == target_case
//! ```
//!
//! ## Constraint Satisfaction
//!
//! More generally, the module can solve arbitrary constraints involving
//! bitvector arithmetic (32-bit):
//!
//! - Arithmetic: add, sub, mul, div, rem
//! - Bitwise: and, or, xor, not, shl, shr
//! - Comparisons: eq, ne, lt, gt, le, ge (signed and unsigned)
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{SymbolicExpr, SymbolicOp, Z3Solver};
//!
//! // Build expression: (state XOR 0x12345678) % 13
//! let state = SymbolicExpr::named("state");
//! let xored = SymbolicExpr::binary(SymbolicOp::Xor, state, SymbolicExpr::constant(0x12345678));
//! let result = SymbolicExpr::binary(SymbolicOp::RemU, xored, SymbolicExpr::constant(13));
//!
//! // Use Z3 to find all states that produce case index 5
//! let solver = Z3Solver::new();
//! let solutions = solver.solve_for_value(&result, "state", 5, 100);
//!
//! // Build mapping: case_index -> [state values that reach it]
//! let mapping = solver.build_case_mapping(&result, "state", 13, 10);
//! ```
//!
//! # Performance Considerations
//!
//! Z3 context creation has some overhead. For repeated solving, create a single
//! [`Z3Solver`] and reuse it. The solver uses 32-bit bitvectors (`BV(32)`) for
//! all computations, matching CIL's `int32` semantics.

mod evaluator;
mod expr;
mod ops;

// The solver module requires z3 which is gated behind the deobfuscation feature
#[cfg(feature = "deobfuscation")]
mod solver;

// Re-export public types - SymbolicExpr, SymbolicOp, SymbolicEvaluator are always available
pub use evaluator::SymbolicEvaluator;
pub use expr::SymbolicExpr;
pub use ops::SymbolicOp;

// Z3Solver is only available with the deobfuscation feature
#[cfg(feature = "deobfuscation")]
pub use solver::Z3Solver;
