//! Inter-procedural call graph construction and analysis.
//!
//! This module provides call graph construction for .NET assemblies, enabling
//! inter-procedural analysis by building a graph of call relationships between
//! methods.
//!
//! # Architecture
//!
//! The call graph is built by scanning method bodies for call instructions and
//! resolving their targets. For virtual calls, Class Hierarchy Analysis (CHA)
//! is used to determine possible runtime targets.
//!
//! The implementation uses generic graph infrastructure, providing access
//! to standard graph algorithms like SCC computation, topological sorting,
//! and traversal.
//!
//! # Components
//!
//! - [`CallGraph`]: The main call graph structure with forward and reverse edges
//! - [`CallGraphNode`]: Information about a method in the call graph
//! - [`CallSite`]: A specific call instruction within a method
//! - [`CallTarget`]: The resolved target(s) of a call
//! - [`CallResolver`]: Virtual call resolution using Class Hierarchy Analysis
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::CallGraph;
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("assembly.dll")?;
//! let call_graph = CallGraph::build(&assembly)?;
//!
//! // Find all methods called by a specific method
//! for callee in call_graph.callees(method_token) {
//!     println!("Calls: {:?}", callee);
//! }
//!
//! // Find all callers of a method
//! for caller in call_graph.callers(method_token) {
//!     println!("Called by: {:?}", caller);
//! }
//!
//! // Iterate in topological order (bottom-up)
//! for method in call_graph.topological_order() {
//!     // Process callees before callers
//! }
//!
//! // Check for recursion
//! if call_graph.has_recursion() {
//!     for method in call_graph.recursive_methods() {
//!         println!("Recursive method: {:?}", method);
//!     }
//! }
//! ```

mod graph;
mod node;
mod resolution;
mod site;

pub use graph::{CallGraph, CallGraphStats};
pub use node::CallGraphNode;
pub use resolution::{CallResolver, ResolverStats};
pub use site::{CallSite, CallTarget, CallType};
