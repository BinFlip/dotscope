//! Import scope parsing for Portable PDB format.
//!
//! This module provides comprehensive parsing capabilities for import declarations
//! used in Portable PDB files. Import scopes define the set of namespaces, types,
//! and assemblies that are accessible within a lexical scope for debugging purposes.
//!
//! # Import Declarations
//!
//! Import declarations are encoded in a binary format within the ImportScope table's
//! imports blob. This module provides structured parsing of these declarations into
//! type-safe Rust representations.
//!
//! # Key Components
//!
//! - **Types**: Import declaration types and enums ([`ImportKind`], [`ImportDeclaration`], [`ImportsInfo`])
//! - **Parser**: Binary blob parsing functionality ([`parse_imports_blob`])
//! - **Integration**: Seamless integration with the broader metadata system
//!
//! # Examples
//!
//! ## Basic Import Parsing
//!
//! ```rust,ignore
//! use dotscope::metadata::importscope::{parse_imports_blob, ImportDeclaration};
//!
//! // Parse imports blob from ImportScope table
//! let imports = parse_imports_blob(blob_data, blobs_heap)?;
//!
//! // Process import declarations
//! for declaration in &imports.declarations {
//!     match declaration {
//!         ImportDeclaration::ImportNamespace { namespace } => {
//!             println!("Import namespace: {}", namespace);
//!         }
//!         ImportDeclaration::ImportType { type_ref } => {
//!             println!("Import type: {:?}", type_ref);
//!         }
//!         _ => println!("Other import type"),
//!     }
//! }
//! ```
//!
//! # Format Specification
//!
//! Based on the Portable PDB format specification:
//! - [Portable PDB Format - ImportScope Table](https://github.com/dotnet/designs/blob/main/accepted/2020/diagnostics/portable-pdb.md)
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe and can be used
//! concurrently across multiple threads.

mod parser;
mod types;

pub use parser::parse_imports_blob;
pub use types::{ImportDeclaration, ImportKind, ImportsInfo};
