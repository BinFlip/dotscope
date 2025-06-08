//! .NET Code Access Security (CAS) implementation.
//!
//! This module provides support for parsing and representing .NET Code Access Security
//! permissions and permission sets. Note that CAS has been largely deprecated in modern
//! .NET versions but remains important for analyzing legacy assemblies.
//!
//! # Overview
//!
//! The .NET Code Access Security model allowed fine-grained control over what operations
//! code could perform based on evidence about the code's origin. This included:
//!
//! - **Permission Sets** - Collections of specific permissions granted to code
//! - **Security Actions** - When and how permissions are checked (LinkDemand, Demand, etc.)
//! - **Named Arguments** - Custom security attribute parameters
//! - **Permission Attributes** - Declarative security specifications
//!
//! # Components
//!
//! - [`PermissionSet`] - A collection of security permissions
//! - [`Permission`] - Individual security permission with type and arguments
//! - [`NamedArgument`] - Key-value pairs for permission parameters
//! - Security action types and permission flags
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::{CilObject, metadata::security::PermissionSet};
//!
//! let assembly = CilObject::from_file("legacy_app.dll".as_ref())?;
//!
//! // Check for security permissions on types
//! for entry in assembly.types().iter() {
//!     let (token, type_def) = (entry.key(), entry.value());
//!     if let Some(security) = type_def.security.get() {
//!         println!("Type {} has security permissions", type_def.name);
//!         // Analyze permission sets...
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Legacy Status
//!
//! **Important**: Code Access Security was deprecated starting with .NET Framework 4.0
//! and is not supported in .NET Core/.NET 5+. This implementation is primarily useful
//! for analyzing older .NET Framework assemblies and understanding historical security models.
//!
//! # References
//!
//! - ECMA-335 6th Edition, Partition II, Section 22.11 - DeclSecurity Table
//! - Microsoft .NET Framework Security Documentation (archived)

mod namedargument;
mod permission;
mod permissionset;
mod types;

pub use namedargument::NamedArgument;
pub use permission::Permission;
pub use permissionset::PermissionSet;
pub use types::*;
