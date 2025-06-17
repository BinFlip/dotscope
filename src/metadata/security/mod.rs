//! .NET Code Access Security (CAS) implementation.
//!
//! This module provides comprehensive support for parsing and representing .NET Code Access Security
//! permissions and permission sets from assembly metadata. Code Access Security was a fundamental
//! security model in early .NET Framework versions that allowed fine-grained control over code
//! execution permissions based on evidence about the code's origin and trustworthiness.
//!
//! # Architecture
//!
//! The security module is organized around the core CAS concepts defined in ECMA-335:
//!
//! - **Permission Sets**: Collections of individual permissions that define what operations code can perform
//! - **Security Actions**: Timing and enforcement mechanisms for permission checks (Demand, LinkDemand, etc.)
//! - **Named Arguments**: Flexible parameter systems for custom security attributes
//! - **Permission Types**: Specific classes of permissions (FileIOPermission, SecurityPermission, etc.)
//!
//! The module follows a layered design where high-level permission sets are built from individual
//! permissions, which in turn are composed of named arguments and type specifications.
//!
//! # Key Components
//!
//! - [`crate::metadata::security::PermissionSet`] - Container for collections of security permissions with action types
//! - [`crate::metadata::security::Permission`] - Individual security permission with type information and arguments
//! - [`crate::metadata::security::NamedArgument`] - Key-value parameter pairs for permission configuration
//! - [`crate::metadata::security::SecurityAction`] - Enumeration of CAS enforcement timing and behavior
//! - [`crate::metadata::security::SecurityPermissionFlags`] - Bitfield flags for common security permission types
//!
//! # Usage Examples
//!
//! ## Basic Permission Set Analysis
//!
//! ```rust,no_run
//! use dotscope::{CilObject, metadata::security::PermissionSet};
//!
//! let assembly = CilObject::from_file("legacy_app.dll".as_ref())?;
//!
//! // Analyze security permissions on types
//! for entry in assembly.types().iter() {
//!     let (token, type_def) = (entry.key(), entry.value());
//!     if let Some(security) = type_def.security.get() {
//!         println!("Type {} has security declaration", type_def.name);
//!         println!("  Action: {:?}", security.action);
//!         println!("  Permissions: {}", security.permission_set.permissions().len());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Detailed Permission Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::security::{PermissionSet, Permission, SecurityAction};
//!
//! # let permission_set_data = &[0u8; 100]; // placeholder
//! let permission_set = PermissionSet::new(permission_set_data)?;
//!
//! // Check for dangerous permissions
//! if permission_set.has_file_io() {
//!     println!("WARNING: File system access permissions detected");
//!     let write_paths = permission_set.get_all_file_write_paths();
//!     if !write_paths.is_empty() {
//!         println!("  Write access to: {:?}", write_paths);
//!     }
//! }
//!
//! // Enumerate individual permissions
//! for permission in permission_set.permissions() {
//!     println!("Permission type: {}", permission.class_name);
//!     for arg in &permission.named_arguments {
//!         println!("  {}: {:?}", arg.name, arg.value);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This module defines security-specific error handling for CAS parsing:
//! - **Malformed Security Data**: When permission set binary data is corrupted or invalid
//! - **Unknown Permission Types**: When encountering permission types not defined in the specification
//! - **Invalid Security Actions**: When security action codes are outside valid ranges
//! - **Missing Required Arguments**: When mandatory permission arguments are absent
//!
//! All parsing operations return [`crate::Result<T>`] and follow consistent error patterns
//! defined in the main error module.
//!
//! # Integration
//!
//! Security metadata integrates with several other dotscope modules:
//! - **Tables Module**: Security information is stored in the DeclSecurity metadata table
//! - **Signatures Module**: Permission types may reference type signatures for custom permissions
//! - **Streams Module**: Binary permission data is stored in the blob heap
//! - **Custom Attributes**: Some security specifications use custom attribute syntax
//!
//! # Legacy Status
//!
//! **Important**: Code Access Security was deprecated starting with .NET Framework 4.0
//! and is not supported in .NET Core/.NET 5+. This implementation is primarily useful
//! for analyzing older .NET Framework assemblies and understanding historical security models.
//! Modern .NET applications should use alternative security mechanisms.
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement `Send + Sync`:
//! - Permission sets and permissions are immutable after parsing
//! - No internal mutability or shared state is used
//! - Parsing operations are stateless and can be performed concurrently
//!
//! # References
//!
//! - [ECMA-335 6th Edition, Partition II, Section 22.11 - DeclSecurity Table](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - [ECMA-335 6th Edition, Partition II, Section 23.1.3 - Security Actions](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - Microsoft .NET Framework Security Documentation (archived)

mod namedargument;
mod permission;
mod permissionset;
mod types;

pub use namedargument::NamedArgument;
pub use permission::Permission;
pub use permissionset::PermissionSet;
pub use types::*;
