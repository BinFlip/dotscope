//! DeclSecurity table module.
//!
//! This module provides complete support for the ECMA-335 DeclSecurity metadata table (0x0E),
//! which contains declarative security declarations for assemblies, types, and methods. It includes
//! raw table access, resolved data structures, permission set parsing for .NET Code Access Security (CAS),
//! and integration with the broader metadata system.
//!
//! # Components
//!
//! - [`DeclSecurityRaw`]: Raw table structure with unresolved coded indexes
//! - [`DeclSecurity`]: Owned variant with resolved references and parsed permission sets
//! - [`DeclSecurityLoader`]: Internal loader for processing DeclSecurity table data
//! - Type aliases for efficient collections and reference management
//!
//! # DeclSecurity Table Structure
//!
//! Each DeclSecurity table row contains these fields:
//! - **Action**: Security action type (Demand, Assert, Deny, etc.)
//! - **Parent**: Target element where security is applied (coded index)
//! - **PermissionSet**: Serialized security permissions (blob)
//!
//! The parent can be any metadata element that supports the `HasDeclSecurity` coded index,
//! including assemblies, types (TypeDef), and methods (MethodDef).
//!
//! # Security Actions
//!
//! The .NET security model supports various declarative actions:
//! - **Demand**: Require callers to have specific permissions at runtime
//! - **Assert**: Temporarily escalate permissions for trusted code paths
//! - **Deny**: Prevent code from using certain permissions even if granted
//! - **LinkDemand**: Check permissions at JIT compilation time
//! - **InheritanceDemand**: Require permissions for type inheritance
//! - **PermitOnly**: Restrict permissions to only those specified
//!
//! # Reference
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - DeclSecurity table specification
//! - [ECMA-335 II.23.1.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - SecurityAction enumeration

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`DeclSecurity`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved security declarations by their metadata tokens.
pub type DeclSecurityMap = SkipMap<Token, DeclSecurityRc>;

/// A vector that holds a list of [`DeclSecurity`] references
///
/// Thread-safe append-only vector for storing security declaration collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type DeclSecurityList = Arc<boxcar::Vec<DeclSecurityRc>>;

/// A reference-counted pointer to a [`DeclSecurity`]
///
/// Provides shared ownership and automatic memory management for security declaration instances.
/// Multiple references can safely point to the same security declaration data across threads.
pub type DeclSecurityRc = Arc<DeclSecurity>;
