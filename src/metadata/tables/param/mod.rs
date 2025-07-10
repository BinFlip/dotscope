//! # Param Table Module
//!
//! This module provides comprehensive access to the **Param** metadata table (ID 0x08),
//! which contains information about method parameters including their names, attributes,
//! sequence numbers, and metadata. Param entries define the components of method signatures
//! and provide parameter-specific information for proper method invocation.
//!
//! ## Overview
//!
//! The Param table manages method parameter information in .NET assemblies:
//! - **Parameter Names**: Human-readable names for method parameters
//! - **Sequence Numbers**: Ordering of parameters within method signatures
//! - **Attributes**: Parameter characteristics (in, out, optional, default values)
//! - **Marshalling**: Information for interop and P/Invoke scenarios
//!
//! This table is essential for understanding method signatures and enabling proper
//! parameter binding during method invocation.
//!
//! ## Components
//!
//! The module implements a dual-representation pattern for optimal performance:
//!
//! - [`ParamRaw`] - Raw table data with unresolved indexes for initial parsing
//! - [`Param`] - Processed data with resolved parameter names
//! - [`ParamLoader`] - Handles conversion between raw and processed representations
//! - [`ParamMap`] - Thread-safe storage mapping tokens to processed entries
//! - [`ParamList`] - Thread-safe collection for sequential access
//!
//! ## Table Structure
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u16` | Parameter attributes and characteristics |
//! | `Sequence` | `u16` | Parameter order in method signature (0 = return type) |
//! | `Name` | `u32` | Index into string heap containing parameter name |
//!
//! The sequence number determines parameter ordering, with 0 reserved for the return type
//! and 1+ for actual parameters in declaration order.
//!
//! ## Parameter Attributes
//!
//! The [`crate::metadata::tables::ParamAttributes`] module defines all possible parameter flags:
//!
//! ### Direction Attributes
//! - [`IN`](ParamAttributes::IN) - Parameter is input (passed to method)
//! - [`OUT`](ParamAttributes::OUT) - Parameter is output (returned from method)
//!
//! ### Optional Attributes  
//! - [`OPTIONAL`](ParamAttributes::OPTIONAL) - Parameter is optional
//! - [`HAS_DEFAULT`](ParamAttributes::HAS_DEFAULT) - Parameter has default value
//!
//! ### Marshalling Attributes
//! - [`HAS_FIELD_MARSHAL`](ParamAttributes::HAS_FIELD_MARSHAL) - Parameter has marshalling information
//!
//! ## ECMA-335 Specification
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22.33** - Param table structure and semantics
//! - **§II.23.1.13** - Parameter attributes flags
//! - **§II.24.2.1** - String heap references
//!
//! For detailed specifications, see [ECMA-335 6th Edition](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod builder;
mod loader;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map holding the mapping of [`crate::metadata::token::Token`] to parsed [`Param`] entries.
///
/// This concurrent skip list provides efficient O(log n) access to Param entries
/// by their metadata token. Used for resolving parameter information during method processing.
pub type ParamMap = SkipMap<Token, ParamRc>;

/// Thread-safe vector holding a list of [`Param`] entries.
///
/// Uses a lock-free vector implementation for efficient concurrent access.
/// Provides sequential access to Param entries for iteration and batch processing.
pub type ParamList = Arc<boxcar::Vec<ParamRc>>;

/// Reference-counted pointer to a [`Param`] entry.
///
/// Enables efficient sharing of Param data across multiple contexts
/// while maintaining memory safety through automatic reference counting.
pub type ParamRc = Arc<Param>;

#[allow(non_snake_case)]
/// Parameter attribute flags for the Param table.
///
/// This module defines all possible flags that can be set in the `Flags` field
/// of Param entries according to ECMA-335 §II.23.1.13. These flags control
/// parameter behavior, direction, and characteristics.
pub mod ParamAttributes {
    /// Parameter is an input parameter (passed to the method).
    ///
    /// This flag indicates that the parameter is used to pass data into the method.
    /// Most parameters are input parameters by default.
    pub const IN: u32 = 0x0001;

    /// Parameter is an output parameter (data flows out of the method).
    ///
    /// This flag indicates that the parameter is used to return data from the method.
    /// Often used with reference or pointer types for multiple return values.
    pub const OUT: u32 = 0x0002;

    /// Parameter is optional and may be omitted in calls.
    ///
    /// This flag indicates that the parameter is optional and can be omitted
    /// when calling the method. Used primarily for COM interop scenarios.
    pub const OPTIONAL: u32 = 0x0010;

    /// Parameter has a default value defined.
    ///
    /// This flag indicates that the parameter has a default value specified
    /// in the Constant table. When set, there should be a corresponding
    /// Constant entry for this parameter.
    pub const HAS_DEFAULT: u32 = 0x1000;

    /// Parameter has marshalling information defined.
    ///
    /// This flag indicates that the parameter has custom marshalling information
    /// defined in the `FieldMarshal` table for interop scenarios.
    pub const HAS_FIELD_MARSHAL: u32 = 0x2000;

    /// Reserved bits that shall be zero in conforming implementations.
    ///
    /// These bits are reserved by the ECMA-335 specification and should
    /// not be set in valid metadata.
    pub const UNUSED: u32 = 0xcfe0;
}
