//! `GenericParam` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `GenericParam` metadata table,
//! which defines generic type and method parameters. This enables generic programming support
//! in .NET assemblies with type-safe parameterized types and methods.
//!
//! # Overview
//! The `GenericParam` table enables generic programming scenarios:
//! - **Generic types**: Class and interface type parameters (`List<T>`, `Dictionary<TKey, TValue>`)
//! - **Generic methods**: Method-level type parameters (`Method<U>()`)
//! - **Constraint specification**: Base class and interface constraints
//! - **Variance annotations**: Covariance and contravariance for type safety
//! - **Reflection support**: Runtime access to generic parameter metadata
//!
//! # Components
//! - [`GenericParamRaw`]: Raw generic parameter data read directly from metadata tables
//! - [`GenericParam`]: Owned generic parameter data with resolved references
//! - [`GenericParamLoader`]: Processes and loads generic parameter metadata
//! - [`GenericParamMap`]: Thread-safe collection of parameters indexed by token
//! - [`GenericParamList`]: Vector-based collection of parameters
//! - [`GenericParamRc`]: Reference-counted parameter for shared ownership
//!
//! # Table Structure
//! Each `GenericParam` entry contains:
//! - **Number**: Ordinal position within the parameter list (0-based)
//! - **Flags**: Variance and constraint attributes
//! - **Owner**: Reference to the owning type or method (coded index)
//! - **Name**: String reference to the parameter name
//!
//! # Generic Parameter Types
//! Parameters can be defined at different scopes:
//! ```text
//! ┌──────────────┬─────────────────────────────────────────┐
//! │ Scope        │ Example                                 │
//! ├──────────────┼─────────────────────────────────────────┤
//! │ Type Level   │ class List<T> { ... }                   │
//! │ Method Level │ void Method<U>(U parameter) { ... }     │
//! │ Interface    │ interface IEnumerable<out T> { ... }    │
//! │ Delegate     │ delegate TResult Func<in T, out TResult>│
//! └──────────────┴─────────────────────────────────────────┘
//! ```
//!
//!
//! # Generic Parameter Attributes
//! The [`GenericParamAttributes`] module defines flags for parameter characteristics:
//! - **Variance**: COVARIANT, CONTRAVARIANT for type safety
//! - **Constraints**: Reference type, value type, constructor constraints
//! - **Special flags**: Various constraint and variance combinations
//!
//! # Variance and Constraints
//! Generic parameters support advanced type system features:
//! - **Covariance**: `IEnumerable<out T>` allows `IEnumerable<Derived>` → `IEnumerable<Base>`
//! - **Contravariance**: `Action<in T>` allows `Action<Base>` → `Action<Derived>`
//! - **Reference constraint**: `where T : class` requires reference types
//! - **Value constraint**: `where T : struct` requires value types
//! - **Constructor constraint**: `where T : new()` requires parameterless constructor
//!
//! # Owner Resolution
//! Generic parameters are owned by either types or methods:
//! - **Type parameters**: Owned by `TypeDef` entries (classes, interfaces)
//! - **Method parameters**: Owned by `MethodDef` entries (generic methods)
//! - **Coded index**: Uses `TypeOrMethodDef` coded index for owner resolution
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.20 for the complete `GenericParam` table specification.

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

/// Thread-safe map of generic parameter entries indexed by parameter token.
///
/// This skip list-based map provides efficient concurrent access to generic parameter
/// metadata, allowing multiple threads to resolve parameter information during
/// generic type analysis and reflection operations.
pub type GenericParamMap = SkipMap<Token, GenericParamRc>;

/// Thread-safe vector of generic parameter entries.
///
/// This collection provides ordered access to generic parameter entries, useful for
/// sequential processing and bulk operations during generic type analysis and
/// parameter enumeration.
pub type GenericParamList = Arc<boxcar::Vec<GenericParamRc>>;

/// Reference-counted generic parameter entry.
///
/// Provides shared ownership of [`GenericParam`] instances, enabling efficient
/// sharing of parameter metadata across multiple data structures and threads.
pub type GenericParamRc = Arc<GenericParam>;

#[allow(non_snake_case)]
/// Generic parameter attribute flags for the `GenericParamAttributes` field.
///
/// These constants define the possible values for the `Flags` field in `GenericParam` table entries,
/// specifying variance, constraints, and other characteristics of generic type and method parameters.
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.20 for `GenericParam` table flag specifications.
pub mod GenericParamAttributes {
    /// Mask for extracting variance information.
    ///
    /// Use this mask with bitwise AND to extract the variance bits from the flags.
    /// The result can then be compared with COVARIANT or CONTRAVARIANT constants.
    pub const VARIANCE_MASK: u32 = 0x0003;

    /// The generic parameter is covariant.
    ///
    /// Covariant parameters allow assignment compatibility in the direction of
    /// inheritance (e.g., `IEnumerable<Derived>` can be assigned to `IEnumerable<Base>`).
    /// Used with `out` keyword in C# (`IEnumerable<out T>`).
    pub const COVARIANT: u32 = 0x0001;

    /// The generic parameter is contravariant.
    ///
    /// Contravariant parameters allow assignment compatibility in the reverse direction
    /// of inheritance (e.g., `Action<Base>` can be assigned to `Action<Derived>`).
    /// Used with `in` keyword in C# (`Action<in T>`).
    pub const CONTRAVARIANT: u32 = 0x0002;

    /// Mask for extracting special constraint information.
    ///
    /// Use this mask with bitwise AND to extract the constraint bits from the flags.
    /// The result can then be compared with specific constraint constants.
    pub const SPECIAL_CONSTRAINT_MASK: u32 = 0x001C;

    /// The generic parameter has a reference type constraint.
    ///
    /// This constraint requires the type argument to be a reference type (class).
    /// Corresponds to `where T : class` constraint in C#.
    pub const REFERENCE_TYPE_CONSTRAINT: u32 = 0x0004;

    /// The generic parameter has a value type constraint.
    ///
    /// This constraint requires the type argument to be a non-nullable value type (struct).
    /// Corresponds to `where T : struct` constraint in C#.
    pub const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT: u32 = 0x0008;

    /// The generic parameter has a default constructor constraint.
    ///
    /// This constraint requires the type argument to have a public parameterless constructor.
    /// Corresponds to `where T : new()` constraint in C#.
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: u32 = 0x0010;

    /// Mask for reserved bits that should not be set.
    ///
    /// Reserved bits in the flags field that are not currently defined by the ECMA-335
    /// specification. These bits should be zero in valid metadata.
    pub const RESERVED_MASK: u32 = 0xFFE0;
}
