//! Builder pattern implementations for creating mock metadata objects
//!
//! This module contains fluent API builders for creating various .NET metadata
//! structures used in testing. Each builder provides a clean, composable way
//! to construct mock objects with realistic data.

// Private sub-modules - public interface is through parent test module
mod assembly;
mod attributes;
mod constants;
mod fields;
mod files;
mod generics;
mod methods;
mod params;
mod properties;
mod signatures;
mod types;

// Re-export all builders for use by parent module
pub use assembly::*;
//pub use attributes::*;
pub use constants::*;
pub use fields::*;
pub use files::*;
//pub use generics::*;
pub use methods::*;
pub use params::*;
pub use properties::*;
//pub use signatures::*;
pub use types::*;
