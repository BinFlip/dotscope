//! # `MethodSemantics` Table Module  
//!
//! This module provides comprehensive access to the **`MethodSemantics`** metadata table (ID 0x18),
//! which specifies the relationship between methods and events or properties in .NET assemblies.
//! The table defines which methods serve as getters, setters, adders, removers, and other
//! semantic roles for properties and events.
//!
//! ## Overview
//!
//! The `MethodSemantics` table establishes the semantic binding between:
//! - **Methods**: Individual method definitions that implement semantic behavior
//! - **Properties**: Property definitions requiring getter/setter methods
//! - **Events**: Event definitions requiring add/remove/fire methods
//!
//! Each entry specifies a method's semantic role (getter, setter, adder, etc.) and its
//! association with a specific property or event through coded indexes.
//!
//! ## Components
//!
//! The module implements a dual-representation pattern for optimal performance:
//!
//! - [`MethodSemanticsRaw`] - Raw table data with unresolved indexes for initial parsing
//! - [`MethodSemantics`] - Processed data with resolved references and owned data for runtime use
//! - [`MethodSemanticsLoader`] - Handles conversion between raw and processed representations
//! - [`MethodSemanticsMap`] - Thread-safe storage mapping tokens to processed entries
//! - [`MethodSemanticsAttributes`] - Constants defining semantic relationship types
//!
//! ## Table Structure  
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Semantics` | `u16` | Bitmask defining the semantic relationship type |
//! | `Method` | `u32` | Index into `MethodDef` table identifying the method |
//! | `Association` | `u32` | `HasSemantics` coded index to property or event |
//!
//! The `Semantics` field uses [`MethodSemanticsAttributes`] constants:
//! - `SETTER` (0x0001) - Property setter method
//! - `GETTER` (0x0002) - Property getter method  
//! - `OTHER` (0x0004) - Other property/event method
//! - `ADD_ON` (0x0008) - Event add method
//! - `REMOVE_ON` (0x0010) - Event remove method
//! - `FIRE` (0x0020) - Event fire method
//!
//! ## ECMA-335 Specification
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22.28** - `MethodSemantics` table structure and semantics
//! - **§II.23.1.12** - `MethodSemanticsAttributes` enumeration
//! - **§II.24.2.6** - `HasSemantics` coded index encoding
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

/// Thread-safe map holding the mapping of [`crate::metadata::token::Token`] to parsed [`MethodSemantics`] entries.
///
/// This concurrent skip list provides efficient O(log n) access to method semantics entries
/// by their metadata token, supporting multiple concurrent readers and writers.
pub type MethodSemanticsMap = SkipMap<Token, MethodSemanticsRc>;

/// Thread-safe vector holding a list of [`MethodSemantics`] entries.
///
/// Uses a lock-free vector implementation for efficient concurrent access to
/// the collection of all method semantics entries in the metadata.
pub type MethodSemanticsList = Arc<boxcar::Vec<MethodSemanticsRc>>;

/// Reference-counted pointer to a [`MethodSemantics`] entry.
///
/// Enables efficient sharing of method semantics data across multiple contexts
/// while maintaining memory safety through automatic reference counting.
pub type MethodSemanticsRc = Arc<MethodSemantics>;

#[allow(non_snake_case)]
/// Constants defining method semantic relationship types for the `MethodSemantics` table.
///
/// These flags specify the role a method plays in relation to a property or event,
/// as defined in ECMA-335 §II.23.1.12. Multiple flags can be combined using bitwise OR.
///
/// ## Property Semantics
/// - [`MethodSemanticsAttributes::SETTER`] - Method is a property setter (write access)
/// - [`MethodSemanticsAttributes::GETTER`] - Method is a property getter (read access)  
/// - [`MethodSemanticsAttributes::OTHER`] - Method provides other property-related functionality
///
/// ## Event Semantics  
/// - [`MethodSemanticsAttributes::ADD_ON`] - Method adds event handlers (subscribe)
/// - [`MethodSemanticsAttributes::REMOVE_ON`] - Method removes event handlers (unsubscribe)
/// - [`MethodSemanticsAttributes::FIRE`] - Method fires/raises the event
/// - [`MethodSemanticsAttributes::OTHER`] - Method provides other event-related functionality
pub mod MethodSemanticsAttributes {
    /// Setter method for property (0x0001).
    ///
    /// Indicates the method provides write access to a property value.
    pub const SETTER: u32 = 0x0001;

    /// Getter method for property (0x0002).
    ///
    /// Indicates the method provides read access to a property value.
    pub const GETTER: u32 = 0x0002;

    /// Other method for property or event (0x0004).
    ///
    /// Indicates the method provides additional functionality related to
    /// the associated property or event beyond the standard operations.
    pub const OTHER: u32 = 0x0004;

    /// `AddOn` method for event (0x0008).
    ///
    /// Indicates the method adds event handlers (subscription functionality).
    pub const ADD_ON: u32 = 0x0008;

    /// `RemoveOn` method for event (0x0010).
    ///
    /// Indicates the method removes event handlers (unsubscription functionality).
    pub const REMOVE_ON: u32 = 0x0010;

    /// Fire method for event (0x0020).
    ///
    /// Indicates the method fires or raises the event, invoking all registered handlers.
    pub const FIRE: u32 = 0x0020;
}
