//! Event table module.
//!
//! This module provides complete support for the ECMA-335 Event metadata table (0x14),
//! which contains event definitions for .NET types. Events represent notification mechanisms
//! that allow objects to communicate state changes and important occurrences to interested
//! observers using the observer pattern. It includes raw table access, resolved data structures,
//! and integration with the broader metadata system.
//!
//! # Components
//!
//! - [`EventRaw`]: Raw table structure with unresolved heap indexes
//! - [`Event`]: Owned variant with resolved strings/types and full metadata
//! - [`EventLoader`]: Internal loader for processing Event table data
//! - Type aliases for efficient collections and reference management
//!
//! # Event Table Structure
//!
//! The Event table contains event definitions with these fields:
//! - **EventFlags**: Attributes controlling event behavior (see [`EventAttributes`])
//! - **Name**: Event name identifier (string heap reference)
//! - **EventType**: Type of the event handler (TypeDef, TypeRef, or TypeSpec coded index)
//!
//! Events are associated with accessor methods through the MethodSemantics table, which
//! defines the standard add/remove pattern and optional custom methods.
//!
//! # .NET Event Model
//!
//! .NET events provide these capabilities:
//! - **Type Safety**: Event handler type is verified at compile time
//! - **Multicast Support**: Multiple subscribers can be attached to a single event
//! - **Standard Pattern**: Consistent add/remove accessor methods with optional raise
//! - **Reflection Support**: Full metadata access for dynamic event handling
//!
//! # Reference
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`Event`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved event definitions by their metadata tokens.
pub type EventMap = SkipMap<Token, EventRc>;

/// A vector that holds a list of [`Event`] references
///
/// Thread-safe append-only vector for storing event collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type EventList = Arc<boxcar::Vec<EventRc>>;

/// A reference-counted pointer to an [`Event`]
///
/// Provides shared ownership and automatic memory management for event instances.
/// Multiple references can safely point to the same event data across threads.
pub type EventRc = Arc<Event>;

#[allow(non_snake_case)]
/// Event flags bit field constants
///
/// Defines event-level attributes that control event behavior and special naming conventions.
/// These flags are stored in the Event table's EventFlags field and indicate whether the
/// event has special meaning or requires special handling by the runtime.
///
/// # Reference
/// - [ECMA-335 II.23.1.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - EventAttributes enumeration
pub mod EventAttributes {
    /// Event has a special name
    ///
    /// Indicates that the event's name is special and should be treated accordingly
    /// by development tools. This is typically used for events that follow specific
    /// naming conventions or have special significance in the type system.
    pub const SPECIAL_NAME: u32 = 0x0200;

    /// Runtime provides special behavior based on the event name
    ///
    /// The Common Language Infrastructure provides special behavior for this event,
    /// depending upon the name of the event. This flag indicates that the runtime
    /// will recognize and handle this event in a special way.
    pub const RTSPECIAL_NAME: u32 = 0x0400;
}
