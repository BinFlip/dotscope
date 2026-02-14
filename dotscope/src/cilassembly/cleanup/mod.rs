//! Assembly cleanup infrastructure for removing unused metadata.
//!
//! This module provides generic cleanup capabilities for [`CilAssembly`](crate::CilAssembly),
//! enabling removal of metadata entries and their cascading orphans. This is useful for:
//!
//! - **Deobfuscation**: Removing protection infrastructure (types, methods, fields)
//! - **Dead code elimination**: Removing unused types and methods
//! - **Assembly optimization**: Compacting metadata after modifications
//!
//! # Architecture
//!
//! The cleanup system has two main components:
//!
//! ## 1. Change-Driven Cleanup
//!
//! When you explicitly delete types/methods/fields, the cleanup executor:
//! - Removes the specified items
//! - Finds and removes orphaned metadata that only referenced deleted items
//! - Preserves pre-existing orphans (may be used via reflection)
//!
//! ## 2. General Optimization (during PE generation)
//!
//! The PE generator automatically:
//! - Compacts heaps (only emits referenced entries)
//! - Deduplicates StandAloneSig entries
//! - Removes truly unreferenced entries
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::cilassembly::{CilAssembly, cleanup::CleanupRequest};
//!
//! let mut assembly = CilAssembly::new(view);
//!
//! // Build a cleanup request
//! let mut request = CleanupRequest::new();
//! request.add_type(protection_type_token);
//! request.add_method(decryptor_method_token);
//! request.exclude_section(".confuser");
//!
//! // Execute cleanup (modifies AssemblyChanges)
//! let stats = assembly.execute_cleanup(&request)?;
//! println!("{}", stats);
//!
//! // Generate assembly (cleanup is applied)
//! assembly.write_to_file("output.exe")?;
//! ```
//!
//! # What Gets Cleaned Up
//!
//! When a **type** is deleted:
//! - All its methods (MethodDef)
//! - All its fields (Field)
//! - NestedClass entries
//! - InterfaceImpl entries
//! - ClassLayout entries
//! - GenericParam entries (and their constraints)
//! - CustomAttributes targeting the type
//! - PropertyMap/EventMap entries
//!
//! When a **method** is deleted:
//! - All its parameters (Param)
//! - Its StandAloneSig (local variables)
//! - MethodSemantics entries
//! - MethodImpl entries
//! - GenericParam entries (and their constraints)
//! - ImplMap entries (P/Invoke)
//! - DeclSecurity entries
//! - CustomAttributes targeting the method
//!
//! When a **field** is deleted:
//! - FieldRVA entries
//! - FieldLayout entries
//! - FieldMarshal entries
//! - Constant entries
//! - CustomAttributes targeting the field

mod compaction;
mod executor;
mod orphans;
mod references;
mod request;
mod stats;

pub(crate) use compaction::mark_unreferenced_heap_entries;
pub use executor::execute_cleanup;
pub use request::CleanupRequest;
pub use stats::CleanupStats;
