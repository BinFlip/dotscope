//! # `StandAloneSig` Table Loader
//!
//! This module provides loading functionality for the `StandAloneSig` metadata table (ID 0x11).
//! The `StandAloneSig` table contains standalone signatures that are not directly associated
//! with methods, fields, or properties, but are referenced from CIL instructions or used
//! in complex signature scenarios throughout .NET assemblies.
//!
//! ## Purpose
//!
//! The `StandAloneSig` table serves several critical functions:
//! - **Method Signatures**: Stores signatures for method pointers and function calls
//! - **Local Variable Signatures**: Contains local variable type information for methods
//! - **Dynamic Signatures**: Supports runtime signature generation and manipulation
//! - **CIL Instruction Support**: Provides signatures referenced by CIL instructions
//!
//! ## Dependencies
//!
//! - **`TypeDef` Table**: Required for type definition resolution
//! - **`TypeRef` Table**: Required for external type resolution
//! - **`TypeSpec` Table**: Required for constructed type resolution
//! - **`MethodDef` Table**: Required for method context during signature processing
//!
//! ## Signature Types
//!
//! `StandAloneSig` entries can contain:
//! - **Method Signatures**: Function pointer and delegate signatures
//! - **Local Variable Signatures**: Local variable type declarations
//! - **Field Signatures**: Standalone field type information
//! - **Generic Signatures**: Generic type and method instantiations
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.39 - `StandAloneSig` table specification
//! - [`crate::metadata::tables::StandAloneSigRaw`] - Raw table entry structure
//! - [`crate::metadata::tables::StandAloneSig`] - Owned table entry type

use std::sync::Arc;

use crate::{
    assembly::VisitedMap,
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::StandAloneSigRaw,
    },
    prelude::TableId,
    Result,
};
use rayon::iter::{ParallelBridge, ParallelIterator};

/// Loader implementation for the `StandAloneSig` metadata table.
///
/// This loader processes `StandAloneSig` table entries (ID 0x11) that contain standalone
/// signatures for method pointers, local variables, and other signature scenarios.
/// It handles the loading, parsing, and integration of signatures with method definitions
/// and type system components.
///
/// ## Error Handling
///
/// The loader validates:
/// - Signature blob format and structure
/// - Type reference validity and accessibility
/// - Method signature compatibility and constraints
/// - Generic parameter consistency and bounds
///
pub(crate) struct StandAloneSigLoader;

impl MetadataLoader for StandAloneSigLoader {
    /// Loads and processes all `StandAloneSig` table entries from the metadata.
    ///
    /// ## Arguments
    ///
    /// * `context` - The loading context containing metadata and storage facilities
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - All standalone signatures loaded and validated successfully
    /// * `Err(_)` - Signature loading or validation failed
    ///
    /// ## Parallel Processing
    ///
    /// The loader processes method definitions in parallel to improve performance
    /// with large assemblies while maintaining thread safety through shared state.
    ///
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blobs)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<StandAloneSigRaw>() {
                let shared_visited = Arc::new(VisitedMap::new(context.input.data().len()));
                let results: Vec<Result<()>> = context
                    .method_def
                    .iter()
                    .par_bridge()
                    .map(|row| {
                        let method = row.value();
                        method.parse(
                            &context.input,
                            blobs,
                            table,
                            context.types,
                            shared_visited.clone(),
                        )
                    })
                    .collect();

                // ToDo: We return only the first error encountered
                for result in results {
                    result?;
                }
            }
        }

        Ok(())
    }

    /// Returns the table identifier for the `StandAloneSig` table.
    ///
    /// ## Returns
    ///
    /// [`TableId::StandAloneSig`] (0x11) - The metadata table identifier
    fn table_id(&self) -> TableId {
        TableId::StandAloneSig
    }

    /// Returns the dependency list for `StandAloneSig` table loading.
    ///
    /// The `StandAloneSig` table depends on multiple other tables for proper
    /// signature resolution and type system integration:
    ///
    /// - **`TypeDef`**: Required for resolving type definitions in signatures
    /// - **`TypeRef`**: Required for resolving external type references
    /// - **`TypeSpec`**: Required for resolving constructed and generic types
    /// - **`MethodDef`**: Required for method context during signature processing
    ///
    /// ## Returns
    ///
    /// A slice containing the required table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
        ]
    }
}
