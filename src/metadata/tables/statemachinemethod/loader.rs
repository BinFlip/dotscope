//! `StateMachineMethod` table loader for efficient metadata processing
//!
//! This module provides the [`StateMachineMethodLoader`] implementation that handles
//! loading and processing `StateMachineMethod` table entries from Portable PDB metadata.
//! The loader follows the established `MetadataLoader` pattern for consistent parallel
//! processing and efficient memory utilization.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{StateMachineMethodRaw, TableId},
    },
    Result,
};

/// Metadata loader for `StateMachineMethod` table entries
///
/// This loader processes `StateMachineMethod` table data to build efficient lookup
/// structures for state machine debugging support. The loader handles:
///
/// - Parallel processing of table rows for optimal performance
/// - Building token-based lookup maps for fast method resolution
/// - Creating ordered lists for sequential access patterns
/// - Memory-efficient storage using reference counting
///
/// # State Machine Debugging Context
///
/// The `StateMachineMethod` table is crucial for modern .NET debugging because
/// async/await and iterator methods are implemented as state machines. Without
/// this mapping, debuggers would show confusing compiler-generated method names
/// and lose the connection to the original user code.
///
/// # Integration
///
/// This loader integrates with the broader metadata loading infrastructure:
/// - Uses the [`LoaderContext`] for coordinated loading across all tables
/// - Implements [`MetadataLoader`] trait for consistent processing patterns
/// - Provides thread-safe data structures for concurrent debugger access
///
/// # References
///
/// - [Portable PDB Format - StateMachineMethod Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#statemachinemethod-table-0x36)
/// - [.NET State Machine Implementation](https://devblogs.microsoft.com/dotnet/how-async-await-really-works/)
pub struct StateMachineMethodLoader;

impl MetadataLoader for StateMachineMethodLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<StateMachineMethodRaw>() {
                table.par_iter().try_for_each(|row| {
                    let state_machine_method = row.to_owned(context.method_def)?;
                    context
                        .state_machine_method
                        .insert(state_machine_method.token, state_machine_method);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::StateMachineMethod
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
