//! Implementation of `RowReadable` for `StateMachineMethodRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `StateMachineMethod` table (ID 0x36),
//! enabling reading of state machine method mapping information from Portable PDB files. The
//! StateMachineMethod table maps compiler-generated state machine methods (like MoveNext) back
//! to their original user-written async/await and iterator methods.
//!
//! ## Table Structure (Portable PDB)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `MoveNextMethod` | MethodDef table index | Compiler-generated state machine method |
//! | `KickoffMethod` | MethodDef table index | Original user-written method |
//!
//! ## Debugging Context
//!
//! This table is essential for providing proper debugging experiences with modern C# features:
//! - **Async/Await**: Maps async state machine MoveNext methods to original async methods
//! - **Iterator Methods**: Maps iterator state machine methods to yield-returning methods
//! - **Stepping Support**: Enables debuggers to step through user code rather than generated code
//! - **Breakpoint Mapping**: Allows breakpoints in user methods to work correctly
//!
//! ## State Machine Patterns
//!
//! The table handles several compiler-generated patterns:
//! - **Async Methods**: User async method → compiler-generated async state machine
//! - **Iterator Methods**: User yield method → compiler-generated iterator state machine  
//! - **Async Iterators**: User async iterator → compiler-generated async iterator state machine
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::statemachinemethod::writer`] - Binary serialization support
//! - [`crate::metadata::tables::statemachinemethod`] - High-level StateMachineMethod interface
//! - [`crate::metadata::tables::statemachinemethod::raw`] - Raw structure definition

use crate::{
    metadata::{
        tables::{RowReadable, StateMachineMethodRaw, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for StateMachineMethodRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(StateMachineMethodRaw {
            rid,
            token: Token::new(0x3600_0000 + rid),
            offset: *offset,
            move_next_method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
            kickoff_method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x00, // move_next_method (2 bytes, normal table) - 0x0001
            0x02, 0x00, // kickoff_method (2 bytes, normal table) - 0x0002
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::StateMachineMethod, 1), (TableId::MethodDef, 1000)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<StateMachineMethodRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StateMachineMethodRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x36000001);
            assert_eq!(row.move_next_method, 0x0001);
            assert_eq!(row.kickoff_method, 0x0002);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x00, 0x00, // move_next_method (4 bytes, large table) - 0x00000101
            0x02, 0x02, 0x00, 0x00, // kickoff_method (4 bytes, large table) - 0x00000202
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::StateMachineMethod, 1),
                (TableId::MethodDef, 100000),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<StateMachineMethodRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StateMachineMethodRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x36000001);
            assert_eq!(row.move_next_method, 0x00000101);
            assert_eq!(row.kickoff_method, 0x00000202);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
