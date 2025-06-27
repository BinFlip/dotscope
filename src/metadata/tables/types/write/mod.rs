//! Write-capable infrastructure for creating and modifying metadata tables.
//!
//! This module provides the functionality for creating, modifying, and serializing
//! .NET CLI metadata tables to binary format. It includes traits, builders, and
//! containers that enable type-safe construction and serialization of metadata
//! with support for both sequential and parallel operations.
//!
//! # Key Components (Future Implementation)
//!
//! - [`crate::metadata::tables::types::RowWritable`] - Trait for serializing table rows to byte data
//! - [`WritableMetadataTable`] - Container for mutable table data with owned rows
//! - [`WritableTableData`] - Enumeration of all writable table variants
//! - [`WritableTablesHeader`] - Complete metadata tables header for serialization
//! - [`TableBuilder`] - Builder pattern for constructing tables incrementally
//!
//! # Planned Architecture
//!
//! The write infrastructure will mirror the read architecture but with mutable
//! ownership semantics:
//! - Tables will hold owned row data (e.g., `Vec<TypeDefOwned>`)
//! - Size calculations will be performed dynamically based on current content
//! - Serialization will support incremental writing and validation
//! - Cross-references will be maintained and validated during construction
//!
//! # Thread Safety
//!
//! Write operations will support concurrent construction with proper synchronization:
//! - [`RowWritable`] types will be [`Sync`] to support parallel serialization
//! - Builders will provide thread-safe incremental construction
//! - Validation will occur at table and header level before serialization

mod data;
mod header;
mod table;
mod traits;

// TODO: Implement write infrastructure
pub use data::TableDataOwned;
// pub use data::WritableTableData;
// pub use header::WritableTablesHeader;
// pub use table::WritableMetadataTable;
pub use traits::RowWritable;
