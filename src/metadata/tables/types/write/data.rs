//! Writable table data enumeration for all metadata table variants.
//!
//! This module will contain the `WritableTableData` enum that represents
//! all possible writable metadata table types. This provides a type-erased
//! interface for working with tables of different types in a uniform way.
//!
//! # Planned Implementation
//!
//! ```rust,ignore
//! pub enum WritableTableData {
//!     Module(WritableMetadataTable<ModuleOwned>),
//!     TypeRef(WritableMetadataTable<TypeRefOwned>),
//!     TypeDef(WritableMetadataTable<TypeDefOwned>),
//!     Field(WritableMetadataTable<FieldOwned>),
//!     MethodDef(WritableMetadataTable<MethodDefOwned>),
//!     Param(WritableMetadataTable<ParamOwned>),
//!     // ... for all table types
//! }
//!
//! impl WritableTableData {
//!     pub fn table_id(&self) -> TableId;
//!     pub fn row_count(&self) -> u32;
//!     pub fn calculate_size(&self) -> u32;
//!     pub fn write_to_buffer(&self, data: &mut [u8], offset: &mut usize) -> Result<()>;
//! }
//! ```

// TODO: Implement WritableTableData enum and methods
