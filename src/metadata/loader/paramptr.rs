//! `ParamPtr` loader implementation
//!
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::{ParamPtrRaw, TableId},
    },
    Result,
};

/// Loader for ParamPtr metadata table entries.
///
/// ParamPtr tables provide indirection for parameter access in uncompressed (`#-`) metadata streams.
/// This loader processes all ParamPtr entries and stores them in the loader context for later resolution.
pub(crate) struct ParamPtrLoader;

impl MetadataLoader for ParamPtrLoader {
    fn table_id(&self) -> TableId {
        TableId::ParamPtr
    }

    fn dependencies(&self) -> &'static [TableId] {
        // ParamPtr is a simple indirection table with no dependencies
        &[]
    }

    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<ParamPtrRaw>(TableId::ParamPtr) {
                for row in table {
                    let owned = row.to_owned()?;
                    context.param_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }
}

/// Load all ParamPtr entries from the metadata tables and populate the loader context.
///
/// ParamPtr tables provide indirection for parameter access in uncompressed (`#-`) metadata streams.
/// Each entry contains a 1-based index into the Param table, allowing for flexible parameter ordering.
///
/// # Parameters
/// - `context`: Reference to the loader context to populate with ParamPtr data
///
/// # Returns
/// - `Ok(())` on successful loading
/// - `Err` if table access or parsing fails
///
/// # Loading Process
/// 1. Check if ParamPtr table exists in the metadata
/// 2. If present, iterate through all ParamPtr entries
/// 3. Convert each raw entry to a resolved ParamPtr instance
/// 4. Store in the loader context's ParamPtr map using the token as key
///
/// # Usage in `#-` Streams
/// When ParamPtr is present, parameter resolution should:
/// 1. First check if a ParamPtr entry exists for the requested parameter
/// 2. Use the ParamPtr's target index to access the actual Param table entry
/// 3. Fall back to direct Param table access if no ParamPtr entry exists
pub fn load_paramptrs(context: &LoaderContext) -> Result<()> {
    if let Some(header) = context.meta {
        if let Some(table) = header.table::<ParamPtrRaw>(TableId::ParamPtr) {
            for row in table {
                let owned = row.to_owned()?;
                context.param_ptr.insert(row.token, owned);
            }
        }
    }
    Ok(())
}
