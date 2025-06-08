//! `MethodDef` loader implementation

use std::sync::Arc;

use crate::{
    metadata::loader::{data::CilObjectData, MetadataLoader},
    prelude::{MethodDefRaw, TableId, Token},
    Result,
};

/// Loader for `MethodDef` metadata
pub(crate) struct MethodDefLoader;

impl MetadataLoader for MethodDefLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings), Some(blobs)) = (&data.meta, &data.strings, &data.blobs)
        {
            if let Some(table) = header.table::<MethodDefRaw>(TableId::MethodDef) {
                table.par_iter().try_for_each(|row| {
                    let type_params = if row.param_list == 0 || data.params.is_empty() {
                        Arc::new(boxcar::Vec::new())
                    } else {
                        let next_row_id = row.rid + 1;

                        let start = row.param_list as usize;
                        let end = if next_row_id > table.row_count() {
                            data.params.len() + 1
                        } else {
                            match table.get(next_row_id) {
                                Some(next_row) => next_row.param_list as usize,
                                None => {
                                    return Err(malformed_error!(
                                        "Failed to resolve param_end from next row - {}",
                                        next_row_id
                                    ))
                                }
                            }
                        };

                        if start > data.params.len() || end > (data.params.len() + 1) || end < start
                        {
                            Arc::new(boxcar::Vec::new())
                        } else {
                            let type_params = Arc::new(boxcar::Vec::with_capacity(end - start));
                            for counter in start..end {
                                let token_value =
                                    u32::try_from(counter | 0x0800_0000).map_err(|_| {
                                        malformed_error!(
                                            "Token value too large: {}",
                                            counter | 0x0800_0000
                                        )
                                    })?;
                                match data.params.get(&Token::new(token_value)) {
                                    Some(param) => _ = type_params.push(param.value().clone()),
                                    None => {
                                        return Err(malformed_error!(
                                            "Failed to resolve param - {}",
                                            counter | 0x0800_0000
                                        ))
                                    }
                                }
                            }

                            type_params
                        }
                    };

                    let res = row.to_owned(strings, blobs, type_params)?;
                    data.methods.insert(row.token, Arc::new(res));

                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodDef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Param]
    }
}
