//! `StandAloneSig` loader implementation

use std::sync::{Arc, Mutex};

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::StandAloneSigRaw,
    },
    prelude::TableId,
    Result,
};
use rayon::iter::{ParallelBridge, ParallelIterator};

/// Loader for `StandAloneSig` metadata
pub(crate) struct StandAloneSigLoader;

impl MetadataLoader for StandAloneSigLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blobs)) = (&data.meta, &data.blobs) {
            if let Some(table) = header.table::<StandAloneSigRaw>(TableId::StandAloneSig) {
                let error = Arc::new(Mutex::new(None));

                data.methods.iter().par_bridge().for_each(|row| {
                    if lock!(error).is_some() {
                        return;
                    }

                    let method = row.value();
                    if let Err(err) = method.parse(&data.file, blobs, table, &data.types) {
                        let mut guard = lock!(error);
                        if guard.is_none() {
                            *guard = Some(err);
                        }
                    }
                });

                if let Some(err) = Arc::into_inner(error).unwrap().into_inner().unwrap() {
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::StandAloneSig
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
        ]
    }
}
