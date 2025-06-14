//! `StandAloneSig` loader implementation

use std::sync::Arc;

use crate::{
    disassembler::VisitedMap,
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::StandAloneSigRaw,
    },
    prelude::TableId,
    Result,
};
use rayon::iter::{ParallelBridge, ParallelIterator};

/// Loader for `StandAloneSig` metadata
pub(crate) struct StandAloneSigLoader;

impl MetadataLoader for StandAloneSigLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blobs)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<StandAloneSigRaw>(TableId::StandAloneSig) {
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
