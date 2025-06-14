use crate::metadata::{
    imports::{ImportContainer, ImportRc, Imports},
    token::Token,
};
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `File`
pub type FileMap = SkipMap<Token, FileRc>;
/// A vector that holds a list of `File`
pub type FileList = Arc<boxcar::Vec<FileRc>>;
/// A reference to a `File`
pub type FileRc = Arc<File>;

#[allow(non_snake_case)]
/// All possible flags for `FileAttributes`
pub mod FileAttributes {
    /// This is not a resource file
    pub const CONTAINS_META_DATA: u32 = 0x0000;
    /// This is a resource file or other non-metadata-containing file
    pub const CONTAINS_NO_META_DATA: u32 = 0x0001;
}

impl ImportContainer for Arc<File> {
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_file(self)
    }
}
