//! File and ModuleRef builders for creating mock file and module references
//!
//! This module provides builders for creating File and ModuleRef instances
//! with realistic metadata for testing scenarios.

use std::sync::Arc;

use crate::metadata::{
    customattributes::CustomAttributeValue,
    tables::{AssemblyRefHash, File, FileRc, ModuleRef, ModuleRefRc},
    token::Token,
};

/// Builder for creating mock ModuleRef instances with various configurations
pub struct ModuleRefBuilder {
    rid: u32,
    name: String,
    custom_attributes: Option<Arc<boxcar::Vec<Arc<CustomAttributeValue>>>>,
}

impl ModuleRefBuilder {
    pub fn new() -> Self {
        Self {
            rid: 1,
            name: "TestModule".to_string(),
            custom_attributes: None,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn build(self) -> ModuleRefRc {
        Arc::new(ModuleRef {
            rid: self.rid,
            offset: self.rid as usize,
            token: Token::new(0x1A000000 + self.rid),
            name: self.name,
            custom_attributes: self
                .custom_attributes
                .unwrap_or_else(|| Arc::new(boxcar::Vec::<Arc<CustomAttributeValue>>::new())),
        })
    }
}

impl Default for ModuleRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating mock File instances
pub struct FileBuilder {
    rid: u32,
    name: String,
    flags: u32,
    hash_value: Option<AssemblyRefHash>,
}

impl FileBuilder {
    pub fn new() -> Self {
        Self {
            rid: 1,
            name: "TestFile.dll".to_string(),
            flags: 0,
            hash_value: None,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn with_hash(mut self, hash_bytes: &[u8]) -> Self {
        self.hash_value = AssemblyRefHash::new(hash_bytes).ok();
        self
    }

    pub fn build(self) -> FileRc {
        Arc::new(File {
            rid: self.rid,
            token: Token::new(0x26000000 + self.rid),
            offset: self.rid as usize,
            flags: self.flags,
            name: self.name,
            hash_value: self
                .hash_value
                .unwrap_or_else(|| AssemblyRefHash::new(&[1, 2, 3, 4]).unwrap()),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        })
    }
}

impl Default for FileBuilder {
    fn default() -> Self {
        Self::new()
    }
}
