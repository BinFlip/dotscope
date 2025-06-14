//! Assembly and AssemblyRef builders for creating mock assembly references
//!
//! This module provides builders for creating AssemblyRef instances with
//! realistic metadata including versioning, culture, and hash information.

use std::sync::{atomic::AtomicU32, Arc};

use crate::metadata::{
    tables::{AssemblyRef, AssemblyRefHash, AssemblyRefRc},
    token::Token,
};

/// Builder for creating mock AssemblyRef instances with realistic metadata
pub struct AssemblyRefBuilder {
    rid: u32,
    name: String,
    culture: Option<String>,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    revision_number: u32,
    flags: u32,
    hash: Option<AssemblyRefHash>,
}

impl AssemblyRefBuilder {
    pub fn new() -> Self {
        Self {
            rid: 1,
            name: "TestAssembly".to_string(),
            culture: None,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            hash: None,
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

    pub fn with_version(mut self, major: u32, minor: u32, build: u32, revision: u32) -> Self {
        self.major_version = major;
        self.minor_version = minor;
        self.build_number = build;
        self.revision_number = revision;
        self
    }

    pub fn with_culture(mut self, culture: &str) -> Self {
        self.culture = Some(culture.to_string());
        self
    }

    pub fn with_hash(mut self, hash_bytes: &[u8]) -> Self {
        self.hash = AssemblyRefHash::new(hash_bytes).ok();
        self
    }

    /// Create a .NET Framework-style assembly reference
    pub fn dotnet_framework(name: &str) -> Self {
        Self::new()
            .with_name(name)
            .with_version(4, 0, 0, 0)
            .with_hash(&[1, 2, 3, 4, 5, 6, 7, 8])
    }

    /// Create a .NET Core-style assembly reference
    pub fn dotnet_core(name: &str) -> Self {
        Self::new().with_name(name).with_version(6, 0, 0, 0)
    }

    pub fn build(self) -> AssemblyRefRc {
        Arc::new(AssemblyRef {
            rid: self.rid,
            token: Token::new(0x23000000 + self.rid),
            offset: self.rid as usize,
            name: self.name,
            culture: self.culture,
            major_version: self.major_version,
            minor_version: self.minor_version,
            build_number: self.build_number,
            revision_number: self.revision_number,
            flags: self.flags,
            identifier: None,
            hash: self.hash,
            os_platform_id: AtomicU32::new(0),
            os_major_version: AtomicU32::new(0),
            os_minor_version: AtomicU32::new(0),
            processor: AtomicU32::new(0),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        })
    }
}

impl Default for AssemblyRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}
