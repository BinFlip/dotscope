//! Embedded resources and manifest resource management for .NET assemblies.
//!
//! This module provides types and logic for parsing, storing, and accessing embedded resources
//! in .NET assemblies, including manifest resources, resource streams, and resource types.
//!
//! # Key Types
//! - [`Resources`] - Container for all resources in the assembly
//! - [`Resource`] - Parsed resource entry
//! - [`ManifestResourceRc`] - Reference-counted manifest resource
mod parser;
mod types;

use dashmap::DashMap;
pub use parser::Resource;
pub use types::*;

use std::sync::Arc;

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        streams::{
            AssemblyRefMap, FileMap, ManifestResourceRaw, ManifestResourceRc, Strings, TableId,
            TablesHeader,
        },
    },
    Result,
};

/// Container for all resources in the assembly.
///
/// Provides efficient lookup and management of embedded resources by name.
pub struct Resources {
    /// Reference to the originally loaded file
    file: Arc<File>,
    /// Map of all resources by name
    data: DashMap<String, ManifestResourceRc>,
}

impl Resources {
    /// Creates a new empty Resources container.
    ///
    /// # Arguments
    /// * `file` - The originally loaded file
    #[must_use]
    pub fn new(file: Arc<File>) -> Self {
        Resources {
            file,
            data: DashMap::new(),
        }
    }

    /// Gets a resource by name.
    ///
    /// # Arguments
    /// * `name` - The name of the resource to look for
    #[must_use]
    pub fn get(&self, name: &str) -> Option<ManifestResourceRc> {
        self.data.get(name).map(|entry| entry.clone())
    }

    /// Gets all resources.
    #[must_use]
    pub fn all(&self) -> &DashMap<String, ManifestResourceRc> {
        &self.data
    }

    /// Get a slice to the data of a resource.
    ///
    /// # Arguments
    /// * `resource` - The resources to read the data from
    #[must_use]
    pub fn get_data(&self, resource: &ManifestResourceRc) -> Option<&[u8]> {
        match resource.source {
            // ToDo: The only case we currently handle, is if the resource is embedded in the current file.
            //       Other cases, like File or AssemblyRef, will require us to implement loading multiple binaries
            //       and reading the data from there
            None => self
                .file
                .data_slice(resource.data_offset, resource.data_size)
                .ok(),
            _ => None,
        }
    }

    /// Loads resources from the `ManifestResource` table.
    ///
    /// # Arguments
    /// * `file`        - The mapped raw data of the loaded binary
    /// * `cor20`       - The cor20 header of the loaded binary
    /// * `strings`     - The #String heap
    /// * `tables`      - The table header of the metadata
    /// * `assemblies`  - The loaded `AssemblyRef` information
    /// * `files`       - The loaded `File` information
    ///
    /// # Errors
    /// Returns an error if the resource data cannot be read or parsed.
    pub fn load(
        &self,
        cor20: &Cor20Header,
        strings: &Strings,
        tables: &TablesHeader,
        assemblies: &AssemblyRefMap,
        files: &FileMap,
    ) -> Result<()> {
        if let Some(table) = tables.table::<ManifestResourceRaw>(TableId::ManifestResource) {
            for row in table {
                let manifest_resource =
                    row.to_owned(&self.file, cor20, strings, files, assemblies, table)?;
                self.data
                    .insert(manifest_resource.name.clone(), manifest_resource.clone());
            }
        }
        Ok(())
    }

    /// Returns the number of resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over all resources.
    ///
    /// Returns an iterator that yields references to each resource entry.
    #[must_use]
    pub fn iter(&self) -> dashmap::iter::Iter<String, ManifestResourceRc> {
        self.data.iter()
    }
}

impl<'a> IntoIterator for &'a Resources {
    type Item = dashmap::mapref::multiple::RefMulti<'a, String, ManifestResourceRc>;
    type IntoIter = dashmap::iter::Iter<'a, String, ManifestResourceRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
