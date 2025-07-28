//! # File Builder
//!
//! Provides a fluent API for building File table entries that describe files in multi-file assemblies.
//! The File table contains information about additional files that are part of the assembly but
//! stored separately from the main manifest, including modules, resources, and native libraries.
//!
//! ## Overview
//!
//! The `FileBuilder` enables creation of file entries with:
//! - File name specification (required)
//! - File attributes configuration (metadata vs. resource files)
//! - Hash value for integrity verification
//! - Automatic heap management and token generation
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a module file reference
//! let module_token = FileBuilder::new()
//!     .name("MyModule.netmodule")
//!     .contains_metadata()
//!     .hash_value(&[0x12, 0x34, 0x56, 0x78])
//!     .build(&mut context)?;
//!
//! // Create a resource file reference
//! let resource_token = FileBuilder::new()
//!     .name("Resources.resources")
//!     .contains_no_metadata()
//!     .hash_value(&[0xAB, 0xCD, 0xEF, 0x01])
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: File name is required
//! - **Heap Management**: Strings and blobs are automatically added to heaps
//! - **Token Generation**: Metadata tokens are created automatically
//! - **File Type Support**: Methods for specifying metadata vs. resource files

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{FileAttributes, FileRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating File table entries.
///
/// `FileBuilder` provides a fluent API for creating entries in the File
/// metadata table, which contains information about files that are part
/// of multi-file assemblies.
///
/// # Purpose
///
/// The File table serves several key functions:
/// - **Multi-file Assembly Support**: Lists additional files in assemblies
/// - **Module References**: References to .netmodule files with executable code
/// - **Resource Files**: References to .resources files with binary data
/// - **Native Libraries**: References to unmanaged DLLs for P/Invoke
/// - **Integrity Verification**: Hash values for file validation
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing File entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let hash_bytes = vec![0x01, 0x02, 0x03, 0x04]; // Example hash
///
/// let file_token = FileBuilder::new()
///     .name("MyLibrary.netmodule")
///     .contains_metadata()
///     .hash_value(&hash_bytes)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: A file name must be provided
/// - **Name Not Empty**: File names cannot be empty strings
/// - **Hash Format**: Hash values can be empty but must be valid blob data
///
/// # Integration
///
/// File entries integrate with other metadata structures:
/// - **ManifestResource**: Resources can reference files
/// - **ExportedType**: Types can be forwarded to files
/// - **Assembly Loading**: Runtime uses file information for loading
#[derive(Debug, Clone, Default)]
pub struct FileBuilder {
    /// The name of the file
    name: Option<String>,
    /// File attribute flags
    flags: u32,
    /// Hash value for integrity verification
    hash_value: Option<Vec<u8>>,
}

impl FileBuilder {
    /// Creates a new `FileBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods. File attributes default to
    /// `CONTAINS_META_DATA` (0x0000).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FileBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: FileAttributes::CONTAINS_META_DATA, // Default to metadata file
            hash_value: None,
        }
    }

    /// Sets the name of the file.
    ///
    /// The file name typically includes the file extension (e.g.,
    /// "MyModule.netmodule", "Resources.resources").
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the file
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FileBuilder::new()
    ///     .name("MyLibrary.netmodule");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets file attributes using a bitmask.
    ///
    /// File attributes specify the type and characteristics of the file.
    /// Use the `FileAttributes` constants for standard values.
    ///
    /// # Arguments
    ///
    /// * `flags` - File attributes bitmask
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FileBuilder::new()
    ///     .flags(FileAttributes::CONTAINS_NO_META_DATA);
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Marks the file as containing .NET metadata.
    ///
    /// This is appropriate for .netmodule files and other executable
    /// modules that contain .NET metadata and can define types and methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FileBuilder::new()
    ///     .name("MyModule.netmodule")
    ///     .contains_metadata();
    /// ```
    #[must_use]
    pub fn contains_metadata(mut self) -> Self {
        self.flags |= FileAttributes::CONTAINS_META_DATA;
        self.flags &= !FileAttributes::CONTAINS_NO_META_DATA;
        self
    }

    /// Marks the file as containing no .NET metadata.
    ///
    /// This is appropriate for resource files, images, configuration data,
    /// or unmanaged libraries that do not contain .NET metadata.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FileBuilder::new()
    ///     .name("Resources.resources")
    ///     .contains_no_metadata();
    /// ```
    #[must_use]
    pub fn contains_no_metadata(mut self) -> Self {
        self.flags |= FileAttributes::CONTAINS_NO_META_DATA;
        self.flags &= !FileAttributes::CONTAINS_META_DATA;
        self
    }

    /// Sets the hash value for file integrity verification.
    ///
    /// The hash value is used to verify that the file hasn't been tampered
    /// with or corrupted. This is typically a SHA-1 or SHA-256 hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash data for verification
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let hash = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    /// let builder = FileBuilder::new()
    ///     .hash_value(&hash);
    /// ```
    #[must_use]
    pub fn hash_value(mut self, hash: &[u8]) -> Self {
        self.hash_value = Some(hash.to_vec());
        self
    }

    /// Builds the File entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings and blobs to
    /// the appropriate heaps, creates the File table entry, and returns
    /// the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created File entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file name is not set
    /// - The file name is empty
    /// - There are issues adding strings or blobs to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    ///
    /// let file_token = FileBuilder::new()
    ///     .name("MyModule.netmodule")
    ///     .contains_metadata()
    ///     .build(&mut context)?;
    ///
    /// println!("Created File with token: {}", file_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "File name is required for File".to_string(),
            })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "File name cannot be empty for File".to_string(),
            });
        }

        let name_index = context.string_get_or_add(&name)?;

        let hash_value_index = if let Some(hash) = self.hash_value {
            if hash.is_empty() {
                0
            } else {
                context.blob_add(&hash)?
            }
        } else {
            0
        };

        let rid = context.next_rid(TableId::File);
        let token = Token::new(((TableId::File as u32) << 24) | rid);

        let file = FileRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags: self.flags,
            name: name_index,
            hash_value: hash_value_index,
        };

        let table_data = TableDataOwned::File(file);
        context.table_row_add(TableId::File, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::FileAttributes, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_file_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = FileBuilder::new()
            .name("MyModule.netmodule")
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_default() -> Result<()> {
        let builder = FileBuilder::default();
        assert!(builder.name.is_none());
        assert_eq!(builder.flags, FileAttributes::CONTAINS_META_DATA);
        assert!(builder.hash_value.is_none());
        Ok(())
    }

    #[test]
    fn test_file_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = FileBuilder::new().contains_metadata().build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("File name is required"));

        Ok(())
    }

    #[test]
    fn test_file_builder_empty_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = FileBuilder::new().name("").build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("File name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_file_builder_contains_metadata() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = FileBuilder::new()
            .name("Module.netmodule")
            .contains_metadata()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_contains_no_metadata() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = FileBuilder::new()
            .name("Resources.resources")
            .contains_no_metadata()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_with_hash_value() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let hash = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let token = FileBuilder::new()
            .name("HashedFile.dll")
            .hash_value(&hash)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_with_flags() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = FileBuilder::new()
            .name("CustomFile.data")
            .flags(FileAttributes::CONTAINS_NO_META_DATA)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_multiple_files() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token1 = FileBuilder::new()
            .name("Module1.netmodule")
            .contains_metadata()
            .build(&mut context)?;

        let token2 = FileBuilder::new()
            .name("Resources.resources")
            .contains_no_metadata()
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(token1, token2);
        assert_eq!(token1.table(), TableId::File as u8);
        assert_eq!(token2.table(), TableId::File as u8);
        assert_eq!(token2.row(), token1.row() + 1);

        Ok(())
    }

    #[test]
    fn test_file_builder_comprehensive() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let hash = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

        let token = FileBuilder::new()
            .name("ComprehensiveModule.netmodule")
            .contains_metadata()
            .hash_value(&hash)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test fluent API chaining
        let token = FileBuilder::new()
            .name("FluentFile.resources")
            .contains_no_metadata()
            .hash_value(&[0x11, 0x22, 0x33, 0x44])
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_file_builder_clone() {
        let builder1 = FileBuilder::new().name("CloneTest.dll").contains_metadata();
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.flags, builder2.flags);
        assert_eq!(builder1.hash_value, builder2.hash_value);
    }

    #[test]
    fn test_file_builder_debug() {
        let builder = FileBuilder::new().name("DebugFile.netmodule");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("FileBuilder"));
        assert!(debug_str.contains("DebugFile.netmodule"));
    }

    #[test]
    fn test_file_builder_empty_hash() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = FileBuilder::new()
            .name("NoHashFile.dll")
            .hash_value(&[]) // Empty hash should work
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::File as u8);
        assert!(token.row() > 0);

        Ok(())
    }
}
