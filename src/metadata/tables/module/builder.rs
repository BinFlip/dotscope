//! ModuleBuilder for creating Module metadata entries.
//!
//! This module provides [`ModuleBuilder`] for creating Module table entries
//! with a fluent API. Module entries define module identity information including
//! name, version identifier (Mvid), and Edit-and-Continue support for .NET assemblies.

use crate::{
    metadata::{
        cilassembly::BuilderContext,
        tables::{ModuleRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Module metadata entries.
///
/// `ModuleBuilder` provides a fluent API for creating Module table entries
/// with validation and automatic GUID management. Module entries define the
/// identity information for the current module including name, unique identifier,
/// and development support information.
///
/// # Module Identity Model
///
/// .NET modules follow a structured identity model:
/// - **Module Name**: Human-readable identifier for the module
/// - **Module Version ID (Mvid)**: GUID that uniquely identifies module versions
/// - **Generation**: Reserved field for future versioning (always 0)
/// - **Edit-and-Continue Support**: Optional GUIDs for development scenarios
///
/// # Module Table Characteristics
///
/// The Module table has unique characteristics:
/// - **Single Entry**: Always contains exactly one row per PE file
/// - **Foundation Table**: One of the first tables loaded with no dependencies
/// - **Identity Anchor**: Provides the base identity that other tables reference
/// - **Version Management**: Enables proper module version tracking and resolution
///
/// # Module Creation Scenarios
///
/// Different module creation patterns serve various development scenarios:
/// - **Basic Module**: Simple name and auto-generated Mvid
/// - **Versioned Module**: Explicit Mvid for version control integration
/// - **Development Module**: ENC support for Edit-and-Continue debugging
/// - **Production Module**: Optimized settings for release builds
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(&mut assembly);
///
/// // Create a basic module with auto-generated Mvid
/// let basic_module = ModuleBuilder::new()
///     .name("MyModule.dll")
///     .build(&mut context)?;
///
/// // Create a module with specific Mvid for version control
/// let versioned_module = ModuleBuilder::new()
///     .name("MyLibrary.dll")
///     .mvid(&[
///         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
///         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
///     ])
///     .build(&mut context)?;
///
/// // Create a module with Edit-and-Continue support for development
/// let dev_module = ModuleBuilder::new()
///     .name("DebugModule.dll")
///     .encid(&[
///         0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
///         0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
///     ])
///     .build(&mut context)?;
///
/// // Create a module with full development support
/// let full_dev_module = ModuleBuilder::new()
///     .name("FullDevModule.dll")
///     .generation(0) // Always 0 per ECMA-335
///     .mvid(&[
///         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
///         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
///     ])
///     .encid(&[
///         0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
///         0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
///     ])
///     .encbaseid(&[
///         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
///         0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
///     ])
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ModuleBuilder {
    generation: Option<u32>,
    name: Option<String>,
    mvid: Option<[u8; 16]>,
    encid: Option<[u8; 16]>,
    encbaseid: Option<[u8; 16]>,
}

impl Default for ModuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleBuilder {
    /// Creates a new ModuleBuilder.
    ///
    /// # Returns
    ///
    /// A new [`ModuleBuilder`] instance ready for configuration.
    pub fn new() -> Self {
        Self {
            generation: None,
            name: None,
            mvid: None,
            encid: None,
            encbaseid: None,
        }
    }

    /// Sets the generation number for the module.
    ///
    /// According to ECMA-335 §II.22.30, this field is reserved and shall always
    /// be zero. This method is provided for completeness but should typically
    /// not be called or should be called with 0.
    ///
    /// # Arguments
    ///
    /// * `generation` - The generation number (should be 0)
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ModuleBuilder;
    /// let builder = ModuleBuilder::new()
    ///     .generation(0); // Always 0 per ECMA-335
    /// ```
    pub fn generation(mut self, generation: u32) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Sets the name of the module.
    ///
    /// Specifies the human-readable name for the module, typically matching
    /// the filename of the PE file. This name is stored in the string heap
    /// and used for module identification and debugging purposes.
    ///
    /// # Arguments
    ///
    /// * `name` - The module name (typically ends with .dll or .exe)
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ModuleBuilder;
    /// let builder = ModuleBuilder::new()
    ///     .name("MyLibrary.dll");
    /// ```
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the Module Version Identifier (Mvid) GUID.
    ///
    /// The Mvid is a GUID that uniquely identifies different versions of the
    /// same module. Each compilation typically generates a new Mvid, enabling
    /// proper version tracking and module resolution in complex scenarios.
    ///
    /// # Arguments
    ///
    /// * `mvid` - The 16-byte GUID for module version identification
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ModuleBuilder;
    /// let builder = ModuleBuilder::new()
    ///     .mvid(&[
    ///         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ///         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    ///     ]);
    /// ```
    pub fn mvid(mut self, mvid: &[u8; 16]) -> Self {
        self.mvid = Some(*mvid);
        self
    }

    /// Sets the Edit-and-Continue identifier GUID.
    ///
    /// The EncId provides support for Edit-and-Continue debugging scenarios
    /// where code can be modified during debugging sessions. This GUID helps
    /// track and manage incremental changes during development.
    ///
    /// # Arguments
    ///
    /// * `encid` - The 16-byte GUID for Edit-and-Continue identification
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ModuleBuilder;
    /// let builder = ModuleBuilder::new()
    ///     .encid(&[
    ///         0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    ///         0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ///     ]);
    /// ```
    pub fn encid(mut self, encid: &[u8; 16]) -> Self {
        self.encid = Some(*encid);
        self
    }

    /// Sets the Edit-and-Continue base identifier GUID.
    ///
    /// The EncBaseId provides support for tracking the base version in
    /// Edit-and-Continue scenarios. This GUID identifies the original
    /// version before any incremental modifications were applied.
    ///
    /// # Arguments
    ///
    /// * `encbaseid` - The 16-byte GUID for Edit-and-Continue base identification
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ModuleBuilder;
    /// let builder = ModuleBuilder::new()
    ///     .encbaseid(&[
    ///         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ///         0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    ///     ]);
    /// ```
    pub fn encbaseid(mut self, encbaseid: &[u8; 16]) -> Self {
        self.encbaseid = Some(*encbaseid);
        self
    }

    /// Builds the Module entry and adds it to the assembly.
    ///
    /// Validates all required fields, adds the module name to the string heap,
    /// adds any GUIDs to the GUID heap, creates the ModuleRaw structure, and
    /// adds it to the assembly's Module table. Returns a token that can be
    /// used to reference this module.
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for heap and table management
    ///
    /// # Returns
    ///
    /// Returns a `Result<Token>` containing the token for the new Module entry,
    /// or an error if validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - `name` is not specified (required field)
    /// - String heap operations fail
    /// - GUID heap operations fail
    /// - Table operations fail
    /// - The Module table already contains an entry (modules are unique)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(&mut assembly);
    /// let token = ModuleBuilder::new()
    ///     .name("MyModule.dll")
    ///     .build(&mut context)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "name field is required".to_string(),
            })?;

        let existing_count = context.next_rid(TableId::Module) - 1;
        if existing_count > 0 {
            return Err(crate::Error::ModificationInvalidOperation {
                details: "Module table already contains an entry. Only one module per assembly is allowed.".to_string(),
            });
        }

        let name_index = context.add_string(&name)?;

        let mvid_index = if let Some(mvid) = self.mvid {
            context.add_guid(&mvid)?
        } else {
            let new_mvid = generate_random_guid();
            context.add_guid(&new_mvid)?
        };

        let encid_index = if let Some(encid) = self.encid {
            context.add_guid(&encid)?
        } else {
            0 // 0 indicates no EncId
        };

        let encbaseid_index = if let Some(encbaseid) = self.encbaseid {
            context.add_guid(&encbaseid)?
        } else {
            0 // 0 indicates no EncBaseId
        };

        let rid = context.next_rid(TableId::Module);
        let token = Token::new((TableId::Module as u32) << 24 | rid);

        let module_raw = ModuleRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            generation: self.generation.unwrap_or(0), // Always 0 per ECMA-335
            name: name_index,
            mvid: mvid_index,
            encid: encid_index,
            encbaseid: encbaseid_index,
        };

        let table_data = TableDataOwned::Module(module_raw);
        context.add_table_row(TableId::Module, table_data)?;

        Ok(token)
    }
}

/// Generates a random GUID for module identification.
///
/// This is a simple GUID generator for when no specific Mvid is provided.
fn generate_random_guid() -> [u8; 16] {
    // For now, generate a simple deterministic GUID based on timestamp and counter
    // In production, this should use a proper GUID generation library
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(1);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
    let combined = timestamp.wrapping_add(counter);

    let mut guid = [0u8; 16];
    guid[0..8].copy_from_slice(&combined.to_le_bytes());
    guid[8..16].copy_from_slice(&(!combined).to_le_bytes());

    guid[6] = (guid[6] & 0x0F) | 0x40; // Version 4
    guid[8] = (guid[8] & 0x3F) | 0x80; // Variant 10

    guid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{cilassembly::CilAssembly, cilassemblyview::CilAssemblyView};
    use std::path::PathBuf;

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        Ok(CilAssembly::new(view))
    }

    #[test]
    fn test_module_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        // Note: WindowsBase.dll already has a Module entry, so this should fail
        let result = ModuleBuilder::new()
            .name("TestModule.dll")
            .build(&mut context);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Module table already contains an entry"));
        Ok(())
    }

    #[test]
    fn test_module_builder_with_mvid() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        let mvid = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];

        let result = ModuleBuilder::new()
            .name("TestModule.dll")
            .mvid(&mvid)
            .build(&mut context);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Module table already contains an entry"));
        Ok(())
    }

    #[test]
    fn test_module_builder_with_enc_support() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        let encid = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ];
        let encbaseid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];

        let result = ModuleBuilder::new()
            .name("DebugModule.dll")
            .encid(&encid)
            .encbaseid(&encbaseid)
            .build(&mut context);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Module table already contains an entry"));
        Ok(())
    }

    #[test]
    fn test_module_builder_missing_name() {
        let mut assembly = get_test_assembly().unwrap();
        let mut context = BuilderContext::new(&mut assembly);

        let result = ModuleBuilder::new().build(&mut context);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name field is required"));
    }

    #[test]
    fn test_module_builder_generation() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        let result = ModuleBuilder::new()
            .name("TestModule.dll")
            .generation(0) // Should always be 0 per ECMA-335
            .build(&mut context);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Module table already contains an entry"));
        Ok(())
    }

    #[test]
    fn test_module_builder_default() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        // Test Default trait implementation
        let result = ModuleBuilder::default()
            .name("DefaultModule.dll")
            .build(&mut context);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Module table already contains an entry"));
        Ok(())
    }

    #[test]
    fn test_guid_generation() {
        let guid1 = generate_random_guid();
        let guid2 = generate_random_guid();

        // GUIDs should be different
        assert_ne!(guid1, guid2);

        // Verify GUID version and variant bits
        assert_eq!(guid1[6] & 0xF0, 0x40); // Version 4
        assert_eq!(guid1[8] & 0xC0, 0x80); // Variant 10
        assert_eq!(guid2[6] & 0xF0, 0x40); // Version 4
        assert_eq!(guid2[8] & 0xC0, 0x80); // Variant 10
    }

    // Note: To properly test ModuleBuilder functionality, we would need to create
    // an empty assembly without an existing Module entry. These tests demonstrate
    // the validation logic working correctly with an existing module.
}
