//! Builder for constructing `AssemblyOS` table entries
//!
//! This module provides the [`crate::metadata::tables::assemblyos::builder::AssemblyOSBuilder`] which enables fluent construction
//! of `AssemblyOS` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let os_token = AssemblyOSBuilder::new()
//!     .os_platform_id(1)             // Windows platform
//!     .os_major_version(10)          // Windows 10
//!     .os_minor_version(0)           // Windows 10.0
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{AssemblyOsRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `AssemblyOS` table entries
///
/// Provides a fluent interface for building `AssemblyOS` metadata table entries.
/// These entries specify operating system targeting information for assemblies,
/// though they are rarely used in modern .NET applications which rely on runtime
/// platform abstraction.
///
/// # Required Fields
/// - `os_platform_id`: Operating system platform identifier
/// - `os_major_version`: Major version number of the target OS
/// - `os_minor_version`: Minor version number of the target OS
///
/// # Historical Context
///
/// The AssemblyOS table was designed for early .NET Framework scenarios where
/// assemblies might need explicit OS compatibility declarations. Modern applications
/// typically rely on runtime platform abstraction instead of metadata-level OS targeting.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Windows 10 targeting
/// let win10_os = AssemblyOSBuilder::new()
///     .os_platform_id(1)    // Windows platform
///     .os_major_version(10)  // Windows 10
///     .os_minor_version(0)   // Windows 10.0
///     .build(&mut context)?;
///
/// // Windows 7 targeting
/// let win7_os = AssemblyOSBuilder::new()
///     .os_platform_id(1)    // Windows platform
///     .os_major_version(6)   // Windows 7
///     .os_minor_version(1)   // Windows 7.1
///     .build(&mut context)?;
///
/// // Custom OS targeting
/// let custom_os = AssemblyOSBuilder::new()
///     .os_platform_id(99)    // Custom platform
///     .os_major_version(1)    // Major version
///     .os_minor_version(0)    // Minor version
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)]
pub struct AssemblyOSBuilder {
    /// Operating system platform identifier
    os_platform_id: Option<u32>,
    /// Major version number of the target OS
    os_major_version: Option<u32>,
    /// Minor version number of the target OS
    os_minor_version: Option<u32>,
}

impl AssemblyOSBuilder {
    /// Creates a new `AssemblyOSBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide all required fields before calling build().
    ///
    /// # Returns
    /// A new `AssemblyOSBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyOSBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            os_platform_id: None,
            os_major_version: None,
            os_minor_version: None,
        }
    }

    /// Sets the operating system platform identifier
    ///
    /// Specifies the target operating system platform. While ECMA-335 doesn't
    /// standardize exact values, common historical identifiers include
    /// Windows, Unix, and other platform designations.
    ///
    /// # Parameters
    /// - `os_platform_id`: The operating system platform identifier
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Common Values
    /// - `1`: Windows platforms
    /// - `2`: Unix/Linux platforms  
    /// - `3`: macOS platforms
    /// - Custom values for proprietary platforms
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Windows platform
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_platform_id(1);
    ///
    /// // Unix/Linux platform
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_platform_id(2);
    /// ```
    #[must_use]
    pub fn os_platform_id(mut self, os_platform_id: u32) -> Self {
        self.os_platform_id = Some(os_platform_id);
        self
    }

    /// Sets the major version number of the target OS
    ///
    /// Specifies the major version of the target operating system.
    /// Combined with minor version to specify exact OS version requirements.
    ///
    /// # Parameters
    /// - `os_major_version`: The major version number
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Windows 10 (major version 10)
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_major_version(10);
    ///
    /// // Windows 7 (major version 6)
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_major_version(6);
    /// ```
    #[must_use]
    pub fn os_major_version(mut self, os_major_version: u32) -> Self {
        self.os_major_version = Some(os_major_version);
        self
    }

    /// Sets the minor version number of the target OS
    ///
    /// Specifies the minor version of the target operating system.
    /// Combined with major version to specify exact OS version requirements.
    ///
    /// # Parameters
    /// - `os_minor_version`: The minor version number
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Windows 10.0 (minor version 0)
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_minor_version(0);
    ///
    /// // Windows 7.1 (minor version 1)
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_minor_version(1);
    /// ```
    #[must_use]
    pub fn os_minor_version(mut self, os_minor_version: u32) -> Self {
        self.os_minor_version = Some(os_minor_version);
        self
    }

    /// Builds and adds the `AssemblyOS` entry to the metadata
    ///
    /// Validates all required fields, creates the `AssemblyOS` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this assembly OS entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created assembly OS entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (os_platform_id, os_major_version, or os_minor_version)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = AssemblyOSBuilder::new()
    ///     .os_platform_id(1)
    ///     .os_major_version(10)
    ///     .os_minor_version(0)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let os_platform_id =
            self.os_platform_id
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "OS platform identifier is required for AssemblyOS".to_string(),
                })?;

        let os_major_version =
            self.os_major_version
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "OS major version is required for AssemblyOS".to_string(),
                })?;

        let os_minor_version =
            self.os_minor_version
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "OS minor version is required for AssemblyOS".to_string(),
                })?;

        let next_rid = context.next_rid(TableId::AssemblyOS);
        let token_value = ((TableId::AssemblyOS as u32) << 24) | next_rid;
        let token = Token::new(token_value);

        let assembly_os = AssemblyOsRaw {
            rid: next_rid,
            token,
            offset: 0,
            os_platform_id,
            os_major_version,
            os_minor_version,
        };

        context.table_row_add(TableId::AssemblyOS, TableDataOwned::AssemblyOS(assembly_os))?;
        Ok(token)
    }
}

impl Default for AssemblyOSBuilder {
    /// Creates a default `AssemblyOSBuilder`
    ///
    /// Equivalent to calling [`AssemblyOSBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::BuilderContext, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_assemblyos_builder_new() {
        let builder = AssemblyOSBuilder::new();

        assert!(builder.os_platform_id.is_none());
        assert!(builder.os_major_version.is_none());
        assert!(builder.os_minor_version.is_none());
    }

    #[test]
    fn test_assemblyos_builder_default() {
        let builder = AssemblyOSBuilder::default();

        assert!(builder.os_platform_id.is_none());
        assert!(builder.os_major_version.is_none());
        assert!(builder.os_minor_version.is_none());
    }

    #[test]
    fn test_assemblyos_builder_windows10() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(10) // Windows 10
            .os_minor_version(0) // Windows 10.0
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_windows7() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(6) // Windows 7
            .os_minor_version(1) // Windows 7.1
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_linux() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyOSBuilder::new()
            .os_platform_id(2) // Unix/Linux
            .os_major_version(5) // Linux kernel 5
            .os_minor_version(4) // Linux kernel 5.4
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_custom() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyOSBuilder::new()
            .os_platform_id(99) // Custom platform
            .os_major_version(1) // Custom major
            .os_minor_version(0) // Custom minor
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_missing_platform_id() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = AssemblyOSBuilder::new()
            .os_major_version(10)
            .os_minor_version(0)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("OS platform identifier is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_missing_major_version() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = AssemblyOSBuilder::new()
            .os_platform_id(1)
            .os_minor_version(0)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("OS major version is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_missing_minor_version() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = AssemblyOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("OS minor version is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_clone() {
        let builder = AssemblyOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .os_minor_version(0);

        let cloned = builder.clone();
        assert_eq!(builder.os_platform_id, cloned.os_platform_id);
        assert_eq!(builder.os_major_version, cloned.os_major_version);
        assert_eq!(builder.os_minor_version, cloned.os_minor_version);
    }

    #[test]
    fn test_assemblyos_builder_debug() {
        let builder = AssemblyOSBuilder::new()
            .os_platform_id(2)
            .os_major_version(5)
            .os_minor_version(4);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyOSBuilder"));
        assert!(debug_str.contains("os_platform_id"));
        assert!(debug_str.contains("os_major_version"));
        assert!(debug_str.contains("os_minor_version"));
    }

    #[test]
    fn test_assemblyos_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = AssemblyOSBuilder::new()
            .os_platform_id(3)
            .os_major_version(12)
            .os_minor_version(5)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first OS entry
        let token1 = AssemblyOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(10)
            .os_minor_version(0)
            .build(&mut context)
            .expect("Should build first OS entry");

        // Build second OS entry
        let token2 = AssemblyOSBuilder::new()
            .os_platform_id(2) // Unix/Linux
            .os_major_version(5)
            .os_minor_version(4)
            .build(&mut context)
            .expect("Should build second OS entry");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_zero_values() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyOSBuilder::new()
            .os_platform_id(0) // Zero platform
            .os_major_version(0) // Zero major
            .os_minor_version(0) // Zero minor
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_max_values() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyOSBuilder::new()
            .os_platform_id(u32::MAX) // Max platform
            .os_major_version(u32::MAX) // Max major
            .os_minor_version(u32::MAX) // Max minor
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyOS as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }
}
