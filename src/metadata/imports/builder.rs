//! Builder for native PE imports that integrates with the dotscope builder pattern.
//!
//! This module provides [`NativeImportsBuilder`] for creating native PE import tables
//! with a fluent API. The builder follows the established dotscope pattern of not holding
//! references to BuilderContext and instead taking it as a parameter to the build() method.

use crate::{cilassembly::BuilderContext, Result};

/// Builder for creating native PE import tables.
///
/// `NativeImportsBuilder` provides a fluent API for creating native PE import tables
/// with validation and automatic integration into the assembly. The builder follows
/// the established dotscope pattern where the context is passed to build() rather
/// than being held by the builder.
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::imports::NativeImportsBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// NativeImportsBuilder::new()
///     .add_dll("kernel32.dll")
///     .add_function("kernel32.dll", "GetCurrentProcessId")
///     .add_function("kernel32.dll", "ExitProcess")
///     .add_dll("user32.dll")
///     .add_function_by_ordinal("user32.dll", 120) // MessageBoxW
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct NativeImportsBuilder {
    /// DLLs to add to the import table
    dlls: Vec<String>,

    /// Named function imports to add (dll_name, function_name)
    functions: Vec<(String, String)>,

    /// Ordinal function imports to add (dll_name, ordinal)
    ordinal_functions: Vec<(String, u16)>,
}

impl NativeImportsBuilder {
    /// Creates a new native imports builder.
    ///
    /// # Returns
    ///
    /// A new [`NativeImportsBuilder`] ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dlls: Vec::new(),
            functions: Vec::new(),
            ordinal_functions: Vec::new(),
        }
    }

    /// Adds a DLL to the import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// Multiple calls with the same DLL name will reuse the existing descriptor.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL (e.g., "kernel32.dll", "user32.dll")
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let builder = NativeImportsBuilder::new()
    ///     .add_dll("kernel32.dll")
    ///     .add_dll("user32.dll");
    /// ```
    #[must_use]
    pub fn add_dll(mut self, dll_name: impl Into<String>) -> Self {
        let dll_name = dll_name.into();
        if !self.dlls.contains(&dll_name) {
            self.dlls.push(dll_name);
        }
        self
    }

    /// Adds a named function import from a specific DLL.
    ///
    /// Adds a named function import to the specified DLL's import descriptor.
    /// The DLL will be automatically added if it hasn't been added already.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `function_name` - Name of the function to import
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let builder = NativeImportsBuilder::new()
    ///     .add_function("kernel32.dll", "GetCurrentProcessId")
    ///     .add_function("kernel32.dll", "ExitProcess");
    /// ```
    #[must_use]
    pub fn add_function(
        mut self,
        dll_name: impl Into<String>,
        function_name: impl Into<String>,
    ) -> Self {
        let dll_name = dll_name.into();
        let function_name = function_name.into();

        // Ensure DLL is added
        if !self.dlls.contains(&dll_name) {
            self.dlls.push(dll_name.clone());
        }

        self.functions.push((dll_name, function_name));
        self
    }

    /// Adds an ordinal-based function import.
    ///
    /// Adds a function import that uses ordinal-based lookup instead of name-based.
    /// This can be more efficient but is less portable across DLL versions.
    /// The DLL will be automatically added if it hasn't been added already.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `ordinal` - Ordinal number of the function in the DLL's export table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let builder = NativeImportsBuilder::new()
    ///     .add_function_by_ordinal("user32.dll", 120); // MessageBoxW
    /// ```
    #[must_use]
    pub fn add_function_by_ordinal(mut self, dll_name: impl Into<String>, ordinal: u16) -> Self {
        let dll_name = dll_name.into();

        // Ensure DLL is added
        if !self.dlls.contains(&dll_name) {
            self.dlls.push(dll_name.clone());
        }

        self.ordinal_functions.push((dll_name, ordinal));
        self
    }

    /// Builds the native imports and integrates them into the assembly.
    ///
    /// This method validates the configuration and integrates all specified DLLs and
    /// functions into the assembly through the BuilderContext. The builder automatically
    /// handles DLL dependency management and function import setup.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for assembly modification
    ///
    /// # Returns
    ///
    /// `Ok(())` if the import table was created successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DLL names are invalid or empty
    /// - Function names are invalid or empty
    /// - Ordinal values are invalid (0)
    /// - Duplicate functions are specified
    /// - Integration with the assembly fails
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::imports::NativeImportsBuilder;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// NativeImportsBuilder::new()
    ///     .add_dll("kernel32.dll")
    ///     .add_function("kernel32.dll", "GetCurrentProcessId")
    ///     .build(&mut context)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<()> {
        // Add all DLLs first
        for dll_name in &self.dlls {
            context.add_native_import_dll(dll_name)?;
        }

        // Add all named functions
        for (dll_name, function_name) in &self.functions {
            context.add_native_import_function(dll_name, function_name)?;
        }

        // Add all ordinal functions
        for (dll_name, ordinal) in &self.ordinal_functions {
            context.add_native_import_function_by_ordinal(dll_name, *ordinal)?;
        }

        Ok(())
    }
}

impl Default for NativeImportsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
    };
    use std::path::PathBuf;

    #[test]
    fn test_native_imports_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = NativeImportsBuilder::new()
                .add_dll("kernel32.dll")
                .add_function("kernel32.dll", "GetCurrentProcessId")
                .add_function("kernel32.dll", "ExitProcess")
                .build(&mut context);

            // Should succeed with current placeholder implementation
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_native_imports_builder_with_ordinals() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = NativeImportsBuilder::new()
                .add_dll("user32.dll")
                .add_function_by_ordinal("user32.dll", 120) // MessageBoxW
                .add_function("user32.dll", "GetWindowTextW")
                .build(&mut context);

            // Should succeed with current placeholder implementation
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_native_imports_builder_auto_dll_addition() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = NativeImportsBuilder::new()
                // Don't explicitly add DLL - should be added automatically
                .add_function("kernel32.dll", "GetCurrentProcessId")
                .add_function_by_ordinal("user32.dll", 120)
                .build(&mut context);

            // Should succeed - DLLs should be added automatically
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_native_imports_builder_empty() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = NativeImportsBuilder::new().build(&mut context);

            // Should succeed even with no imports
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_native_imports_builder_duplicate_dlls() {
        let builder = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .add_dll("kernel32.dll") // Duplicate should be ignored
            .add_dll("user32.dll");

        // Should contain only 2 unique DLLs
        assert_eq!(builder.dlls.len(), 2);
        assert!(builder.dlls.contains(&"kernel32.dll".to_string()));
        assert!(builder.dlls.contains(&"user32.dll".to_string()));
    }

    #[test]
    fn test_native_imports_builder_fluent_api() {
        let builder = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .add_function("kernel32.dll", "GetCurrentProcessId")
            .add_function("kernel32.dll", "ExitProcess")
            .add_dll("user32.dll")
            .add_function_by_ordinal("user32.dll", 120);

        // Verify builder state
        assert_eq!(builder.dlls.len(), 2);
        assert_eq!(builder.functions.len(), 2);
        assert_eq!(builder.ordinal_functions.len(), 1);

        assert!(builder.dlls.contains(&"kernel32.dll".to_string()));
        assert!(builder.dlls.contains(&"user32.dll".to_string()));

        assert!(builder.functions.contains(&(
            "kernel32.dll".to_string(),
            "GetCurrentProcessId".to_string()
        )));
        assert!(builder
            .functions
            .contains(&("kernel32.dll".to_string(), "ExitProcess".to_string())));

        assert!(builder
            .ordinal_functions
            .contains(&("user32.dll".to_string(), 120)));
    }
}
