//! Name-based method and constructor lookup for the emulation context.
//!
//! Provides search methods that find methods by type namespace, type name,
//! and method name strings.

use crate::{emulation::engine::context::EmulationContext, metadata::token::Token};

impl EmulationContext {
    /// Finds a method by its declaring type name and method name.
    ///
    /// This searches through all types in the assembly to find a method
    /// matching the specified criteria. Useful for locating methods
    /// to emulate without knowing their metadata token.
    ///
    /// # Arguments
    ///
    /// * `type_namespace` - The namespace of the declaring type (e.g., "System")
    /// * `type_name` - The name of the declaring type (e.g., "String")
    /// * `method_name` - The name of the method to find (e.g., "Concat")
    ///
    /// # Returns
    ///
    /// The method's token if found, or `None` if no matching method exists.
    #[must_use]
    pub fn find_method(
        &self,
        type_namespace: &str,
        type_name: &str,
        method_name: &str,
    ) -> Option<Token> {
        // First find the type
        let cil_type = self.get_type_by_name(type_namespace, type_name)?;

        cil_type.find_method(method_name).map(|m| m.token)
    }

    /// Finds all methods matching a given name in a type.
    ///
    /// This is useful for finding overloaded methods where multiple
    /// methods share the same name but have different signatures.
    ///
    /// # Arguments
    ///
    /// * `type_namespace` - The namespace of the declaring type
    /// * `type_name` - The name of the declaring type
    /// * `method_name` - The name of the methods to find
    ///
    /// # Returns
    ///
    /// A vector of method tokens for all matching methods.
    #[must_use]
    pub fn find_methods(
        &self,
        type_namespace: &str,
        type_name: &str,
        method_name: &str,
    ) -> Vec<Token> {
        let Some(cil_type) = self.get_type_by_name(type_namespace, type_name) else {
            return Vec::new();
        };

        cil_type
            .find_methods(method_name)
            .iter()
            .map(|m| m.token)
            .collect()
    }

    /// Finds a static method by type and name.
    ///
    /// This is a convenience method that finds a method and verifies
    /// it is static. Useful for finding entry points or utility methods.
    ///
    /// # Arguments
    ///
    /// * `type_namespace` - The namespace of the declaring type
    /// * `type_name` - The name of the declaring type
    /// * `method_name` - The name of the method to find
    ///
    /// # Returns
    ///
    /// The method's token if found and static, or `None` otherwise.
    #[must_use]
    pub fn find_static_method(
        &self,
        type_namespace: &str,
        type_name: &str,
        method_name: &str,
    ) -> Option<Token> {
        let cil_type = self.get_type_by_name(type_namespace, type_name)?;
        cil_type
            .find_method(method_name)
            .filter(|m| m.is_static())
            .map(|m| m.token)
    }

    /// Finds an instance constructor for a type.
    ///
    /// Instance constructors in .NET are named ".ctor". This method finds
    /// the constructor for object instantiation.
    ///
    /// # Arguments
    ///
    /// * `type_namespace` - The namespace of the type
    /// * `type_name` - The name of the type
    ///
    /// # Returns
    ///
    /// The constructor's token if found, or `None` if the type has no constructor.
    #[must_use]
    pub fn find_constructor(&self, type_namespace: &str, type_name: &str) -> Option<Token> {
        self.find_method(type_namespace, type_name, ".ctor")
    }

    /// Finds all constructors for a type.
    ///
    /// Types can have multiple constructors with different parameters.
    /// This returns all of them.
    ///
    /// # Returns
    ///
    /// A vector of constructor tokens.
    #[must_use]
    pub fn find_constructors(&self, type_namespace: &str, type_name: &str) -> Vec<Token> {
        self.find_methods(type_namespace, type_name, ".ctor")
    }
}
