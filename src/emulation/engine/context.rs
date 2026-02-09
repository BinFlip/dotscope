//! Emulation context providing access to assembly metadata.
//!
//! The [`EmulationContext`] provides the interpreter with access to
//! the loaded assembly's metadata, instructions, and strings.

use std::sync::Arc;

use crate::{
    assembly::Instruction,
    emulation::{engine::error::EmulationError, exception::ExceptionClause},
    metadata::{
        imports::{Import, ImportSourceId, ImportType},
        method::{Method, MethodModifiers},
        signatures::{SignatureMethod, SignatureTypeSpec, TypeSignature},
        tables::{
            MemberRef, MethodSpec, MethodSpecRc, StandAloneSigRaw, StandAloneSignature,
            TableAccess, TypeSpecRaw,
        },
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeReference, PointerSize},
    },
    prelude::ExceptionHandlerFlags,
    CilObject, Result,
};

/// Context for emulation providing access to assembly metadata.
///
/// The emulation context wraps a [`CilObject`] and provides convenient
/// access to methods, instructions, and strings needed during emulation.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::emulation::EmulationContext;
/// use dotscope::CilObject;
///
/// let assembly = Arc::new(CilObject::from_path("test.dll")?);
/// let context = EmulationContext::new(assembly);
///
/// // Get method body
/// let method = context.get_method(method_token)?;
///
/// // Get user string
/// let s = context.get_user_string(string_index)?;
/// ```
pub struct EmulationContext {
    /// The loaded assembly.
    assembly: Arc<CilObject>,
}

impl EmulationContext {
    /// Creates a new emulation context.
    #[must_use]
    pub fn new(assembly: Arc<CilObject>) -> Self {
        EmulationContext { assembly }
    }

    /// Returns a reference to the underlying assembly.
    #[must_use]
    pub fn assembly(&self) -> Arc<CilObject> {
        self.assembly.clone()
    }

    /// Gets a method by its token.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method token is not found.
    pub fn get_method(&self, token: Token) -> Result<Arc<Method>> {
        self.assembly
            .methods()
            .get(&token)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| EmulationError::MethodNotFound { token }.into())
    }

    /// Gets the instructions for a method.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no body.
    pub fn get_instructions(&self, method_token: Token) -> Result<Vec<Instruction>> {
        let method = self.get_method(method_token)?;

        // Get instructions from the method's blocks
        let instructions: Vec<Instruction> = method.instructions().cloned().collect();
        if instructions.is_empty() && method.body.get().is_none() {
            return Err(EmulationError::MissingMethodBody {
                token: method_token,
            }
            .into());
        }
        Ok(instructions)
    }

    /// Gets the base RVA (address of the first instruction) of a method.
    ///
    /// This is used to convert between absolute RVAs and method-relative offsets.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no instructions.
    pub fn get_method_base_rva(&self, method_token: Token) -> Result<u64> {
        let instructions = self.get_instructions(method_token)?;
        instructions.first().map(|instr| instr.rva).ok_or_else(|| {
            EmulationError::MissingMethodBody {
                token: method_token,
            }
            .into()
        })
    }

    /// Converts an absolute RVA to a method-relative offset.
    ///
    /// Branch targets in CIL are stored as absolute RVAs, but the instruction
    /// pointer uses method-relative offsets. This function converts between them.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found.
    /// Method-relative offsets are bounded by IL method body size (< u32::MAX)
    #[allow(clippy::cast_possible_truncation)]
    pub fn rva_to_method_offset(&self, method_token: Token, rva: u64) -> Result<u32> {
        let base_rva = self.get_method_base_rva(method_token)?;
        let offset = rva.saturating_sub(base_rva);
        Ok(offset as u32)
    }

    /// Gets an instruction at a specific method-relative offset.
    ///
    /// The offset is relative to the start of the method's IL code (0 = first instruction).
    /// This is the offset used by CIL branch instructions and the instruction pointer.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or no instruction exists at the offset.
    pub fn get_instruction_at(&self, method_token: Token, offset: u32) -> Result<Instruction> {
        let instructions = self.get_instructions(method_token)?;

        // Get the base RVA to compute method-relative offsets from RVAs
        // Branch targets are stored as absolute RVAs and converted to method offsets
        // using rva_to_method_offset(target_rva - base_rva), so we need to match
        // instructions by their RVA-based offset, not accumulated instruction sizes
        let base_rva = instructions
            .first()
            .map(|instr| instr.rva)
            .ok_or(EmulationError::InvalidInstructionPointer { offset })?;

        // Find instruction at the given method-relative offset using RVA
        for instr in instructions {
            let instr_offset = instr.rva.saturating_sub(base_rva);
            if instr_offset == u64::from(offset) {
                return Ok(instr);
            }
        }

        Err(EmulationError::InvalidInstructionPointer { offset }.into())
    }

    /// Gets an instruction by index within a method's instruction list.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or the index is out of bounds.
    pub fn get_instruction_by_index(
        &self,
        method_token: Token,
        index: usize,
    ) -> Result<Instruction> {
        let instructions = self.get_instructions(method_token)?;

        instructions.into_iter().nth(index).ok_or_else(|| {
            EmulationError::InvalidInstructionPointer {
                offset: u32::try_from(index).unwrap_or(u32::MAX),
            }
            .into()
        })
    }

    /// Gets a user string from the #US heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::UserStringNotFound`] if the string is not found.
    pub fn get_user_string(&self, index: u32) -> Result<String> {
        let userstrings = self
            .assembly
            .userstrings()
            .ok_or(EmulationError::UserStringNotFound { index })?;

        let idx =
            usize::try_from(index).map_err(|_| EmulationError::UserStringNotFound { index })?;

        let string_data = userstrings
            .get(idx)
            .map_err(|_| EmulationError::UserStringNotFound { index })?;

        Ok(string_data.to_string_lossy())
    }

    /// Gets the local variable types for a method.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    /// Returns [`EmulationError::TypeNotFound`] if a local variable's type reference is dead.
    pub fn get_local_types(&self, method_token: Token) -> Result<Vec<CilFlavor>> {
        let method = self.get_method(method_token)?;

        // Get locals from the method's local_vars field
        // boxcar::Vec iter returns (index, &value) tuples
        let mut locals = Vec::new();
        for (index, local) in method.local_vars.iter() {
            let Ok(idx) = u16::try_from(index) else {
                continue; // Skip locals with index > u16::MAX
            };

            // Resolve the type from the CilTypeRef
            let cil_flavor = match local.base.upgrade() {
                Some(cil_type) => cil_type.flavor().clone(),
                None => {
                    // Type reference is dead - this is an error condition
                    return Err(EmulationError::TypeNotFound {
                        method_token,
                        local_index: idx,
                    }
                    .into());
                }
            };

            locals.push(cil_flavor);
        }

        Ok(locals)
    }

    /// Checks if a method returns a value (non-void).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn method_returns_value(&self, method_token: Token) -> Result<bool> {
        let method = self.get_method(method_token)?;

        // Check the return type from the method signature (it's in .base field)
        Ok(!matches!(
            method.signature.return_type.base,
            TypeSignature::Void
        ))
    }

    /// Gets the return type of a method as a CilFlavor.
    ///
    /// Returns `None` if the method returns void.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_return_type(&self, method_token: Token) -> Result<Option<CilFlavor>> {
        let method = self.get_method(method_token)?;

        if matches!(method.signature.return_type.base, TypeSignature::Void) {
            Ok(None)
        } else {
            Ok(Some(CilFlavor::from(&method.signature.return_type.base)))
        }
    }

    /// Gets the parameter types for a method as CilFlavors.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_parameter_types(&self, method_token: Token) -> Result<Vec<CilFlavor>> {
        let method = self.get_method(method_token)?;

        Ok(method
            .signature
            .params
            .iter()
            .map(|param| CilFlavor::from(&param.base))
            .collect())
    }

    /// Gets the maximum stack size for a method.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found, has no body, or has invalid metadata.
    pub fn get_max_stack(&self, method_token: Token) -> Result<u16> {
        let method = self.get_method(method_token)?;

        let body = method.body.get().ok_or(EmulationError::MissingMethodBody {
            token: method_token,
        })?;

        u16::try_from(body.max_stack).map_err(|_| {
            EmulationError::InvalidMethodMetadata {
                token: method_token,
                reason: "max_stack exceeds u16::MAX",
            }
            .into()
        })
    }

    /// Converts a type token to a CilFlavor.
    ///
    /// This handles TypeDef, TypeRef, and TypeSpec tokens, resolving them
    /// to the appropriate CIL flavor type for emulation.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::UnresolvedTypeToken`] if the type cannot be resolved
    /// and the token table is not a recognized type table.
    pub fn type_token_to_cil_flavor(&self, token: Token) -> Result<CilFlavor> {
        if let Some(cil_type) = self.assembly.types().get(&token) {
            return Ok(cil_type.flavor().clone());
        }

        Err(EmulationError::UnresolvedTypeToken { token }.into())
    }

    /// Gets the parameter count for a method.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_parameter_count(&self, method_token: Token) -> Result<usize> {
        let method = self.get_method(method_token)?;
        Ok(method.params.count())
    }

    /// Checks if a method is static.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn is_static_method(&self, method_token: Token) -> Result<bool> {
        let method = self.get_method(method_token)?;
        Ok(method.flags_modifiers.contains(MethodModifiers::STATIC))
    }

    /// Gets a type by its token.
    ///
    /// Returns the [`CilType`] for the given token if it exists in the
    /// assembly's type registry.
    ///
    /// # Returns
    ///
    /// `Some(CilTypeRc)` if the type is found, `None` otherwise.
    #[must_use]
    pub fn get_type(&self, type_token: Token) -> Option<CilTypeRc> {
        self.assembly.types().get(&type_token)
    }

    /// Gets a type by namespace and name.
    ///
    /// Searches the assembly's type registry for a type with the given
    /// qualified name.
    ///
    /// # Returns
    ///
    /// `Some(CilTypeRc)` if the type is found, `None` otherwise.
    #[must_use]
    pub fn get_type_by_name(&self, namespace: &str, name: &str) -> Option<CilTypeRc> {
        let fullname = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{namespace}.{name}")
        };
        self.assembly.types().get_by_fullname(&fullname, true)
    }

    /// Checks if one type is compatible with (assignable to) another.
    ///
    /// This uses the full .NET type compatibility rules including:
    /// - Exact type matching
    /// - Inheritance compatibility (subtype checking)
    /// - Interface implementation
    /// - Primitive type widening
    /// - Reference types to System.Object
    ///
    /// # Arguments
    ///
    /// * `source_token` - Token of the source type (the value's type)
    /// * `target_token` - Token of the target type (the expected type)
    ///
    /// # Returns
    ///
    /// `true` if the source type can be assigned to the target type.
    /// Returns `true` if either type cannot be resolved (permissive fallback).
    #[must_use]
    pub fn is_type_compatible(&self, source_token: Token, target_token: Token) -> bool {
        // Same token is always compatible
        if source_token == target_token {
            return true;
        }

        // Try to resolve both types
        let Some(source_type) = self.get_type(source_token) else {
            return true; // Permissive if source type unknown
        };

        let Some(target_type) = self.get_type(target_token) else {
            return true; // Permissive if target type unknown
        };

        // Use CilType's is_compatible_with method
        source_type.is_compatible_with(&target_type)
    }

    /// Checks if a type is compatible with another type using CilType references.
    ///
    /// This is a convenience method that takes resolved CilType references
    /// instead of tokens.
    #[must_use]
    pub fn is_type_compatible_ref(source: &CilType, target: &CilType) -> bool {
        source.is_compatible_with(target)
    }

    /// Gets the declaring type of a method.
    ///
    /// For a method token, returns the type that declares the method.
    /// This is useful for `newobj` to get the type being instantiated
    /// from the constructor token.
    ///
    /// # Returns
    ///
    /// `Some(CilTypeRc)` if the declaring type is found, `None` otherwise.
    #[must_use]
    pub fn get_declaring_type(&self, method_token: Token) -> Option<CilTypeRc> {
        // Search through all types to find the one that declares this method
        for type_info in self.assembly.types().all_types() {
            for (_, method_ref) in type_info.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    if method.token == method_token {
                        return self.assembly.types().get(&type_info.token);
                    }
                }
            }
        }
        None
    }

    /// Gets the declaring type token of a method.
    ///
    /// Returns just the token instead of the full type, which is useful
    /// when you only need the type token for heap allocation.
    ///
    /// # Returns
    ///
    /// `Some(Token)` if the declaring type is found, `None` otherwise.
    #[must_use]
    pub fn get_declaring_type_token(&self, method_token: Token) -> Option<Token> {
        for type_info in self.assembly.types().all_types() {
            for (_, method_ref) in type_info.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    if method.token == method_token {
                        return Some(type_info.token);
                    }
                }
            }
        }
        None
    }

    /// Gets the declaring type of a field.
    ///
    /// For a field token, returns the type that declares the field.
    /// This is useful for finding the type whose static constructor needs
    /// to be run before accessing static fields.
    ///
    /// # Returns
    ///
    /// `Some(CilTypeRc)` if the declaring type is found, `None` otherwise.
    #[must_use]
    pub fn get_declaring_type_of_field(&self, field_token: Token) -> Option<CilTypeRc> {
        // Search through all types to find the one that declares this field
        for type_info in self.assembly.types().all_types() {
            for (_, field_rc) in type_info.fields.iter() {
                if field_rc.token == field_token {
                    return self.assembly.types().get(&type_info.token);
                }
            }
        }
        None
    }

    /// Gets the declaring type token of a field.
    ///
    /// Returns just the token instead of the full type, which is useful
    /// when you only need the type token for type initialization checks.
    ///
    /// # Returns
    ///
    /// `Some(Token)` if the declaring type is found, `None` otherwise.
    #[must_use]
    pub fn get_declaring_type_token_of_field(&self, field_token: Token) -> Option<Token> {
        for type_info in self.assembly.types().all_types() {
            for (_, field_rc) in type_info.fields.iter() {
                if field_rc.token == field_token {
                    return Some(type_info.token);
                }
            }
        }
        None
    }

    /// Finds the static constructor (.cctor) for a type.
    ///
    /// The static constructor is a special method named ".cctor" that is
    /// called automatically by the runtime before any static member of
    /// the type is accessed.
    ///
    /// # Arguments
    ///
    /// * `type_token` - Token of the type to find the .cctor for
    ///
    /// # Returns
    ///
    /// `Some(Token)` if the type has a static constructor, `None` otherwise.
    #[must_use]
    pub fn find_type_cctor(&self, type_token: Token) -> Option<Token> {
        let type_info = self.assembly.types().get(&type_token)?;

        // Search through the type's methods for .cctor
        for (_, method_ref) in type_info.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                if method.name == ".cctor" {
                    return Some(method.token);
                }
            }
        }
        None
    }

    /// Checks if a method is virtual.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn is_virtual_method(&self, method_token: Token) -> Result<bool> {
        let method = self.get_method(method_token)?;
        Ok(method.flags_modifiers.contains(MethodModifiers::VIRTUAL))
    }

    /// Resolves a virtual method call to a concrete implementation.
    ///
    /// Given a virtual method token and the runtime type of the object,
    /// this resolves to the actual method that should be called based on
    /// the type hierarchy.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The declared virtual method being called
    /// * `runtime_type` - The actual runtime type of the object
    ///
    /// # Returns
    ///
    /// The token of the method to actually call. If virtual dispatch cannot
    /// be resolved (type unknown, method not overridden), returns the original
    /// method token.
    #[must_use]
    pub fn resolve_virtual_call(&self, method_token: Token, runtime_type: Token) -> Token {
        // Get the method being called
        let Ok(method) = self.get_method(method_token) else {
            return method_token;
        };

        // Not virtual? Return as-is
        if !method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
            return method_token;
        }

        let method_name = &method.name;

        // Get the runtime type
        let Some(runtime_type_info) = self.get_type(runtime_type) else {
            return method_token;
        };

        // Search for an override in the runtime type
        if let Some(override_token) =
            Self::find_method_override(&runtime_type_info, method_name, &method)
        {
            return override_token;
        }

        // No override found, return original
        method_token
    }

    /// Finds a method override in a type hierarchy.
    ///
    /// Searches for a virtual method override that matches both the name and
    /// signature of the base method. This ensures proper override resolution
    /// and avoids matching methods that merely hide the base method.
    fn find_method_override(
        type_info: &CilType,
        method_name: &str,
        base_method: &Method,
    ) -> Option<Token> {
        // First check the type itself for a matching override
        for (_, method_ref) in type_info.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                if method.name == method_name
                    && method.flags_modifiers.contains(MethodModifiers::VIRTUAL)
                    && Self::signatures_match(&method.signature, &base_method.signature)
                {
                    return Some(method.token);
                }
            }
        }

        // Check base types (inheritance chain)
        if let Some(base) = type_info.base() {
            return Self::find_method_override(&base, method_name, base_method);
        }

        None
    }

    /// Checks if two method signatures are compatible for override purposes.
    ///
    /// Two signatures match if they have the same parameter count and
    /// compatible parameter types. Return type covariance is allowed per
    /// ECMA-335 but we use exact matching for simplicity.
    fn signatures_match(candidate: &SignatureMethod, base: &SignatureMethod) -> bool {
        // Parameter count must match
        if candidate.param_count != base.param_count {
            return false;
        }

        // Generic parameter count must match
        if candidate.param_count_generic != base.param_count_generic {
            return false;
        }

        // Parameter types must match (compare each parameter)
        if candidate.params.len() != base.params.len() {
            return false;
        }

        for (candidate_param, base_param) in candidate.params.iter().zip(base.params.iter()) {
            if candidate_param.base != base_param.base {
                return false;
            }
        }

        // All checks passed - signatures are compatible
        true
    }

    /// Gets type information useful for casting operations.
    ///
    /// Returns the type's namespace and name, which is useful for
    /// error messages in cast failures.
    #[must_use]
    pub fn get_type_name(&self, type_token: Token) -> Option<(String, String)> {
        self.get_type(type_token)
            .map(|t| (t.namespace.clone(), t.name.clone()))
    }

    /// Formats a type token as a readable string for error messages.
    ///
    /// Returns "Namespace.Name" if the type is known, or "0x{token:08X}"
    /// if the type cannot be resolved.
    #[must_use]
    pub fn format_type_token(&self, type_token: Token) -> String {
        if let Some(type_info) = self.get_type(type_token) {
            if type_info.namespace.is_empty() {
                type_info.name.clone()
            } else {
                format!("{}.{}", type_info.namespace, type_info.name)
            }
        } else {
            format!("0x{:08X}", type_token.value())
        }
    }

    /// Checks if a type is a value type.
    ///
    /// Value types (structs, enums, primitives) are copied by value
    /// rather than by reference.
    #[must_use]
    pub fn is_value_type(&self, type_token: Token) -> bool {
        self.get_type(type_token)
            .is_some_and(|t| t.flavor().is_value_type())
    }

    /// Checks if a type is a reference type.
    ///
    /// Reference types (classes, interfaces, arrays) are passed by reference.
    #[must_use]
    pub fn is_reference_type(&self, type_token: Token) -> bool {
        self.get_type(type_token)
            .is_none_or(|t| t.flavor().is_reference_type()) // Default to reference type if unknown
    }

    /// Checks if a type is an interface.
    #[must_use]
    pub fn is_interface(&self, type_token: Token) -> bool {
        self.get_type(type_token)
            .is_some_and(|t| t.flavor() == &CilFlavor::Interface)
    }

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
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dotscope::emulation::EmulationContext;
    /// use dotscope::CilObject;
    /// use std::sync::Arc;
    ///
    /// let assembly = Arc::new(CilObject::from_path("assembly.dll")?);
    /// let context = EmulationContext::new(assembly);
    ///
    /// // Find a specific method
    /// if let Some(token) = context.find_method("MyNamespace", "MyClass", "MyMethod") {
    ///     let method = context.get_method(token)?;
    ///     println!("Found method: {}", method.name);
    /// }
    /// ```
    #[must_use]
    pub fn find_method(
        &self,
        type_namespace: &str,
        type_name: &str,
        method_name: &str,
    ) -> Option<Token> {
        // First find the type
        let cil_type = self.get_type_by_name(type_namespace, type_name)?;

        // Then search for the method in that type
        for (_, method_ref) in cil_type.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                if method.name == method_name {
                    return Some(method.token);
                }
            }
        }

        None
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

        let mut tokens = Vec::new();
        for (_, method_ref) in cil_type.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                if method.name == method_name {
                    tokens.push(method.token);
                }
            }
        }

        tokens
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

        for (_, method_ref) in cil_type.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                if method.name == method_name
                    && method.flags_modifiers.contains(MethodModifiers::STATIC)
                {
                    return Some(method.token);
                }
            }
        }

        None
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

    /// Gets a MemberRef by its token.
    ///
    /// MemberRef entries represent external method or field references
    /// (e.g., calls to BCL methods like `System.String.Concat`).
    ///
    /// # Returns
    ///
    /// The MemberRef if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_member_ref(&self, token: Token) -> Option<Arc<MemberRef>> {
        self.assembly
            .refs_members()
            .get(&token)
            .map(|e| e.value().clone())
    }

    /// Gets a method specification by its token.
    ///
    /// MethodSpec entries represent generic method instantiations with concrete
    /// type arguments (e.g., calls to `List<T>.Add` with `T = int`).
    ///
    /// # Arguments
    ///
    /// * `token` - A MethodSpec metadata token (table 0x2B)
    ///
    /// # Returns
    ///
    /// The MethodSpec if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_method_spec(&self, token: Token) -> Option<MethodSpecRc> {
        self.assembly
            .method_specs()
            .get(&token)
            .map(|e| e.value().clone())
    }

    /// Resolves a MethodSpec token to its underlying method token.
    ///
    /// For generic method instantiations, this extracts the token of the actual
    /// method being called (either a MethodDef or MemberRef).
    ///
    /// # Arguments
    ///
    /// * `method_spec` - The MethodSpec to resolve
    ///
    /// # Returns
    ///
    /// The token of the underlying method, or `None` if resolution fails.
    #[must_use]
    pub fn resolve_method_spec_to_token(method_spec: &MethodSpec) -> Option<Token> {
        match &method_spec.method {
            CilTypeReference::MethodDef(method_ref) => method_ref.upgrade().map(|m| m.token),
            CilTypeReference::MemberRef(member_ref) => Some(member_ref.token),
            _ => None,
        }
    }

    /// Gets a standalone signature by its token.
    ///
    /// Standalone signatures are used for:
    /// - `calli` instructions (method call site signatures)
    /// - Local variable declarations
    /// - Function pointer types
    ///
    /// # Arguments
    ///
    /// * `token` - A StandAloneSig metadata token (table 0x11)
    ///
    /// # Returns
    ///
    /// The parsed signature if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_standalone_signature(&self, token: Token) -> Option<StandAloneSignature> {
        let tables = self.assembly.tables()?;
        let blob = self.assembly.blob()?;
        let table = <_ as TableAccess<StandAloneSigRaw>>::table(tables)?;
        let row = token.row();
        let raw_sig = table.get(row)?;
        // Parse the raw signature using the blob heap
        let owned_sig = raw_sig.to_owned(blob).ok()?;
        Some(owned_sig.parsed_signature.clone())
    }

    /// Gets the signature of a TypeSpec by its token.
    ///
    /// TypeSpec entries represent complex types through signatures in the blob heap,
    /// including generic instantiations, array types, and type parameters.
    ///
    /// # Arguments
    ///
    /// * `token` - A TypeSpec metadata token (table 0x1B)
    ///
    /// # Returns
    ///
    /// The parsed TypeSpec signature if found, or `None` if the token doesn't exist.
    #[must_use]
    pub fn get_typespec_signature(&self, token: Token) -> Option<SignatureTypeSpec> {
        // Only handle TypeSpec tokens (table 0x1B)
        if token.table() != 0x1B {
            return None;
        }

        let tables = self.assembly.tables()?;
        let blob = self.assembly.blob()?;
        let table = <_ as TableAccess<TypeSpecRaw>>::table(tables)?;
        let row = token.row();
        let raw_typespec = table.get(row)?;
        // Parse the raw signature using the blob heap
        let owned_typespec = raw_typespec.to_owned(blob).ok()?;
        Some(owned_typespec.signature.clone())
    }

    /// Finds a P/Invoke import by the method it's associated with.
    ///
    /// P/Invoke imports are used for calling native code from managed code.
    /// This searches the assembly's imports to find one matching the given
    /// method token.
    ///
    /// # Arguments
    ///
    /// * `method_token` - Token of the method to find imports for
    ///
    /// # Returns
    ///
    /// The import information if found, or `None` if no import exists
    /// for this method.
    #[must_use]
    pub fn find_import_by_method(&self, method_token: Token) -> Option<Arc<Import>> {
        for import_entry in self.assembly.imports().cil().iter() {
            let import = import_entry.value();
            if let ImportType::Method(import_method) = &import.import {
                if import_method.token == method_token {
                    return Some(import.clone());
                }
            }
        }
        None
    }

    /// Gets the DLL/module name from a P/Invoke import.
    ///
    /// For imports from external modules (P/Invoke), this returns the DLL name
    /// (e.g., "kernel32.dll"). For other import types, returns `None`.
    ///
    /// # Arguments
    ///
    /// * `import` - The import to get the DLL name from
    ///
    /// # Returns
    ///
    /// The DLL name if this is a ModuleRef-sourced import, or `None` otherwise.
    #[must_use]
    pub fn get_import_dll_name(&self, import: &Import) -> Option<String> {
        match import.source_id {
            ImportSourceId::ModuleRef(token) => self
                .assembly
                .imports()
                .cil()
                .get_module_ref(token)
                .map(|module_ref| module_ref.name.clone()),
            _ => None,
        }
    }

    /// Extracts type name and namespace from a MemberRef's parent type reference.
    ///
    /// This is useful for identifying the declaring type of external method
    /// references without having to manually handle weak reference upgrades.
    ///
    /// # Arguments
    ///
    /// * `member_ref` - The MemberRef to extract type info from
    ///
    /// # Returns
    ///
    /// A tuple of (namespace, name), or `None` if the type reference is invalid.
    #[must_use]
    pub fn get_member_ref_type_info(member_ref: &MemberRef) -> Option<(String, String)> {
        use crate::metadata::typesystem::CilTypeReference;

        match &member_ref.declaredby {
            CilTypeReference::TypeRef(cil_type_ref)
            | CilTypeReference::TypeDef(cil_type_ref)
            | CilTypeReference::TypeSpec(cil_type_ref) => cil_type_ref
                .upgrade()
                .map(|t| (t.namespace.clone(), t.name.clone())),
            _ => None,
        }
    }

    /// Gets the full type name from a MemberRef's parent type reference.
    ///
    /// Returns the fully qualified type name (e.g., "System.String") or
    /// extracts what's available from the reference.
    ///
    /// # Arguments
    ///
    /// * `member_ref` - The MemberRef to extract type name from
    ///
    /// # Returns
    ///
    /// The type name string, or "Unknown" if the reference is invalid.
    #[must_use]
    pub fn get_member_ref_type_name(member_ref: &MemberRef) -> String {
        use crate::metadata::typesystem::CilTypeReference;

        match &member_ref.declaredby {
            CilTypeReference::TypeRef(cil_type_ref)
            | CilTypeReference::TypeDef(cil_type_ref)
            | CilTypeReference::TypeSpec(cil_type_ref) => {
                if let Some(cil_type) = cil_type_ref.upgrade() {
                    if cil_type.namespace.is_empty() {
                        cil_type.name.clone()
                    } else {
                        format!("{}.{}", cil_type.namespace, cil_type.name)
                    }
                } else {
                    "Unknown".to_string()
                }
            }
            CilTypeReference::ModuleRef(m) => m.name.clone(),
            _ => "Unknown".to_string(),
        }
    }

    /// Gets the token from a MemberRef's parent type reference.
    ///
    /// # Arguments
    ///
    /// * `member_ref` - The MemberRef to extract token from
    ///
    /// # Returns
    ///
    /// The type token if the reference is valid, or `None` otherwise.
    #[must_use]
    pub fn get_member_ref_type_token(member_ref: &MemberRef) -> Option<Token> {
        use crate::metadata::typesystem::CilTypeReference;

        match &member_ref.declaredby {
            CilTypeReference::TypeRef(cil_type_ref)
            | CilTypeReference::TypeDef(cil_type_ref)
            | CilTypeReference::TypeSpec(cil_type_ref) => cil_type_ref.upgrade().map(|t| t.token),
            CilTypeReference::ModuleRef(m) => Some(m.token),
            _ => None,
        }
    }

    /// Gets the size of a type in bytes for the sizeof instruction.
    ///
    /// This method computes the size based on:
    /// 1. Explicit `ClassLayout.class_size` if defined for the type
    /// 2. Primitive type sizes based on the `CilFlavor`
    /// 3. A default pointer-sized value for unknown types
    ///
    /// # Arguments
    ///
    /// * `type_token` - Token of the type to get size for
    /// * `ptr_size` - Target pointer size for native int/uint types
    ///
    /// # Returns
    ///
    /// The size of the type in bytes.
    #[must_use]
    pub fn get_type_size(&self, type_token: Token, ptr_size: PointerSize) -> usize {
        // Try to get the type from the registry
        if let Some(cil_type) = self.get_type(type_token) {
            // First check for explicit ClassLayout size
            if let Some(&explicit_size) = cil_type.class_size.get() {
                return explicit_size as usize;
            }

            // Otherwise compute from the flavor
            return Self::flavor_to_size(cil_type.flavor(), ptr_size);
        }

        // Default size for unknown types (pointer-sized)
        ptr_size.bytes()
    }

    /// Computes the size in bytes for a CilFlavor.
    ///
    /// # Arguments
    ///
    /// * `flavor` - The CIL type flavor
    /// * `ptr_size` - Target pointer size for native int/uint and reference types
    ///
    /// # Returns
    ///
    /// The size in bytes for the given flavor.
    #[must_use]
    pub fn flavor_to_size(flavor: &CilFlavor, ptr_size: PointerSize) -> usize {
        match flavor {
            CilFlavor::Void => 0,
            CilFlavor::Boolean | CilFlavor::I1 | CilFlavor::U1 => 1,
            CilFlavor::Char | CilFlavor::I2 | CilFlavor::U2 => 2,
            CilFlavor::I4 | CilFlavor::U4 | CilFlavor::R4 => 4,
            CilFlavor::I8 | CilFlavor::U8 | CilFlavor::R8 => 8,
            // TypedRef is two pointers (value + type)
            CilFlavor::TypedRef { .. } => ptr_size.bytes() * 2,
            // Pointer-sized types (native ints, reference types, and other types)
            _ => ptr_size.bytes(),
        }
    }

    /// Converts exception handlers from metadata format to emulation format.
    fn convert_exception_handlers(&self, method_token: Token) -> Result<Vec<ExceptionClause>> {
        let method = self.get_method(method_token)?;
        let body = method.body.get().ok_or(EmulationError::MissingMethodBody {
            token: method_token,
        })?;

        let mut clauses = Vec::new();
        for handler in &body.exception_handlers {
            let clause = if handler.flags == ExceptionHandlerFlags::EXCEPTION {
                // Catch clause - get the type token from the handler field
                let catch_type = handler
                    .handler
                    .as_ref()
                    .map(|t| t.token)
                    .unwrap_or_else(|| Token::new(handler.filter_offset));

                ExceptionClause::Catch {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                    catch_type,
                }
            } else if handler.flags == ExceptionHandlerFlags::FILTER {
                ExceptionClause::Filter {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                    filter_offset: handler.filter_offset,
                }
            } else if handler.flags == ExceptionHandlerFlags::FINALLY {
                ExceptionClause::Finally {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                }
            } else if handler.flags == ExceptionHandlerFlags::FAULT {
                ExceptionClause::Fault {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                }
            } else {
                // Unknown handler type - skip it
                continue;
            };
            clauses.push(clause);
        }

        Ok(clauses)
    }
}
