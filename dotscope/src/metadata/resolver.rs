//! Cross-table token resolver for .NET metadata.
//!
//! Provides [`TokenResolver`](crate::metadata::resolver::TokenResolver), a lightweight
//! borrowing wrapper over [`CilObject`](crate::CilObject) that normalizes token references
//! across metadata tables. This includes:
//!
//! - **TypeRef → TypeDef**: Resolves external type references to their local definitions
//! - **MemberRef → MethodDef**: Resolves member references to locally defined methods
//! - **MemberRef → FieldDef**: Resolves member references to locally defined fields
//! - **MethodSpec → MethodDef**: Unwraps generic method instantiations to their base method
//!
//! # Relationship to Other Resolvers
//!
//! This resolver complements [`TypeResolver`](crate::metadata::typesystem::TypeResolver) which
//! operates at the *signature* level (parsing type signatures from blob heaps and creating
//! [`CilType`](crate::metadata::typesystem::CilType) instances). `TokenResolver` instead operates
//! at the *token* level, performing cross-table lookups to normalize metadata table indirections.
//!
//! # Usage
//!
//! Obtained via [`CilObject::resolver()`](crate::CilObject::resolver):
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use dotscope::metadata::token::Token;
//!
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//! let resolver = assembly.resolver();
//!
//! // Resolve a MemberRef to its MethodDef (returns None if external or not found)
//! let member_ref_token = Token::new(0x0A000001);
//! if let Some(method_def) = resolver.resolve_method(member_ref_token) {
//!     println!("Resolved to MethodDef: 0x{:08X}", method_def.value());
//! }
//!
//! // Find the declaring type of any method-like token
//! let method_token = Token::new(0x06000001);
//! if let Some(declaring_type) = resolver.declaring_type(method_token) {
//!     println!("Declaring type: {}", declaring_type.fullname());
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    metadata::{
        tables::TableId,
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
    },
    CilObject,
};

/// Cross-table token resolver for .NET metadata.
///
/// Normalizes token references across metadata tables, resolving indirections
/// such as TypeRef→TypeDef, MemberRef→MethodDef/FieldDef, and MethodSpec→MethodDef.
/// All resolution methods return `Option` to clearly signal when resolution fails
/// (e.g., when a MemberRef refers to an external assembly method with no local definition).
///
/// # Design
///
/// The resolver is a zero-cost borrowing wrapper — it holds only a `&CilObject` reference
/// and performs no allocations or caching. Resolution is performed on each call by walking
/// the metadata tables. For hot paths, callers should cache the result.
///
/// # Thread Safety
///
/// The resolver itself is `Send + Sync` since it only borrows an immutable `CilObject`.
/// All underlying metadata lookups are lock-free.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// use dotscope::metadata::token::Token;
///
/// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
/// let resolver = assembly.resolver();
///
/// // Resolve a TypeRef to its TypeDef
/// let type_ref = Token::new(0x01000001);
/// if let Some(resolved) = resolver.resolve_type(type_ref) {
///     println!("Resolved TypeRef to: {} (0x{:08X})",
///         resolved.fullname(), resolved.token.value());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct TokenResolver<'a> {
    assembly: &'a CilObject,
}

impl<'a> TokenResolver<'a> {
    /// Creates a new `TokenResolver` for the given assembly.
    ///
    /// This is an internal constructor — users should obtain a resolver via
    /// [`CilObject::resolver()`].
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly whose metadata tables will be used for resolution.
    pub(crate) fn new(assembly: &'a CilObject) -> Self {
        Self { assembly }
    }

    /// Resolves a type token to its most concrete [`CilType`](crate::metadata::typesystem::CilType).
    ///
    /// For TypeRef tokens (table 0x01), performs a fullname lookup to find the corresponding
    /// TypeDef or TypeSpec in the local assembly. If no local match exists (e.g., the type
    /// is defined in an external assembly), returns the original TypeRef entry as a fallback.
    ///
    /// For all other token tables (TypeDef, TypeSpec, primitives), delegates to
    /// [`TypeRegistry::get()`](crate::metadata::typesystem::TypeRegistry::get).
    ///
    /// # Arguments
    ///
    /// * `token` - A metadata token, typically from the TypeDef (0x02), TypeRef (0x01),
    ///   or TypeSpec (0x1B) tables.
    ///
    /// # Returns
    ///
    /// * `Some(CilTypeRc)` - The resolved type, preferring TypeDef over TypeRef
    /// * `None` - The token does not exist in the type registry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// // TypeDef tokens pass through directly
    /// let typedef = Token::new(0x02000001);
    /// assert!(resolver.resolve_type(typedef).is_some());
    ///
    /// // TypeRef tokens are resolved to their local TypeDef equivalent
    /// let typeref = Token::new(0x01000001);
    /// if let Some(resolved) = resolver.resolve_type(typeref) {
    ///     println!("Resolved to: {}", resolved.fullname());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn resolve_type(&self, token: Token) -> Option<CilTypeRc> {
        self.assembly.types().resolve(&token)
    }

    /// Resolves a method-like token to a MethodDef token (table 0x06).
    ///
    /// Handles three token types:
    ///
    /// - **MethodDef (0x06)**: Returns the token directly (already resolved).
    /// - **MemberRef (0x0A)**: Looks up the MemberRef's declaring type, resolves
    ///   TypeRef→TypeDef if needed, then searches the type's method list for a
    ///   method with a matching name.
    /// - **MethodSpec (0x2B)**: Extracts the underlying method token from the
    ///   generic instantiation (which may be a MethodDef or MemberRef) and recurses.
    ///
    /// Returns `None` when:
    /// - The token is not a method-like table (not 0x06, 0x0A, or 0x2B)
    /// - The MemberRef refers to an external method with no local MethodDef
    /// - The declaring type cannot be resolved to a TypeDef with methods
    /// - The MethodSpec's underlying method reference is invalid
    ///
    /// # Arguments
    ///
    /// * `token` - A metadata token from a call instruction operand (MethodDef,
    ///   MemberRef, or MethodSpec).
    ///
    /// # Returns
    ///
    /// * `Some(Token)` - The resolved MethodDef token
    /// * `None` - Resolution failed (external method, invalid token, or unsupported table)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// // MethodDef tokens are returned directly
    /// let methoddef = Token::new(0x06000001);
    /// assert_eq!(resolver.resolve_method(methoddef), Some(methoddef));
    ///
    /// // MemberRef tokens are resolved to local MethodDefs
    /// let memberref = Token::new(0x0A000001);
    /// if let Some(resolved) = resolver.resolve_method(memberref) {
    ///     assert!(resolved.is_table(TableId::MethodDef));
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn resolve_method(&self, token: Token) -> Option<Token> {
        match token.table() {
            0x06 => Some(token),
            0x0A => {
                let member_ref = self.assembly.member_ref(&token)?;
                let declaring_type = self.resolve_declaring_type(&member_ref.declaredby)?;
                declaring_type.methods.iter().find_map(|(_, method_ref)| {
                    let method = method_ref.upgrade()?;
                    if method.name == member_ref.name {
                        Some(method.token)
                    } else {
                        None
                    }
                })
            }
            0x2B => {
                let method_spec = self.assembly.method_spec(&token)?;
                let underlying = Self::extract_methodspec_token(&method_spec.method)?;
                self.resolve_method(underlying)
            }
            _ => None,
        }
    }

    /// Resolves a field-like token to a FieldDef token (table 0x04).
    ///
    /// Handles two token types:
    ///
    /// - **FieldDef (0x04)**: Returns the token directly (already resolved).
    /// - **MemberRef (0x0A)**: Looks up the MemberRef's declaring type, resolves
    ///   TypeRef→TypeDef if needed, then searches the type's field list for a
    ///   field with a matching name.
    ///
    /// Returns `None` when:
    /// - The token is not a field-like table (not 0x04 or 0x0A)
    /// - The MemberRef refers to an external field with no local FieldDef
    /// - The declaring type cannot be resolved to a TypeDef with fields
    ///
    /// # Arguments
    ///
    /// * `token` - A metadata token from a field instruction operand (FieldDef
    ///   or MemberRef).
    ///
    /// # Returns
    ///
    /// * `Some(Token)` - The resolved FieldDef token
    /// * `None` - Resolution failed (external field, invalid token, or unsupported table)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// // FieldDef tokens are returned directly
    /// let fielddef = Token::new(0x04000001);
    /// assert_eq!(resolver.resolve_field(fielddef), Some(fielddef));
    ///
    /// // MemberRef tokens referencing local fields are resolved
    /// let memberref = Token::new(0x0A000001);
    /// if let Some(resolved) = resolver.resolve_field(memberref) {
    ///     assert!(resolved.is_table(TableId::Field));
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn resolve_field(&self, token: Token) -> Option<Token> {
        match token.table() {
            0x04 => Some(token),
            0x0A => {
                let member_ref = self.assembly.member_ref(&token)?;
                let declaring_type = self.resolve_declaring_type(&member_ref.declaredby)?;
                declaring_type.fields.iter().find_map(|(_, field)| {
                    if field.name == member_ref.name {
                        Some(field.token)
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    /// Resolves a MemberRef token to the corresponding MethodDef token.
    ///
    /// This is a stricter variant of [`resolve_method()`](Self::resolve_method) that
    /// only accepts MemberRef tokens (table 0x0A). Returns `None` if the token is not
    /// a MemberRef, or if the referenced method has no local MethodDef definition
    /// (e.g., it belongs to an external assembly).
    ///
    /// This is the primary entry point for deobfuscation passes that need to resolve
    /// cross-assembly method references to local definitions.
    ///
    /// # Arguments
    ///
    /// * `token` - A MemberRef metadata token (table 0x0A). Tokens from other tables
    ///   cause an immediate `None` return.
    ///
    /// # Returns
    ///
    /// * `Some(Token)` - The resolved MethodDef token (guaranteed to be table 0x06)
    /// * `None` - The token is not a MemberRef, the entry does not exist, the declaring
    ///   type cannot be resolved, or no method with a matching name exists
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// let memberref = Token::new(0x0A000001);
    /// if let Some(methoddef) = resolver.resolve_memberref_method(memberref) {
    ///     assert!(methoddef.is_table(TableId::MethodDef));
    /// }
    ///
    /// // Non-MemberRef tokens return None
    /// let methoddef = Token::new(0x06000001);
    /// assert_eq!(resolver.resolve_memberref_method(methoddef), None);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn resolve_memberref_method(&self, token: Token) -> Option<Token> {
        if !token.is_table(TableId::MemberRef) {
            return None;
        }
        let member_ref = self.assembly.member_ref(&token)?;
        let declaring_type = self.resolve_declaring_type(&member_ref.declaredby)?;
        declaring_type.methods.iter().find_map(|(_, method_ref)| {
            let method = method_ref.upgrade()?;
            if method.name == member_ref.name {
                Some(method.token)
            } else {
                None
            }
        })
    }

    /// Resolves a MemberRef token to the corresponding FieldDef token.
    ///
    /// This is a stricter variant of [`resolve_field()`](Self::resolve_field) that
    /// only accepts MemberRef tokens (table 0x0A). Returns `None` if the token is not
    /// a MemberRef, or if the referenced field has no local FieldDef definition
    /// (e.g., it belongs to an external assembly).
    ///
    /// This is the primary entry point for deobfuscation passes that need to resolve
    /// field references used in `ldfld`/`stfld`/`ldsfld`/`stsfld` instructions to
    /// their canonical FieldDef tokens for storage in the emulator's static field table.
    ///
    /// # Arguments
    ///
    /// * `token` - A MemberRef metadata token (table 0x0A). Tokens from other tables
    ///   cause an immediate `None` return.
    ///
    /// # Returns
    ///
    /// * `Some(Token)` - The resolved FieldDef token (guaranteed to be table 0x04)
    /// * `None` - The token is not a MemberRef, the entry does not exist, the declaring
    ///   type cannot be resolved, or no field with a matching name exists
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// let memberref = Token::new(0x0A000001);
    /// if let Some(fielddef) = resolver.resolve_memberref_field(memberref) {
    ///     assert!(fielddef.is_table(TableId::Field));
    /// }
    ///
    /// // Non-MemberRef tokens return None
    /// let fielddef = Token::new(0x04000001);
    /// assert_eq!(resolver.resolve_memberref_field(fielddef), None);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn resolve_memberref_field(&self, token: Token) -> Option<Token> {
        if !token.is_table(TableId::MemberRef) {
            return None;
        }
        let member_ref = self.assembly.member_ref(&token)?;
        let declaring_type = self.resolve_declaring_type(&member_ref.declaredby)?;
        declaring_type.fields.iter().find_map(|(_, field)| {
            if field.name == member_ref.name {
                Some(field.token)
            } else {
                None
            }
        })
    }

    /// Finds the declaring type of a method-like token.
    ///
    /// Resolves the type that declares the given method, handling all three
    /// method token types:
    ///
    /// - **MemberRef (0x0A)**: Reads the `declaredby` field from the MemberRef
    ///   entry, upgrades the weak type reference, and resolves TypeRef→TypeDef
    ///   via [`TypeRegistry::resolve()`](crate::metadata::typesystem::TypeRegistry::resolve).
    /// - **MethodDef (0x06)**: Scans all types in the registry to find which
    ///   type's method list contains the given token. This is an O(n) scan over
    ///   all types — callers in hot paths should cache the result.
    /// - **MethodSpec (0x2B)**: Extracts the underlying method token from the
    ///   generic instantiation and recurses.
    ///
    /// Returns `None` when:
    /// - The token table is not 0x06, 0x0A, or 0x2B
    /// - The MemberRef or MethodSpec entry does not exist
    /// - The declaring type reference cannot be upgraded (dropped weak ref)
    /// - The MethodDef is not found in any type's method list
    ///
    /// # Arguments
    ///
    /// * `method_token` - A metadata token for a MethodDef, MemberRef, or MethodSpec.
    ///
    /// # Returns
    ///
    /// * `Some(CilTypeRc)` - The declaring type, resolved to a TypeDef where possible
    /// * `None` - The declaring type could not be determined
    ///
    /// # Performance
    ///
    /// For MethodDef tokens, this performs an O(n) scan over all types. MemberRef
    /// and MethodSpec resolution is O(1) via direct table lookups.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// let method_token = Token::new(0x06000001);
    /// if let Some(declaring_type) = resolver.declaring_type(method_token) {
    ///     println!("Method belongs to: {}", declaring_type.fullname());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn declaring_type(&self, method_token: Token) -> Option<CilTypeRc> {
        match method_token.table() {
            0x0A => {
                let member = self.assembly.member_ref(&method_token)?;
                let type_token = match &member.declaredby {
                    CilTypeReference::TypeDef(r)
                    | CilTypeReference::TypeRef(r)
                    | CilTypeReference::TypeSpec(r) => r.upgrade().map(|t| t.token),
                    _ => member.declaredby.token(),
                }?;
                self.assembly.types().resolve(&type_token)
            }
            0x06 => {
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
            0x2B => {
                let method_spec = self.assembly.method_spec(&method_token)?;
                let underlying = Self::extract_methodspec_token(&method_spec.method)?;
                self.declaring_type(underlying)
            }
            _ => None,
        }
    }

    /// Finds the declaring type of a field token.
    ///
    /// Scans all types in the registry to find which type's field list contains
    /// the given field token. Handles both FieldDef (0x04) and MemberRef (0x0A)
    /// tokens — for MemberRef, the `declaredby` field is used for O(1) lookup;
    /// for FieldDef, an O(n) scan over all types is performed.
    ///
    /// # Arguments
    ///
    /// * `field_token` - A FieldDef (0x04) or MemberRef (0x0A) token referencing a field.
    ///
    /// # Returns
    ///
    /// * `Some(CilTypeRc)` - The declaring type, resolved to TypeDef where possible
    /// * `None` - The field could not be found in any type's field list
    ///
    /// # Performance
    ///
    /// For MemberRef tokens, resolution is O(1) via the `declaredby` field.
    /// For FieldDef tokens, this performs an O(n) scan over all types.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// let field_token = Token::new(0x04000001);
    /// if let Some(declaring_type) = resolver.declaring_type_of_field(field_token) {
    ///     println!("Field belongs to: {}", declaring_type.fullname());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn declaring_type_of_field(&self, field_token: Token) -> Option<CilTypeRc> {
        match field_token.table() {
            0x0A => {
                // MemberRef: resolve via declaredby
                let member = self.assembly.member_ref(&field_token)?;
                self.resolve_declaring_type(&member.declaredby)
            }
            0x04 => {
                // FieldDef: scan all types
                for type_info in self.assembly.types().all_types() {
                    for (_, field_rc) in type_info.fields.iter() {
                        if field_rc.token == field_token {
                            return self.assembly.types().get(&type_info.token);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Resolves a [`CilTypeReference`] to its concrete [`CilType`](crate::metadata::typesystem::CilType).
    ///
    /// Upgrades the weak reference contained in the `CilTypeReference` and, if the
    /// resulting type is a TypeRef, resolves it to the corresponding TypeDef via
    /// [`TypeRegistry::resolve()`](crate::metadata::typesystem::TypeRegistry::resolve).
    /// This ensures the returned type has populated methods and fields (TypeRef entries
    /// are stubs with empty method/field lists).
    ///
    /// Only handles type-like variants (`TypeDef`, `TypeRef`, `TypeSpec`). Returns `None`
    /// for non-type references (fields, methods, parameters, etc.) or if the weak
    /// reference has been dropped.
    ///
    /// # Arguments
    ///
    /// * `type_ref` - A type reference from a MemberRef's `declaredby` field or similar.
    ///
    /// # Returns
    ///
    /// * `Some(CilTypeRc)` - The resolved type with populated methods and fields
    /// * `None` - The reference is not a type, or the weak reference was dropped
    fn resolve_declaring_type(&self, type_ref: &CilTypeReference) -> Option<CilTypeRc> {
        match type_ref {
            CilTypeReference::TypeDef(r)
            | CilTypeReference::TypeRef(r)
            | CilTypeReference::TypeSpec(r) => {
                let t = r.upgrade()?;
                if t.token.is_table(TableId::TypeRef) {
                    self.assembly.types().resolve(&t.token)
                } else {
                    Some(t)
                }
            }
            _ => None,
        }
    }

    /// Extracts the underlying method token from a [`MethodSpec`](crate::metadata::tables::MethodSpec)'s
    /// method reference field.
    ///
    /// A MethodSpec's `method` field is a [`CilTypeReference`] that points to either
    /// a MethodDef (for local generic methods) or a MemberRef (for external generic
    /// methods). This helper extracts that token for further resolution.
    ///
    /// # Arguments
    ///
    /// * `method_ref` - The `method` field from a MethodSpec entry.
    ///
    /// # Returns
    ///
    /// * `Some(Token)` - The MethodDef or MemberRef token
    /// * `None` - The reference type is unexpected (not MethodDef or MemberRef)
    fn extract_methodspec_token(method_ref: &CilTypeReference) -> Option<Token> {
        match method_ref {
            CilTypeReference::MethodDef(r) => r.token(),
            CilTypeReference::MemberRef(r) => Some(r.token),
            _ => None,
        }
    }
}
