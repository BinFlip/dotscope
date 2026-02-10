//! Cleanup request specification for assembly modifications.
//!
//! This module defines [`CleanupRequest`], which specifies what metadata entries
//! should be removed from an assembly. The cleanup executor will process this
//! request and remove the specified items along with any orphaned metadata that
//! becomes unreferenced as a result.

use std::collections::{BTreeSet, HashSet};

use crate::metadata::token::Token;

/// Request for cleanup operations on a [`CilAssembly`](crate::CilAssembly).
///
/// Specifies explicit deletions to perform. The cleanup executor will:
///
/// 1. Apply these explicit deletions
/// 2. Find and remove orphaned metadata caused by these deletions
/// 3. **Not** remove pre-existing orphans (to preserve intentional patterns)
///
/// This distinction is important: we only remove metadata that became orphaned
/// due to our changes, not metadata that was already orphaned in the original
/// assembly (which may be used via reflection or dynamic code).
///
/// # Iterator Access
///
/// The accessor methods (`types()`, `methods()`, etc.) return iterators that
/// yield tokens in descending RID order. This is the correct order for deletion
/// operations to avoid RID shifting issues.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::cilassembly::cleanup::CleanupRequest;
///
/// let mut request = CleanupRequest::default();
/// request.add_type(protection_type_token);
/// request.add_method(decryptor_method_token);
/// request.exclude_section(".confuser");
///
/// // Iterate in descending order for safe deletion
/// for token in request.types() {
///     // tokens come in descending RID order
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CleanupRequest {
    /// TypeDef tokens to remove.
    ///
    /// When a type is removed, all its members (methods, fields, properties,
    /// events) are also removed, along with cascading orphaned metadata.
    types: BTreeSet<Token>,

    /// MethodDef tokens to remove.
    ///
    /// Removing a method also removes its parameters, local variable signatures,
    /// and any metadata entries that reference only this method.
    methods: BTreeSet<Token>,

    /// MethodSpec tokens to remove.
    ///
    /// Generic method instantiations (e.g., `Decryptor<string>.Decrypt()`).
    methodspecs: BTreeSet<Token>,

    /// Field tokens to remove.
    ///
    /// Removing a field also removes associated FieldRVA, FieldLayout,
    /// FieldMarshal, and Constant entries.
    fields: BTreeSet<Token>,

    /// CustomAttribute tokens to remove directly.
    ///
    /// These are removed without checking if they're orphaned.
    attributes: BTreeSet<Token>,

    /// PE sections to exclude from output.
    ///
    /// Section names (e.g., ".confuser", ".packed") that should not be
    /// included in the generated assembly. Useful for removing obfuscator
    /// artifact sections that contain encrypted data.
    excluded_sections: HashSet<String>,

    /// Whether to remove orphaned metadata entries.
    ///
    /// When true (default), metadata entries that reference only deleted
    /// items will be removed. When false, only explicit deletions are applied.
    remove_orphans: bool,

    /// Whether to remove types that become empty after cleanup.
    ///
    /// When true, types with no remaining methods or fields after cleanup
    /// are also removed.
    remove_empty_types: bool,
}

impl Default for CleanupRequest {
    fn default() -> Self {
        Self {
            types: BTreeSet::new(),
            methods: BTreeSet::new(),
            methodspecs: BTreeSet::new(),
            fields: BTreeSet::new(),
            attributes: BTreeSet::new(),
            excluded_sections: HashSet::new(),
            remove_orphans: true,
            remove_empty_types: true,
        }
    }
}

impl CleanupRequest {
    /// Creates a new cleanup request with default settings.
    ///
    /// Default settings:
    /// - `remove_orphans`: true
    /// - `remove_empty_types`: true
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a cleanup request with custom settings.
    #[must_use]
    pub fn with_settings(remove_orphans: bool, remove_empty_types: bool) -> Self {
        Self {
            types: BTreeSet::new(),
            methods: BTreeSet::new(),
            methodspecs: BTreeSet::new(),
            fields: BTreeSet::new(),
            attributes: BTreeSet::new(),
            excluded_sections: HashSet::new(),
            remove_orphans,
            remove_empty_types,
        }
    }

    /// Adds a type (TypeDef) to be removed.
    ///
    /// When a type is removed, its methods and fields will also be removed,
    /// along with any orphaned metadata entries that reference it.
    pub fn add_type(&mut self, token: Token) -> &mut Self {
        self.types.insert(token);
        self
    }

    /// Adds multiple types (TypeDef) to be removed.
    pub fn add_types(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.types.extend(tokens);
        self
    }

    /// Returns an iterator over types to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn types(&self) -> impl Iterator<Item = &Token> + '_ {
        self.types.iter().rev()
    }

    /// Returns the number of types to remove.
    #[must_use]
    pub fn types_len(&self) -> usize {
        self.types.len()
    }

    /// Adds a method (MethodDef) to be removed.
    pub fn add_method(&mut self, token: Token) -> &mut Self {
        self.methods.insert(token);
        self
    }

    /// Adds multiple methods (MethodDef) to be removed.
    pub fn add_methods(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.methods.extend(tokens);
        self
    }

    /// Returns an iterator over methods to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn methods(&self) -> impl Iterator<Item = &Token> + '_ {
        self.methods.iter().rev()
    }

    /// Returns the number of methods to remove.
    #[must_use]
    pub fn methods_len(&self) -> usize {
        self.methods.len()
    }

    /// Adds a MethodSpec to be removed.
    pub fn add_methodspec(&mut self, token: Token) -> &mut Self {
        self.methodspecs.insert(token);
        self
    }

    /// Adds multiple MethodSpecs to be removed.
    pub fn add_methodspecs(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.methodspecs.extend(tokens);
        self
    }

    /// Returns an iterator over MethodSpecs to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn methodspecs(&self) -> impl Iterator<Item = &Token> + '_ {
        self.methodspecs.iter().rev()
    }

    /// Returns the number of MethodSpecs to remove.
    #[must_use]
    pub fn methodspecs_len(&self) -> usize {
        self.methodspecs.len()
    }

    /// Adds a field to be removed.
    pub fn add_field(&mut self, token: Token) -> &mut Self {
        self.fields.insert(token);
        self
    }

    /// Adds multiple fields to be removed.
    pub fn add_fields(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.fields.extend(tokens);
        self
    }

    /// Returns an iterator over fields to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn fields(&self) -> impl Iterator<Item = &Token> + '_ {
        self.fields.iter().rev()
    }

    /// Returns the number of fields to remove.
    #[must_use]
    pub fn fields_len(&self) -> usize {
        self.fields.len()
    }

    /// Adds a custom attribute to be removed.
    pub fn add_attribute(&mut self, token: Token) -> &mut Self {
        self.attributes.insert(token);
        self
    }

    /// Adds multiple custom attributes to be removed.
    pub fn add_attributes(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.attributes.extend(tokens);
        self
    }

    /// Returns an iterator over attributes to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn attributes(&self) -> impl Iterator<Item = &Token> + '_ {
        self.attributes.iter().rev()
    }

    /// Returns the number of attributes to remove.
    #[must_use]
    pub fn attributes_len(&self) -> usize {
        self.attributes.len()
    }

    /// Excludes a PE section from output.
    ///
    /// The section name should include the dot prefix (e.g., ".confuser").
    pub fn exclude_section(&mut self, name: impl Into<String>) -> &mut Self {
        self.excluded_sections.insert(name.into());
        self
    }

    /// Excludes multiple PE sections from output.
    pub fn exclude_sections(&mut self, names: impl IntoIterator<Item = String>) -> &mut Self {
        self.excluded_sections.extend(names);
        self
    }

    /// Returns the set of sections to exclude.
    #[must_use]
    pub fn excluded_sections(&self) -> &HashSet<String> {
        &self.excluded_sections
    }

    /// Sets whether to remove orphaned metadata.
    pub fn set_remove_orphans(&mut self, remove: bool) -> &mut Self {
        self.remove_orphans = remove;
        self
    }

    /// Returns whether orphaned metadata will be removed.
    #[must_use]
    pub fn remove_orphans(&self) -> bool {
        self.remove_orphans
    }

    /// Sets whether to remove empty types after cleanup.
    pub fn set_remove_empty_types(&mut self, remove: bool) -> &mut Self {
        self.remove_empty_types = remove;
        self
    }

    /// Returns whether empty types will be removed.
    #[must_use]
    pub fn remove_empty_types(&self) -> bool {
        self.remove_empty_types
    }

    /// Returns true if this request has no deletions specified.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
            && self.methods.is_empty()
            && self.methodspecs.is_empty()
            && self.fields.is_empty()
            && self.attributes.is_empty()
    }

    /// Returns true if this request has any deletions specified.
    #[must_use]
    pub fn has_deletions(&self) -> bool {
        !self.is_empty()
    }

    /// Returns the total count of items to delete.
    #[must_use]
    pub fn deletion_count(&self) -> usize {
        self.types.len()
            + self.methods.len()
            + self.methodspecs.len()
            + self.fields.len()
            + self.attributes.len()
    }

    /// Checks if a specific token is marked for deletion.
    ///
    /// This checks all token sets (types, methods, methodspecs, fields, attributes).
    #[must_use]
    pub fn is_deleted(&self, token: Token) -> bool {
        self.types.contains(&token)
            || self.methods.contains(&token)
            || self.methodspecs.contains(&token)
            || self.fields.contains(&token)
            || self.attributes.contains(&token)
    }

    /// Merges another cleanup request into this one.
    ///
    /// All tokens from `other` are added to this request.
    /// Settings (`remove_orphans`, `remove_empty_types`) are not changed.
    pub fn merge(&mut self, other: &CleanupRequest) -> &mut Self {
        self.types.extend(other.types.iter().copied());
        self.methods.extend(other.methods.iter().copied());
        self.methodspecs.extend(other.methodspecs.iter().copied());
        self.fields.extend(other.fields.iter().copied());
        self.attributes.extend(other.attributes.iter().copied());
        self.excluded_sections
            .extend(other.excluded_sections.iter().cloned());
        self
    }

    /// Returns all tokens scheduled for removal.
    ///
    /// This includes types, methods, methodspecs, fields, and attributes.
    #[must_use]
    pub fn all_tokens(&self) -> HashSet<Token> {
        let mut all = HashSet::new();
        all.extend(&self.types);
        all.extend(&self.methods);
        all.extend(&self.methodspecs);
        all.extend(&self.fields);
        all.extend(&self.attributes);
        all
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::cleanup::CleanupRequest,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_cleanup_request_default() {
        let request = CleanupRequest::default();
        assert!(request.is_empty());
        assert!(!request.has_deletions());
        assert_eq!(request.deletion_count(), 0);
        assert!(request.remove_orphans());
        assert!(request.remove_empty_types());
    }

    #[test]
    fn test_add_type() {
        let mut request = CleanupRequest::new();
        let token = Token::from_parts(TableId::TypeDef, 5);

        request.add_type(token);

        assert!(!request.is_empty());
        assert!(request.has_deletions());
        assert_eq!(request.deletion_count(), 1);
        assert!(request.is_deleted(token));
        assert_eq!(request.types_len(), 1);
    }

    #[test]
    fn test_add_method() {
        let mut request = CleanupRequest::new();
        let token = Token::from_parts(TableId::MethodDef, 10);

        request.add_method(token);

        assert!(request.is_deleted(token));
        assert_eq!(request.methods_len(), 1);
    }

    #[test]
    fn test_exclude_section() {
        let mut request = CleanupRequest::new();

        request.exclude_section(".confuser");
        request.exclude_section(".packed");

        assert_eq!(request.excluded_sections().len(), 2);
        assert!(request.excluded_sections().contains(".confuser"));
        assert!(request.excluded_sections().contains(".packed"));
    }

    #[test]
    fn test_merge() {
        let mut request1 = CleanupRequest::new();
        request1.add_type(Token::from_parts(TableId::TypeDef, 1));

        let mut request2 = CleanupRequest::new();
        request2.add_method(Token::from_parts(TableId::MethodDef, 2));
        request2.exclude_section(".test");

        request1.merge(&request2);

        assert_eq!(request1.deletion_count(), 2);
        assert!(request1.excluded_sections().contains(".test"));
    }

    #[test]
    fn test_with_settings() {
        let request = CleanupRequest::with_settings(false, false);

        assert!(!request.remove_orphans());
        assert!(!request.remove_empty_types());
    }

    #[test]
    fn test_method_chaining() {
        let token1 = Token::from_parts(TableId::TypeDef, 1);
        let token2 = Token::from_parts(TableId::MethodDef, 2);
        let token3 = Token::from_parts(TableId::Field, 3);

        let mut request = CleanupRequest::new();
        request
            .add_type(token1)
            .add_method(token2)
            .add_field(token3)
            .exclude_section(".data")
            .set_remove_orphans(true);

        assert_eq!(request.deletion_count(), 3);
        assert!(request.excluded_sections().contains(".data"));
    }

    #[test]
    fn test_types_iterator_descending_order() {
        let mut request = CleanupRequest::new();
        request.add_type(Token::from_parts(TableId::TypeDef, 1));
        request.add_type(Token::from_parts(TableId::TypeDef, 5));
        request.add_type(Token::from_parts(TableId::TypeDef, 3));

        let tokens: Vec<&Token> = request.types().collect();

        // Should be in descending order: 5, 3, 1
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].row(), 5);
        assert_eq!(tokens[1].row(), 3);
        assert_eq!(tokens[2].row(), 1);
    }

    #[test]
    fn test_methods_iterator_descending_order() {
        let mut request = CleanupRequest::new();
        request.add_method(Token::from_parts(TableId::MethodDef, 10));
        request.add_method(Token::from_parts(TableId::MethodDef, 2));
        request.add_method(Token::from_parts(TableId::MethodDef, 7));

        let tokens: Vec<&Token> = request.methods().collect();

        // Should be in descending order: 10, 7, 2
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].row(), 10);
        assert_eq!(tokens[1].row(), 7);
        assert_eq!(tokens[2].row(), 2);
    }
}
