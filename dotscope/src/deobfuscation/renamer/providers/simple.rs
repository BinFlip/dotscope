//! Simple sequential name provider.
//!
//! Provides the original `SimpleNameGenerator` (moved from `cleanup.rs`) and
//! a [`SimpleProvider`] wrapper that implements [`RenameProvider`] using atomic
//! counters for thread-safe name generation.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::deobfuscation::renamer::{
    context::{IdentifierKind, RenameContext},
    RenameProvider,
};

/// Generator for simple sequential names used when renaming obfuscated identifiers.
///
/// Maintains separate counters for types, methods, fields, and parameters.
/// Names are produced in base-26 alphabetic order: `A`, `B`, ..., `Z`, `AA`,
/// `AB`, .... Type names are uppercase; method names are lowercase; field and
/// parameter names carry an `f_` or `p_` prefix respectively.
#[derive(Debug, Default)]
pub struct SimpleNameGenerator {
    types: usize,
    methods: usize,
    fields: usize,
    params: usize,
}

impl SimpleNameGenerator {
    /// Creates a new generator with all counters set to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates the next type name and advances the type counter.
    ///
    /// Names are uppercase base-26: `A`, `B`, ..., `Z`, `AA`, `AB`, ...
    pub fn next_type_name(&mut self) -> String {
        let name = Self::index_to_name(self.types);
        self.types = self.types.saturating_add(1);
        name
    }

    /// Generates the next method name and advances the method counter.
    ///
    /// Names are lowercase base-26: `a`, `b`, ..., `z`, `aa`, `ab`, ...
    pub fn next_method_name(&mut self) -> String {
        let name = Self::index_to_name_lower(self.methods);
        self.methods = self.methods.saturating_add(1);
        name
    }

    /// Generates the next field name and advances the field counter.
    ///
    /// Field names are prefixed with `f_` followed by a lowercase base-26
    /// sequence: `f_a`, `f_b`, ..., `f_z`, `f_aa`, ...
    pub fn next_field_name(&mut self) -> String {
        let name = format!("f_{}", Self::index_to_name_lower(self.fields));
        self.fields = self.fields.saturating_add(1);
        name
    }

    /// Generates the next parameter name and advances the parameter counter.
    ///
    /// Parameter names are prefixed with `p_` followed by a lowercase base-26
    /// sequence: `p_a`, `p_b`, ..., `p_z`, `p_aa`, ...
    pub fn next_param_name(&mut self) -> String {
        let name = format!("p_{}", Self::index_to_name_lower(self.params));
        self.params = self.params.saturating_add(1);
        name
    }

    /// Converts a zero-based index to an uppercase base-26 alphabetic name.
    ///
    /// The mapping is: `0 → "A"`, `25 → "Z"`, `26 → "AA"`, `27 → "AB"`, ...
    #[must_use]
    pub fn index_to_name(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index.checked_rem(26).unwrap_or(0);
            #[allow(clippy::cast_possible_truncation)]
            result.insert(0, (b'A'.saturating_add(remainder as u8)) as char);
            if index < 26 {
                break;
            }
            index = index.checked_div(26).unwrap_or(0).saturating_sub(1);
        }
        result
    }

    /// Converts a zero-based index to a lowercase base-26 alphabetic name.
    ///
    /// Identical to [`index_to_name`](Self::index_to_name) but uses lowercase
    /// letters: `0 → "a"`, `25 → "z"`, `26 → "aa"`, ...
    #[must_use]
    pub fn index_to_name_lower(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index.checked_rem(26).unwrap_or(0);
            #[allow(clippy::cast_possible_truncation)]
            result.insert(0, (b'a'.saturating_add(remainder as u8)) as char);
            if index < 26 {
                break;
            }
            index = index.checked_div(26).unwrap_or(0).saturating_sub(1);
        }
        result
    }
}

/// Thread-safe rename provider that generates simple sequential names.
///
/// Uses atomic counters so that [`RenameProvider::suggest_name`] can take `&self`.
/// This is the default fallback provider when no smart rename configuration is present.
pub struct SimpleProvider {
    type_counter: AtomicUsize,
    method_counter: AtomicUsize,
    field_counter: AtomicUsize,
    param_counter: AtomicUsize,
}

impl SimpleProvider {
    /// Creates a new provider with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_counter: AtomicUsize::new(0),
            method_counter: AtomicUsize::new(0),
            field_counter: AtomicUsize::new(0),
            param_counter: AtomicUsize::new(0),
        }
    }
}

impl RenameProvider for SimpleProvider {
    fn name(&self) -> &'static str {
        "SimpleProvider"
    }

    fn initialize(&mut self) -> crate::Result<()> {
        Ok(())
    }

    fn suggest_name(&self, context: &RenameContext) -> crate::Result<Option<String>> {
        let kind = match context.kind {
            Some(k) => k,
            None => return Ok(None),
        };

        let name = match kind {
            IdentifierKind::Type => {
                let idx = self.type_counter.fetch_add(1, Ordering::Relaxed);
                SimpleNameGenerator::index_to_name(idx)
            }
            IdentifierKind::Method => {
                let idx = self.method_counter.fetch_add(1, Ordering::Relaxed);
                SimpleNameGenerator::index_to_name_lower(idx)
            }
            IdentifierKind::Field => {
                let idx = self.field_counter.fetch_add(1, Ordering::Relaxed);
                format!("f_{}", SimpleNameGenerator::index_to_name_lower(idx))
            }
            IdentifierKind::Parameter => {
                let idx = self.param_counter.fetch_add(1, Ordering::Relaxed);
                format!("p_{}", SimpleNameGenerator::index_to_name_lower(idx))
            }
        };

        Ok(Some(name))
    }

    fn shutdown(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::renamer::{
        context::{IdentifierKind, RenameContext},
        providers::simple::{SimpleNameGenerator, SimpleProvider},
        RenameProvider,
    };

    #[test]
    fn test_name_generator() {
        assert_eq!(SimpleNameGenerator::index_to_name(0), "A");
        assert_eq!(SimpleNameGenerator::index_to_name(25), "Z");
        assert_eq!(SimpleNameGenerator::index_to_name(26), "AA");
        assert_eq!(SimpleNameGenerator::index_to_name(27), "AB");
        assert_eq!(SimpleNameGenerator::index_to_name(702), "AAA");
    }

    #[test]
    fn test_name_generator_lower() {
        assert_eq!(SimpleNameGenerator::index_to_name_lower(0), "a");
        assert_eq!(SimpleNameGenerator::index_to_name_lower(25), "z");
        assert_eq!(SimpleNameGenerator::index_to_name_lower(26), "aa");
    }

    #[test]
    fn test_name_generator_sequential() {
        let mut gen = SimpleNameGenerator::new();
        assert_eq!(gen.next_type_name(), "A");
        assert_eq!(gen.next_type_name(), "B");
        assert_eq!(gen.next_method_name(), "a");
        assert_eq!(gen.next_field_name(), "f_a");
        assert_eq!(gen.next_param_name(), "p_a");
    }

    #[test]
    fn test_simple_provider_trait() {
        let mut provider = SimpleProvider::new();
        provider.initialize().unwrap();

        let type_ctx = RenameContext {
            kind: Some(IdentifierKind::Type),
            ..Default::default()
        };
        let method_ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            ..Default::default()
        };
        let field_ctx = RenameContext {
            kind: Some(IdentifierKind::Field),
            ..Default::default()
        };
        let param_ctx = RenameContext {
            kind: Some(IdentifierKind::Parameter),
            ..Default::default()
        };

        assert_eq!(
            provider.suggest_name(&type_ctx).unwrap(),
            Some("A".to_string())
        );
        assert_eq!(
            provider.suggest_name(&type_ctx).unwrap(),
            Some("B".to_string())
        );
        assert_eq!(
            provider.suggest_name(&method_ctx).unwrap(),
            Some("a".to_string())
        );
        assert_eq!(
            provider.suggest_name(&field_ctx).unwrap(),
            Some("f_a".to_string())
        );
        assert_eq!(
            provider.suggest_name(&param_ctx).unwrap(),
            Some("p_a".to_string())
        );

        provider.shutdown().unwrap();
    }

    #[test]
    fn test_simple_provider_no_kind() {
        let provider = SimpleProvider::new();
        let ctx = RenameContext::default();
        assert_eq!(provider.suggest_name(&ctx).unwrap(), None);
    }
}
