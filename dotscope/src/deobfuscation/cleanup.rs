//! Generic cleanup utilities for deobfuscation.
//!
//! This module provides deobfuscation-specific cleanup operations that build on
//! the generic [`cilassembly::cleanup`](crate::cilassembly::cleanup) infrastructure.
//!
//! The deobfuscation cleanup adds:
//! - Dead method collection from analysis
//! - Entry point protection (preserves public methods, constructors, etc.)
//! - Obfuscated name renaming
//! - Event logging for statistics
//!
//! # Usage
//!
//! Obfuscator-specific modules should:
//! 1. Detect what tokens need to be removed (types, methods, fields)
//! 2. Create a [`CleanupRequest`](crate::cilassembly::CleanupRequest) with those tokens
//! 3. Call [`execute_cleanup`] to perform the cleanup
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::cilassembly::CleanupRequest;
//! use dotscope::deobfuscation::cleanup::execute_cleanup;
//! use dotscope::deobfuscation::DerivedStats;
//!
//! let mut request = CleanupRequest::new();
//! request.add_type(some_type_token);
//! request.add_method(some_method_token);
//! request.add_field(some_field_token);
//!
//! let assembly = execute_cleanup(assembly, Some(request), &ctx)?;
//! // Statistics are derived from the event log
//! let stats = DerivedStats::from_log(&ctx.events);
//! println!("{}", stats.summary());
//! ```

use std::collections::HashSet;

use crate::{
    cilassembly::{CilAssembly, CleanupRequest, GeneratorConfig},
    compiler::EventKind,
    deobfuscation::context::AnalysisContext,
    metadata::{
        tables::{FieldRaw, MethodDefRaw, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// Executes unified cleanup combining an obfuscator's request with dead methods.
///
/// This is the main entry point for cleanup after deobfuscation. It:
/// 1. Starts with the obfuscator's cleanup request (if any)
/// 2. Merges in dead methods from analysis
/// 3. Executes cleanup via the CilAssembly infrastructure
/// 4. Handles renaming and section exclusion
/// 5. Regenerates the assembly
pub fn execute_cleanup(
    assembly: CilObject,
    obfuscator_request: Option<CleanupRequest>,
    ctx: &AnalysisContext,
) -> Result<CilObject> {
    // Start with obfuscator's request or create a new one with config settings
    let mut request = obfuscator_request.unwrap_or_else(|| {
        CleanupRequest::with_settings(
            ctx.config.cleanup.remove_orphan_metadata,
            ctx.config.cleanup.remove_empty_types,
        )
    });

    // Add dead methods from analysis
    let aggressive = ctx.config.cleanup.remove_unused_methods;
    if aggressive {
        for token in ctx.dead_methods.iter() {
            let token = *token;
            if !is_entry_point(&assembly, token, aggressive) {
                request.add_method(token);
            }
        }
    }

    // Determine if we should rename obfuscated names
    let rename_obfuscated = ctx.config.cleanup.rename_obfuscated_names;

    // Nothing to do
    if !request.has_deletions() && request.excluded_sections().is_empty() && !rename_obfuscated {
        return Ok(assembly);
    }

    // Log what we're cleaning
    let types_count = request.types_len();
    let methods_count = request.methods_len();
    let fields_count = request.fields_len();

    if types_count > 0 || methods_count > 0 || fields_count > 0 {
        ctx.events.record(EventKind::Info).message(format!(
            "Cleanup: {} types, {} methods, {} fields",
            types_count, methods_count, fields_count
        ));
    }

    for section_name in request.excluded_sections() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing artifact section: {}", section_name));
    }

    // Create CilAssembly and add cleanup request
    let bytes = assembly.file().data().to_vec();
    let mut cil_assembly = CilAssembly::from_bytes(bytes)?;

    // Log individual removals
    log_cleanup_request(&request, &assembly, ctx);

    // Clone excluded sections before moving request
    let excluded_sections: HashSet<String> = request.excluded_sections().clone();

    // Add cleanup request (the actual cleanup is executed during generation)
    cil_assembly.add_cleanup(request);

    // Handle renaming
    if rename_obfuscated {
        let count = rename_obfuscated_names(&mut cil_assembly)?;
        if count > 0 {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Renamed {} obfuscated names to simple identifiers",
                    count
                ));
        }
    }

    // Regenerate with excluded sections
    // The cleanup is automatically executed during into_cilobject_with
    let generator_config = GeneratorConfig::default().with_excluded_sections(excluded_sections);
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), generator_config)
}

/// Logs cleanup request details to the event log.
fn log_cleanup_request(request: &CleanupRequest, assembly: &CilObject, ctx: &AnalysisContext) {
    // Log type removals
    for type_token in request.types() {
        if let Some(cil_type) = assembly.types().get(type_token) {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Removing type: {} (0x{:08X})",
                    cil_type.name,
                    type_token.value()
                ));
        } else {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!("Removing type: TypeDef RID {}", type_token.row()));
        }
    }

    // Log method removals
    for method_token in request.methods() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .method(*method_token)
            .message("Removing method");
    }

    // Log field removals
    for field_token in request.fields() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing field 0x{:08X}", field_token.value()));
    }

    // Log attribute removals
    for attr_token in request.attributes() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!(
                "Removing custom attribute 0x{:08X}",
                attr_token.value()
            ));
    }
}

/// Checks if a method is an entry point that should not be removed.
pub(crate) fn is_entry_point(assembly: &CilObject, method_token: Token, aggressive: bool) -> bool {
    // Check if it's the assembly entry point
    let entry_token = assembly.cor20header().entry_point_token;
    if entry_token != 0 && Token::new(entry_token) == method_token {
        return true;
    }

    let method_entry = assembly
        .methods()
        .iter()
        .find(|m| m.value().token == method_token);

    let Some(entry) = method_entry else {
        return false;
    };

    let method = entry.value();

    // Static constructors are special runtime entry points
    if method.is_cctor() {
        return true;
    }

    // In aggressive mode, we trust the dead code analysis for everything else
    if aggressive {
        return false;
    }

    // In non-aggressive mode, protect public methods as potential external API
    if method.is_public() {
        return true;
    }

    // Instance constructors in public types could be called externally
    if method.is_ctor() && method.is_public() {
        return true;
    }

    false
}

/// Checks if a name appears to be obfuscated.
fn is_obfuscated_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    for c in name.chars() {
        match c {
            '\u{200B}'..='\u{200F}' => return true,
            '\u{202A}'..='\u{202E}' => return true,
            '\u{2060}'..='\u{206F}' => return true,
            '\u{FEFF}' => return true,
            '\u{E000}'..='\u{F8FF}' => return true,
            c if !c.is_ascii() => {
                if !c.is_alphabetic() {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

/// Checks if a name is a special .NET name that should not be renamed.
fn is_special_name(name: &str) -> bool {
    if name == ".ctor" || name == ".cctor" {
        return true;
    }

    if name == "<Module>" || name == "<PrivateImplementationDetails>" {
        return true;
    }

    if name.starts_with('<') && name.ends_with('>') {
        return true;
    }

    if name.starts_with("get_")
        || name.starts_with("set_")
        || name.starts_with("add_")
        || name.starts_with("remove_")
    {
        return true;
    }

    false
}

/// Generator for simple sequential names.
#[derive(Debug, Default)]
struct SimpleNameGenerator {
    type_counter: usize,
    method_counter: usize,
    field_counter: usize,
}

impl SimpleNameGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_type_name(&mut self) -> String {
        let name = Self::index_to_name(self.type_counter);
        self.type_counter += 1;
        name
    }

    pub fn next_method_name(&mut self) -> String {
        let name = Self::index_to_name_lower(self.method_counter);
        self.method_counter += 1;
        name
    }

    pub fn next_field_name(&mut self) -> String {
        let name = format!("f_{}", Self::index_to_name_lower(self.field_counter));
        self.field_counter += 1;
        name
    }

    #[must_use]
    pub fn index_to_name(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index % 26;
            result.insert(0, (b'A' + remainder as u8) as char);
            if index < 26 {
                break;
            }
            index = index / 26 - 1;
        }
        result
    }

    #[must_use]
    pub fn index_to_name_lower(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index % 26;
            result.insert(0, (b'a' + remainder as u8) as char);
            if index < 26 {
                break;
            }
            index = index / 26 - 1;
        }
        result
    }
}

/// Renames obfuscated type, method, and field names to simple identifiers.
fn rename_obfuscated_names(cil_assembly: &mut CilAssembly) -> Result<usize> {
    let mut renamed_count = 0;
    let mut name_generator = SimpleNameGenerator::new();

    let view = cil_assembly.view();
    let Some(tables) = view.tables() else {
        return Ok(0);
    };

    let Some(strings) = view.strings() else {
        return Ok(0);
    };

    let mut names_to_rename: Vec<(u32, String)> = Vec::new();

    // Collect obfuscated names from TypeDef
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for rid in 1..=typedef_table.row_count {
            if let Some(typedef) = typedef_table.get(rid) {
                if rid == 1 {
                    continue;
                }

                let name_index = typedef.type_name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_type_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated method names from MethodDef
    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
        for rid in 1..=methoddef_table.row_count {
            if let Some(methoddef) = methoddef_table.get(rid) {
                let name_index = methoddef.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_method_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated field names from Field
    if let Some(field_table) = tables.table::<FieldRaw>() {
        for rid in 1..=field_table.row_count {
            if let Some(field) = field_table.get(rid) {
                let name_index = field.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_field_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Apply the renames to the string heap
    for (string_index, new_name) in &names_to_rename {
        if cil_assembly.string_update(*string_index, new_name).is_ok() {
            renamed_count += 1;
        }
    }

    Ok(renamed_count)
}

#[cfg(test)]
mod tests {
    use crate::{cilassembly::CleanupRequest, metadata::token::Token};

    use super::{is_obfuscated_name, is_special_name, SimpleNameGenerator};

    #[test]
    fn test_cleanup_request_builder() {
        let mut request = CleanupRequest::new();
        request
            .add_type(Token::new(0x02000001))
            .add_method(Token::new(0x06000001))
            .add_field(Token::new(0x04000001));

        assert!(request.has_deletions());
        assert_eq!(request.types_len(), 1);
        assert_eq!(request.methods_len(), 1);
        assert_eq!(request.fields_len(), 1);
    }

    #[test]
    fn test_name_generator() {
        assert_eq!(SimpleNameGenerator::index_to_name(0), "A");
        assert_eq!(SimpleNameGenerator::index_to_name(25), "Z");
        assert_eq!(SimpleNameGenerator::index_to_name(26), "AA");
        assert_eq!(SimpleNameGenerator::index_to_name(27), "AB");
        assert_eq!(SimpleNameGenerator::index_to_name(702), "AAA");
    }

    #[test]
    fn test_is_obfuscated_name() {
        assert!(!is_obfuscated_name("MyClass"));
        assert!(!is_obfuscated_name("Main"));
        assert!(is_obfuscated_name("\u{200B}test"));
        assert!(is_obfuscated_name("te\u{200D}st"));
    }

    #[test]
    fn test_is_special_name() {
        assert!(is_special_name(".ctor"));
        assert!(is_special_name(".cctor"));
        assert!(is_special_name("<Module>"));
        assert!(is_special_name("get_Value"));
        assert!(!is_special_name("MyMethod"));
    }
}
