//! Smart renaming subsystem for obfuscated .NET identifiers.
//!
//! This module provides a trait-based renaming pipeline that replaces obfuscated
//! type, method, field, and parameter names with readable identifiers. The pipeline
//! supports two providers:
//!
//! - [`SimpleProvider`](providers::SimpleProvider) — sequential alphabetic names (default)
//! - [`LocalProvider`](providers::local::LocalProvider) — LLM-powered semantic names (requires `smart-rename` feature)
//!
//! # Two-Phase Architecture
//!
//! Renaming is split into **collect** and **apply** phases to work around the
//! `CilObject` → `CilAssembly` consumption boundary in `execute_cleanup()`:
//!
//! 1. [`renames_collect()`] — runs on `&CilObject` (before consumption), walks metadata
//!    tables, identifies obfuscated names, and generates replacement entries.
//! 2. [`renames_apply()`] — runs on `&mut CilAssembly` (after consumption), applies
//!    string heap modifications and handles shared-offset splitting.

mod cascade;
mod config;
mod context;
mod features;
mod phases;
mod prompt;
mod providers;
mod validate;

pub use config::SmartRenameConfig;

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::CilAssembly,
    deobfuscation::utils::{is_obfuscated_name, is_special_name},
    metadata::tables::{FieldRaw, MethodDefRaw, ParamRaw, TableDataOwned, TableId, TypeDefRaw},
    CilObject, Result,
};

use self::{
    cascade::CascadeRenamer,
    providers::{SimpleNameGenerator, SimpleProvider},
};

/// A provider that generates names from context.
///
/// Implementors must be `Send + Sync` for use from rayon parallel iterators.
pub trait RenameProvider: Send + Sync {
    /// Returns the provider name for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Performs one-time initialization (load model, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails (e.g., model file not found).
    fn initialize(&mut self) -> Result<()>;

    /// Suggests a name for one identifier given its extracted features.
    ///
    /// Returns `None` if the provider cannot produce a valid name
    /// (caller uses fallback).
    ///
    /// # Arguments
    ///
    /// * `context` - The extracted features for the identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if inference fails unexpectedly.
    fn suggest_name(&self, context: &context::RenameContext) -> Result<Option<String>>;

    /// Performs cleanup (unload model, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A single rename operation to be applied to the assembly.
#[derive(Debug, Clone)]
pub struct RenameEntry {
    /// Which metadata table contains the row to rename.
    pub table_id: TableId,
    /// Row ID within the table (1-based).
    pub rid: u32,
    /// Original string heap index of the name being replaced.
    pub string_index: u32,
    /// The new name to assign.
    pub new_name: String,
}

/// Collects rename entries using the cascade engine with a smart provider.
///
/// When a [`SmartRenameConfig`] is provided, creates the appropriate provider
/// and runs the full cascade (anchors → phases → members → types).
/// Otherwise falls back to the simple sequential rename strategy.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for obfuscated names.
/// * `config` - Optional smart rename configuration. When `Some`, uses the
///   cascade engine with the configured provider.
///
/// # Returns
///
/// A vector of rename entries ready for [`renames_apply()`].
///
/// # Errors
///
/// Returns an error if provider initialization or name suggestion fails.
pub fn renames_collect(
    assembly: &CilObject,
    config: Option<&SmartRenameConfig>,
) -> Result<Vec<RenameEntry>> {
    if let Some(cfg) = config {
        let mut provider = providers::create_provider(Some(cfg));
        provider.initialize()?;
        let fallback = SimpleProvider::new();
        let cascade = CascadeRenamer::new(assembly, provider.as_ref(), &fallback, cfg.clone());
        let entries = cascade.execute()?;
        provider.shutdown()?;
        Ok(entries)
    } else {
        execute_simple_rename(assembly)
    }
}

/// Applies collected rename entries to the assembly's string heap.
///
/// Handles shared string offsets correctly:
/// - **First rename** at an offset: uses `string_update()` (affects all rows at that offset).
/// - **Subsequent different names** at the same offset: uses `string_add()` to allocate a
///   new string, then `table_row_update()` to point the specific row at it.
///
/// # Arguments
///
/// * `cil_assembly` - The mutable assembly to apply renames to.
/// * `entries` - The rename entries to apply.
///
/// # Returns
///
/// The number of identifiers successfully renamed.
///
/// # Errors
///
/// Returns an error if string heap mutation or table row update fails.
pub fn renames_apply(cil_assembly: &mut CilAssembly, entries: Vec<RenameEntry>) -> Result<usize> {
    if entries.is_empty() {
        return Ok(0);
    }

    let mut renamed_count: usize = 0;

    // Track which string offsets have already been renamed and to what name
    let mut renamed_offsets: HashMap<u32, String> = HashMap::new();

    for entry in &entries {
        if let Some(existing_name) = renamed_offsets.get(&entry.string_index) {
            if *existing_name == entry.new_name {
                // Same name as first rename — string_update already covers this
                renamed_count = renamed_count.saturating_add(1);
                continue;
            }
            // Different name at same offset — allocate new string and update the row
            let change_ref = cil_assembly.string_add(&entry.new_name)?;
            let placeholder = change_ref.placeholder();
            update_row_name_field(cil_assembly, entry.table_id, entry.rid, placeholder)?;
            renamed_count = renamed_count.saturating_add(1);
        } else {
            // First rename at this offset — modify in place
            if cil_assembly
                .string_update(entry.string_index, &entry.new_name)
                .is_ok()
            {
                renamed_offsets.insert(entry.string_index, entry.new_name.clone());
                renamed_count = renamed_count.saturating_add(1);
            }
        }
    }

    Ok(renamed_count)
}

/// Executes the simple sequential rename strategy.
///
/// Preserves exact behavior of the original `rename_obfuscated_names()`:
/// iterates TypeDef → MethodDef → Field → Param tables, uses `seen_indices`
/// dedup, and generates sequential names via [`SimpleNameGenerator`].
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for obfuscated names.
///
/// # Returns
///
/// A vector of rename entries with sequential alphabetic names.
///
/// # Errors
///
/// Returns an error if metadata table access fails.
fn execute_simple_rename(assembly: &CilObject) -> Result<Vec<RenameEntry>> {
    let mut entries = Vec::new();
    let mut name_generator = SimpleNameGenerator::new();

    let Some(tables) = assembly.tables() else {
        return Ok(entries);
    };

    let Some(strings) = assembly.strings() else {
        return Ok(entries);
    };

    let mut seen_indices: HashSet<u32> = HashSet::new();

    // Collect obfuscated names from TypeDef
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for rid in 1..=typedef_table.row_count {
            if let Some(typedef) = typedef_table.get(rid) {
                // Skip <Module> (RID 1)
                if rid == 1 {
                    continue;
                }

                let name_index = typedef.type_name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::TypeDef,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_type_name(),
                            });
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
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::MethodDef,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_method_name(),
                            });
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
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::Field,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_field_name(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated parameter names from Param
    if let Some(param_table) = tables.table::<ParamRaw>() {
        for rid in 1..=param_table.row_count {
            if let Some(param) = param_table.get(rid) {
                let name_index = param.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::Param,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_param_name(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// Updates the name field of a metadata row to point at a new string.
///
/// Reads the current row, replaces the name-bearing field with
/// `new_string_placeholder`, and writes the modified row back. Handles
/// TypeDef, MethodDef, Field, and Param tables.
///
/// # Arguments
///
/// * `cil_assembly` - The assembly containing the metadata table.
/// * `table_id` - Which metadata table to update.
/// * `rid` - Row ID within the table (1-based).
/// * `new_string_placeholder` - The placeholder value from [`string_add()`]
///   pointing to the new string.
///
/// # Errors
///
/// Returns an error if the table row cannot be read or updated.
fn update_row_name_field(
    cil_assembly: &mut CilAssembly,
    table_id: TableId,
    rid: u32,
    new_string_placeholder: u32,
) -> Result<()> {
    let row_data = {
        let view = cil_assembly.view();
        let Some(tables) = view.tables() else {
            return Ok(());
        };

        match table_id {
            TableId::TypeDef => {
                let table = tables.table::<TypeDefRaw>();
                table.and_then(|t| t.get(rid)).map(|row| {
                    let mut row = row.clone();
                    row.type_name = new_string_placeholder;
                    TableDataOwned::TypeDef(row)
                })
            }
            TableId::MethodDef => {
                let table = tables.table::<MethodDefRaw>();
                table.and_then(|t| t.get(rid)).map(|row| {
                    let mut row = row.clone();
                    row.name = new_string_placeholder;
                    TableDataOwned::MethodDef(row)
                })
            }
            TableId::Field => {
                let table = tables.table::<FieldRaw>();
                table.and_then(|t| t.get(rid)).map(|row| {
                    let mut row = row.clone();
                    row.name = new_string_placeholder;
                    TableDataOwned::Field(row)
                })
            }
            TableId::Param => {
                let table = tables.table::<ParamRaw>();
                table.and_then(|t| t.get(rid)).map(|row| {
                    let mut row = row.clone();
                    row.name = new_string_placeholder;
                    TableDataOwned::Param(row)
                })
            }
            _ => None,
        }
    };

    if let Some(data) = row_data {
        cil_assembly.table_row_update(table_id, rid, data)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        cilassembly::{CilAssembly, GeneratorConfig},
        deobfuscation::renamer::{
            self,
            context::{IdentifierKind, RenameContext},
            providers::SimpleProvider,
            RenameProvider, SmartRenameConfig,
        },
        metadata::{
            tables::{MethodDefRaw, TableId, TypeDefRaw},
            validation::ValidationConfig,
        },
        test::helpers::load_sample,
        CilObject,
    };

    const RENAMER_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";
    const ORIGINAL_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/original.exe";

    #[test]
    fn test_simple_provider_via_trait() {
        let provider: Box<dyn RenameProvider> = Box::new(SimpleProvider::new());

        let ctx = RenameContext {
            kind: Some(IdentifierKind::Type),
            ..Default::default()
        };
        let name = provider.suggest_name(&ctx).unwrap();
        assert_eq!(name, Some("A".to_string()));

        let name2 = provider.suggest_name(&ctx).unwrap();
        assert_eq!(name2, Some("B".to_string()));
    }

    /// Regression test: renaming obfuscated names must preserve TypeRef substring
    /// references in the string heap.
    #[test]
    fn test_rename_preserves_typeref_substring_references() {
        let assembly = load_sample(RENAMER_SAMPLE);

        let entries = renamer::renames_collect(&assembly, None).unwrap();
        assert!(!entries.is_empty(), "Expected at least one rename entry");

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = renamer::renames_apply(&mut cil_assembly, entries).unwrap();
        assert!(count > 0, "Expected at least one rename");

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .expect("Generation with renames should produce valid assembly");

        let output_bytes = output.file().data();
        CilObject::from_mem_with_validation(output_bytes.to_vec(), ValidationConfig::production())
            .expect("Roundtrip after rename should pass production validation");
    }

    /// Clean binary should produce zero rename entries.
    #[test]
    fn test_no_renames_on_clean_assembly() {
        let assembly = load_sample(ORIGINAL_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();
        assert!(
            entries.is_empty(),
            "Clean binary should have no obfuscated names, got {}",
            entries.len()
        );
    }

    /// Exact per-table counts from the bitmono_renamer sample.
    #[test]
    fn test_collect_entry_counts() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();

        let types = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .count();
        let methods = entries
            .iter()
            .filter(|e| e.table_id == TableId::MethodDef)
            .count();
        let fields = entries
            .iter()
            .filter(|e| e.table_id == TableId::Field)
            .count();
        let params = entries
            .iter()
            .filter(|e| e.table_id == TableId::Param)
            .count();

        assert_eq!(types, 8, "TypeDef entries");
        assert_eq!(methods, 25, "MethodDef entries");
        assert_eq!(fields, 9, "Field entries");
        assert_eq!(params, 23, "Param entries");
    }

    /// Sequential type names: SimpleProvider → validate → PascalCase produces A, B, C, D, E.
    #[test]
    fn test_collect_sequential_type_names() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();

        let type_names: Vec<&str> = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .map(|e| e.new_name.as_str())
            .collect();

        assert_eq!(type_names.len(), 8);
        assert_eq!(type_names[0], "A");
        assert_eq!(type_names[1], "B");
        assert_eq!(type_names[2], "C");
        assert_eq!(type_names[3], "D");
        assert_eq!(type_names[4], "E");
        assert_eq!(type_names[5], "F");
        assert_eq!(type_names[6], "G");
        assert_eq!(type_names[7], "H");
    }

    /// All field entries should be prefixed with `f_`, all param entries with `p_`.
    #[test]
    fn test_collect_field_and_param_prefixes() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();

        for entry in entries.iter().filter(|e| e.table_id == TableId::Field) {
            assert!(
                entry.new_name.starts_with("f_"),
                "Field name '{}' should start with 'f_'",
                entry.new_name
            );
        }

        for entry in entries.iter().filter(|e| e.table_id == TableId::Param) {
            assert!(
                entry.new_name.starts_with("p_"),
                "Param name '{}' should start with 'p_'",
                entry.new_name
            );
        }
    }

    /// `.ctor` and `Main` must NOT appear in rename entries (special/non-obfuscated).
    #[test]
    fn test_collect_preserves_special_names() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();

        let strings = assembly
            .strings()
            .expect("assembly should have strings heap");

        // Collect original names for all entries
        let original_names: Vec<String> = entries
            .iter()
            .filter_map(|e| strings.get(e.string_index as usize).ok().map(String::from))
            .collect();

        assert!(
            !original_names.iter().any(|n| n == ".ctor"),
            ".ctor should not be in rename entries"
        );
        assert!(
            !original_names.iter().any(|n| n == "Main"),
            "Main should not be in rename entries"
        );
    }

    /// Full roundtrip: collect → apply → generate → reload.
    #[test]
    fn test_roundtrip_apply_and_reload() {
        let assembly = load_sample(RENAMER_SAMPLE);

        let entries = renamer::renames_collect(&assembly, None).unwrap();
        assert!(!entries.is_empty());

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = renamer::renames_apply(&mut cil_assembly, entries.clone()).unwrap();
        assert_eq!(count, entries.len(), "All entries should be applied");

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .expect("Roundtrip generation should succeed");

        CilObject::from_mem_with_validation(
            output.file().data().to_vec(),
            ValidationConfig::production(),
        )
        .expect("Reloaded assembly should pass production validation");
    }

    /// Roundtrip then verify renamed type names in output.
    #[test]
    fn test_roundtrip_verifies_renamed_types() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();
        renamer::renames_apply(&mut cil_assembly, entries).unwrap();

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .unwrap();

        let tables = output.tables().expect("output should have tables");
        let strings = output.strings().expect("output should have strings");
        let typedef_table = tables.table::<TypeDefRaw>().expect("TypeDef table");

        let mut type_names = Vec::new();
        for rid in 1..=typedef_table.row_count {
            if let Some(row) = typedef_table.get(rid) {
                if let Ok(name) = strings.get(row.type_name as usize) {
                    type_names.push(name.to_string());
                }
            }
        }

        assert!(
            type_names.contains(&"A".to_string()),
            "First renamed type 'A' should be present"
        );
        assert!(
            type_names.contains(&"<Module>".to_string()),
            "<Module> should be preserved"
        );
        assert!(
            !type_names.iter().any(|n| n.contains(' ')),
            "No type names should contain spaces after renaming, got: {:?}",
            type_names
                .iter()
                .filter(|n| n.contains(' '))
                .collect::<Vec<_>>()
        );
    }

    /// Roundtrip then verify renamed method names in output.
    /// BitMono's FullRenamer renames ALL methods (including `Main`), so the
    /// output should contain only `.ctor` (special name) and sequential names.
    #[test]
    fn test_roundtrip_verifies_renamed_methods() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();
        renamer::renames_apply(&mut cil_assembly, entries).unwrap();

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .unwrap();

        let tables = output.tables().expect("output should have tables");
        let strings = output.strings().expect("output should have strings");
        let methoddef_table = tables.table::<MethodDefRaw>().expect("MethodDef table");

        let mut method_names = Vec::new();
        for rid in 1..=methoddef_table.row_count {
            if let Some(row) = methoddef_table.get(rid) {
                if let Ok(name) = strings.get(row.name as usize) {
                    method_names.push(name.to_string());
                }
            }
        }

        assert!(
            method_names.contains(&".ctor".to_string()),
            ".ctor should be preserved, got: {:?}",
            method_names
        );
        // BitMono renames Main too, so after our renaming it becomes a sequential name.
        // Verify the first sequential method name is present.
        assert!(
            method_names.contains(&"a".to_string()),
            "First sequential method name 'a' should be present"
        );
        assert!(
            !method_names.iter().any(|n| n.contains(' ')),
            "No method names should contain spaces after renaming, got: {:?}",
            method_names
                .iter()
                .filter(|n| n.contains(' '))
                .collect::<Vec<_>>()
        );
    }

    /// `renames_collect(_, None)` should produce identical results to
    /// `renames_collect(_, Some(&SmartRenameConfig::default()))` — both use SimpleProvider.
    #[test]
    fn test_cascade_with_smart_config_none_matches_default() {
        let assembly_a = load_sample(RENAMER_SAMPLE);
        let entries_none = renamer::renames_collect(&assembly_a, None).unwrap();

        let assembly_b = load_sample(RENAMER_SAMPLE);
        let entries_default =
            renamer::renames_collect(&assembly_b, Some(&SmartRenameConfig::default())).unwrap();

        assert_eq!(
            entries_none.len(),
            entries_default.len(),
            "Both paths should produce same number of entries"
        );

        let keys_none: HashSet<(TableId, u32)> =
            entries_none.iter().map(|e| (e.table_id, e.rid)).collect();
        let keys_default: HashSet<(TableId, u32)> = entries_default
            .iter()
            .map(|e| (e.table_id, e.rid))
            .collect();
        assert_eq!(
            keys_none, keys_default,
            "Both paths should target the same (table, rid) pairs"
        );
    }

    /// Applying two entries with the same `string_index` and same `new_name` should
    /// succeed without error — the second is a no-op covered by `string_update`.
    #[test]
    fn test_apply_renames_idempotent_same_offset() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renamer::renames_collect(&assembly, None).unwrap();
        assert!(!entries.is_empty());

        // Pick the first entry and duplicate it
        let first = entries[0].clone();
        let dup = vec![first.clone(), first.clone()];

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = renamer::renames_apply(&mut cil_assembly, dup).unwrap();
        assert_eq!(
            count, 2,
            "Both entries should count as renamed (second is a covered no-op)"
        );
    }

    /// Manual test for the LLM-backed smart renamer.
    ///
    /// Requires the `smart-rename` feature and a local GGUF model file.
    /// Run with: `cargo test --release -p dotscope --lib --features smart-rename test_smart_rename_llm -- --ignored --nocapture`
    #[test]
    #[ignore]
    #[cfg(feature = "smart-rename")]
    fn test_smart_rename_llm() {
        use std::path::PathBuf;

        let model_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../qwen2.5-coder-3b-instruct-q4_k_m.gguf");
        assert!(
            model_path.exists(),
            "GGUF model not found at {}",
            model_path.display()
        );

        let assembly = load_sample(RENAMER_SAMPLE);

        let config = SmartRenameConfig {
            model_path,
            ..SmartRenameConfig::default()
        };

        let entries = renamer::renames_collect(&assembly, Some(&config)).unwrap();
        assert!(!entries.is_empty(), "Smart renamer should produce entries");

        // Log all entries for manual inspection
        for entry in &entries {
            eprintln!(
                "  {:?} RID {} → {:?}",
                entry.table_id, entry.rid, entry.new_name
            );
        }

        let types = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .count();
        let methods = entries
            .iter()
            .filter(|e| e.table_id == TableId::MethodDef)
            .count();
        let fields = entries
            .iter()
            .filter(|e| e.table_id == TableId::Field)
            .count();
        let params = entries
            .iter()
            .filter(|e| e.table_id == TableId::Param)
            .count();
        eprintln!(
            "Smart rename: {types} types, {methods} methods, {fields} fields, {params} params"
        );

        // Same entry counts as simple renamer (same identifiers detected)
        assert_eq!(types, 5, "TypeDef entries");
        assert_eq!(methods, 17, "MethodDef entries");
        assert_eq!(fields, 1, "Field entries");
        assert_eq!(params, 19, "Param entries");

        // Roundtrip: apply and regenerate
        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();
        let count = renamer::renames_apply(&mut cil_assembly, entries).unwrap();
        assert!(count > 0, "Should apply at least one rename");

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .expect("Roundtrip with smart renames should succeed");

        CilObject::from_mem_with_validation(
            output.file().data().to_vec(),
            ValidationConfig::production(),
        )
        .expect("Reloaded assembly should pass production validation");
    }
}
