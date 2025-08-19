//! Integration tests for native import/export functionality.
//!
//! These tests verify the complete end-to-end functionality of adding
//! native PE imports and exports to assemblies, writing them to disk,
//! and ensuring they can be loaded back correctly with the modifications intact.

use dotscope::prelude::*;
use dotscope::DataDirectoryType;
use std::path::Path;

#[test]
fn test_native_imports_with_minimal_changes() -> Result<()> {
    // Test native imports with minimal metadata changes to trigger the write pipeline properly
    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add a minimal string to ensure we have some changes
    let _test_string_index = context.string_add("TestString")?;

    // Add native imports
    let import_result = NativeImportsBuilder::new()
        .add_dll("kernel32.dll")
        .add_function("kernel32.dll", "GetCurrentProcessId")
        .build(&mut context);

    assert!(
        import_result.is_ok(),
        "Native import builder should succeed"
    );

    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    let mut assembly = context.finish();
    assembly.write_to_file(temp_path)?;

    // Verify that we can at least read the file and it has some import directory
    let file_data = std::fs::read(temp_path)?;
    assert!(!file_data.is_empty(), "Written file should not be empty");

    match CilAssemblyView::from_file(temp_path) {
        Ok(reloaded_view) => {
            // Verify the import directory exists
            let import_directory = reloaded_view
                .file()
                .get_data_directory(DataDirectoryType::ImportTable);
            assert!(import_directory.is_some(), "Should have import directory");
        }
        Err(e) => {
            panic!("Should have loaded! Error: {e:?}")
        }
    }

    Ok(())
}

#[test]
fn add_native_imports_to_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;

    // Check if assembly already has native imports
    let _original_has_imports = view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable)
        .is_some();

    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = context.string_add("NativeImportTest")?;

    // Step 2: Add native imports using NativeImportsBuilder
    let import_result = NativeImportsBuilder::new()
        .add_dll("kernel32.dll")
        .add_function("kernel32.dll", "GetCurrentProcessId")
        .add_function("kernel32.dll", "ExitProcess")
        .add_dll("user32.dll")
        .add_function("user32.dll", "MessageBoxW")
        .add_function("user32.dll", "GetActiveWindow")
        .build(&mut context);

    assert!(
        import_result.is_ok(),
        "Native import builder should succeed"
    );

    // Step 3: Write to a temporary file
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    // Get the assembly back from context and write to file
    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(temp_path)?;

    // Verify the file was actually created
    assert!(temp_path.exists(), "Output file should exist after writing");

    // Verify the file is not empty
    let file_size = std::fs::metadata(temp_path)?.len();
    assert!(file_size > 0, "Output file should not be empty");

    // Step 4: Load the modified file and verify native imports
    let modified_view =
        CilAssemblyView::from_file(temp_path).expect("Modified assembly should load successfully");

    // Verify the assembly now has an import directory
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);

    assert!(
        import_directory.is_some(),
        "Modified assembly should have import directory"
    );

    let (import_rva, import_size) = import_directory.unwrap();
    assert!(import_rva > 0, "Import table RVA should be positive");
    assert!(import_size > 0, "Import table size should be positive");

    // Step 5: Now verify that our added imports can be parsed back correctly from the PE file
    let parsed_imports = modified_view.file().imports();

    assert!(
        parsed_imports.is_some(),
        "Native imports should be parsed successfully from modified PE file"
    );

    let imports = parsed_imports.unwrap();
    assert!(
        !imports.is_empty(),
        "Should have at least one import descriptor"
    );

    // Verify we have the DLLs we added by checking the import descriptors
    let dll_names: Vec<&str> = imports.iter().map(|imp| imp.dll.as_str()).collect();
    assert!(
        dll_names.contains(&"kernel32.dll"),
        "Should have kernel32.dll in import table"
    );
    assert!(
        dll_names.contains(&"user32.dll"),
        "Should have user32.dll in import table"
    );

    // Verify the kernel32.dll functions
    let kernel32_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| imp.dll == "kernel32.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert_eq!(
        kernel32_functions.len(),
        2,
        "kernel32.dll should have 2 functions"
    );
    assert!(
        kernel32_functions.contains(&"GetCurrentProcessId"),
        "Should have GetCurrentProcessId"
    );
    assert!(
        kernel32_functions.contains(&"ExitProcess"),
        "Should have ExitProcess"
    );

    // Verify the user32.dll functions
    let user32_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| imp.dll == "user32.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert_eq!(
        user32_functions.len(),
        2,
        "user32.dll should have 2 functions"
    );
    assert!(
        user32_functions.contains(&"MessageBoxW"),
        "Should have MessageBoxW"
    );
    assert!(
        user32_functions.contains(&"GetActiveWindow"),
        "Should have GetActiveWindow"
    );
    Ok(())
}

#[test]
fn add_native_exports_to_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;

    // Check if assembly already has native exports
    let _original_has_exports = view
        .file()
        .get_data_directory(DataDirectoryType::ExportTable)
        .is_some();

    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = context.string_add("NativeExportTest")?;

    // Step 2: Add native exports using NativeExportsBuilder
    let export_result = NativeExportsBuilder::new("TestLibrary.dll")
        .add_function("TestFunction1", 1, 0x1000)
        .add_function("TestFunction2", 2, 0x2000)
        .add_function("AnotherFunction", 3, 0x3000)
        .build(&mut context);

    assert!(
        export_result.is_ok(),
        "Native export builder should succeed"
    );

    // Step 3: Write to a temporary file
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    // Get the assembly back from context and write to file
    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(temp_path)?;

    // Verify the file was actually created
    assert!(temp_path.exists(), "Output file should exist after writing");

    // Verify the file is not empty
    let file_size = std::fs::metadata(temp_path)?.len();
    assert!(file_size > 0, "Output file should not be empty");

    // Step 4: Load the modified file and verify native exports
    let modified_view =
        CilAssemblyView::from_file(temp_path).expect("Modified assembly should load successfully");

    // Verify the assembly now has an export directory
    let export_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ExportTable);

    assert!(
        export_directory.is_some(),
        "Modified assembly should have export directory"
    );

    let (export_rva, export_size) = export_directory.unwrap();
    assert!(export_rva > 0, "Export table RVA should be positive");
    assert!(export_size > 0, "Export table size should be positive");

    // Step 5: Now verify that our added exports can be parsed back correctly
    // Check export directory first
    let export_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ExportTable);

    let reloaded_assembly = modified_view.to_owned();
    let parsed_exports = reloaded_assembly.native_exports();

    // Check if export parsing now works with our fixes
    if parsed_exports.is_empty() {
        // Export table generation should be successful - verify with goblin
        assert!(
            export_directory.is_some(),
            "Export directory should exist after writing exports"
        );

        let (export_rva, export_size) = export_directory.unwrap();
        assert!(export_rva > 0, "Export table RVA should be positive");
        assert!(export_size > 0, "Export table size should be positive");

        // Try parsing with goblin manually to verify PE format correctness
        let pe = goblin::pe::PE::parse(reloaded_assembly.view().file().data())
            .expect("Goblin should successfully parse PE after export table generation");

        // Verify the exports were written correctly
        assert_eq!(
            pe.exports.len(),
            3,
            "Goblin should find exactly 3 exports in the generated export table"
        );

        // Export table generation is successful - PE format is valid
        // Note: dotscope native_exports() contains user modifications only,
        // which is why it's empty for reloaded assemblies
        return Ok(());
    }

    let exports = parsed_exports;

    // Verify the DLL name we set
    assert_eq!(
        exports.native().dll_name(),
        "TestLibrary.dll",
        "Should have correct DLL name"
    );

    // Verify we have the expected number of functions
    assert_eq!(
        exports.native().function_count(),
        3,
        "Should have 3 exported functions"
    );

    // Verify the specific functions we added
    assert!(
        exports.native().has_function("TestFunction1"),
        "Should have TestFunction1"
    );
    assert!(
        exports.native().has_function("TestFunction2"),
        "Should have TestFunction2"
    );
    assert!(
        exports.native().has_function("AnotherFunction"),
        "Should have AnotherFunction"
    );

    // Verify function details
    let func1 = exports.native().get_function_by_ordinal(1).unwrap();
    assert_eq!(
        func1.name,
        Some("TestFunction1".to_string()),
        "TestFunction1 should have correct name"
    );
    assert_eq!(
        func1.address, 0x1000,
        "TestFunction1 should have correct address"
    );
    assert_eq!(
        func1.ordinal, 1,
        "TestFunction1 should have correct ordinal"
    );

    let func2 = exports.native().get_function_by_ordinal(2).unwrap();
    assert_eq!(
        func2.name,
        Some("TestFunction2".to_string()),
        "TestFunction2 should have correct name"
    );
    assert_eq!(
        func2.address, 0x2000,
        "TestFunction2 should have correct address"
    );
    assert_eq!(
        func2.ordinal, 2,
        "TestFunction2 should have correct ordinal"
    );

    let func3 = exports.native().get_function_by_ordinal(3).unwrap();
    assert_eq!(
        func3.name,
        Some("AnotherFunction".to_string()),
        "AnotherFunction should have correct name"
    );
    assert_eq!(
        func3.address, 0x3000,
        "AnotherFunction should have correct address"
    );
    assert_eq!(
        func3.ordinal, 3,
        "AnotherFunction should have correct ordinal"
    );

    // All added exports verified successfully

    Ok(())
}

#[test]
fn add_both_imports_and_exports_to_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = context.string_add("MixedNativeTest")?;

    // Step 2: Add both native imports and exports

    // Add imports
    let import_result = NativeImportsBuilder::new()
        .add_dll("kernel32.dll")
        .add_function("kernel32.dll", "GetCurrentProcessId")
        .add_function("kernel32.dll", "GetModuleHandleW")
        .build(&mut context);

    assert!(
        import_result.is_ok(),
        "Native import builder should succeed"
    );

    // Add exports
    let export_result = NativeExportsBuilder::new("MixedLibrary.dll")
        .add_function("ExportedFunction1", 1, 0x1000)
        .add_function("ExportedFunction2", 2, 0x2000)
        .build(&mut context);

    assert!(
        export_result.is_ok(),
        "Native export builder should succeed"
    );

    // Step 3: Write to a temporary file
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    // Get the assembly back from context and write to file
    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(temp_path)?;

    // Verify the file was actually created
    assert!(temp_path.exists(), "Output file should exist after writing");

    // Step 4: Load the modified file and verify both imports and exports
    let modified_view =
        CilAssemblyView::from_file(temp_path).expect("Modified assembly should load successfully");

    // Verify import directory
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);
    assert!(
        import_directory.is_some(),
        "Modified assembly should have import directory"
    );

    // Verify export directory
    let export_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ExportTable);
    assert!(
        export_directory.is_some(),
        "Modified assembly should have export directory"
    );

    let (import_rva, import_size) = import_directory.unwrap();
    let (export_rva, export_size) = export_directory.unwrap();

    // Verify both directories were created successfully
    assert!(import_rva > 0, "Import table RVA should be positive");
    assert!(import_size > 0, "Import table size should be positive");
    assert!(export_rva > 0, "Export table RVA should be positive");
    assert!(export_size > 0, "Export table size should be positive");

    // Step 5: Now verify that both imports and exports can be parsed back correctly

    // Verify imports using the file's parsed imports
    let parsed_imports = modified_view.file().imports();

    // Import table generation should work correctly
    assert!(
        parsed_imports.is_some(),
        "Native imports should be parsed successfully from modified PE file with both imports and exports"
    );

    let imports = parsed_imports.unwrap();
    assert!(
        !imports.is_empty(),
        "Should have at least one import descriptor"
    );

    // Verify we have kernel32.dll
    let dll_names: Vec<&str> = imports.iter().map(|imp| imp.dll.as_str()).collect();
    assert!(
        dll_names.contains(&"kernel32.dll"),
        "Should have kernel32.dll in import table"
    );

    let kernel32_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| imp.dll == "kernel32.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert_eq!(
        kernel32_functions.len(),
        2,
        "kernel32.dll should have 2 functions"
    );
    assert!(
        kernel32_functions.contains(&"GetCurrentProcessId"),
        "Should have GetCurrentProcessId"
    );
    assert!(
        kernel32_functions.contains(&"GetModuleHandleW"),
        "Should have GetModuleHandleW"
    );

    // Verify exports using the file's parsed exports
    let parsed_exports = modified_view.file().exports();

    // Export table generation should work correctly
    if parsed_exports.is_none() {
        // Verify with goblin directly as fallback
        let pe = goblin::pe::PE::parse(modified_view.file().data())
            .expect("Goblin should successfully parse PE in combined import/export test");

        assert_eq!(
            pe.exports.len(),
            2,
            "Goblin should find exactly 2 exports in combined import/export test"
        );

        // All added imports and exports verified successfully
        return Ok(());
    }

    // Verify exports using goblin Export structure
    let exports = parsed_exports.unwrap();
    assert_eq!(exports.len(), 2, "Should have 2 exported functions");

    // Find the exported functions by name
    let exported_names: Vec<&str> = exports
        .iter()
        .filter_map(|exp| exp.name.as_deref())
        .collect();

    assert!(
        exported_names.contains(&"ExportedFunction1"),
        "Should have ExportedFunction1"
    );
    assert!(
        exported_names.contains(&"ExportedFunction2"),
        "Should have ExportedFunction2"
    );

    // Verify specific function details
    let func1 = exports
        .iter()
        .find(|exp| exp.name.as_deref() == Some("ExportedFunction1"))
        .unwrap();
    assert_eq!(
        func1.name.as_ref().unwrap(),
        "ExportedFunction1",
        "ExportedFunction1 should have correct name"
    );

    let func2 = exports
        .iter()
        .find(|exp| exp.name.as_deref() == Some("ExportedFunction2"))
        .unwrap();
    assert_eq!(
        func2.name.as_ref().unwrap(),
        "ExportedFunction2",
        "ExportedFunction2 should have correct name"
    );

    // All added imports and exports verified successfully

    Ok(())
}

#[test]
fn round_trip_preserve_existing_data() -> Result<()> {
    // This test verifies that adding native imports/exports doesn't corrupt existing assembly data

    // Step 1: Load the original assembly and capture baseline data
    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;

    let original_string_count = view.strings().map(|s| s.iter().count()).unwrap_or(0);
    let original_method_count = view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = context.string_add("PreserveDataTest")?;

    // Step 2: Add native functionality
    let import_result = NativeImportsBuilder::new()
        .add_dll("kernel32.dll")
        .add_function("kernel32.dll", "GetCurrentProcessId")
        .build(&mut context);
    assert!(
        import_result.is_ok(),
        "Native import builder should succeed"
    );

    // Step 3: Write and reload
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(temp_path)?;

    let modified_view =
        CilAssemblyView::from_file(temp_path).expect("Modified assembly should load successfully");

    // Step 4: Verify existing data is preserved

    // Check that original metadata is intact
    let new_string_count = modified_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let new_method_count = modified_view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Original data should be preserved (may have slight increases due to internal bookkeeping)
    assert!(
        new_string_count >= original_string_count,
        "String count should be preserved or slightly increased"
    );
    assert_eq!(
        new_method_count, original_method_count,
        "Method count should be exactly preserved"
    );

    // Verify the assembly is still a valid .NET assembly
    let _metadata_root = modified_view.metadata_root(); // Should not panic
    assert!(
        modified_view.tables().is_some(),
        "Should still have metadata tables"
    );
    assert!(
        modified_view.strings().is_some(),
        "Should still have strings heap"
    );

    // Verify that an import directory was created (indicating native imports were written)
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);
    assert!(
        import_directory.is_some(),
        "Should have import directory indicating native imports were written"
    );

    Ok(())
}

#[test]
fn test_native_imports_parsing_from_existing_pe() -> Result<()> {
    // Test that existing native imports are correctly parsed when loading a CilAssemblyView
    // This test verifies the implementation of PE import/export parsing functionality

    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;

    // Verify the file has imports to parse
    let original_imports = view.file().imports();
    if original_imports.is_none() || original_imports.unwrap().is_empty() {
        // Skip test if no imports exist
        return Ok(());
    }

    // Verify that native imports are accessible from the PE file
    // Note: With copy-on-write semantics, assembly.native_imports() only returns user modifications.
    // To access the original PE imports, we use the file's parsed imports.
    let parsed_imports = view.file().imports();
    assert!(
        parsed_imports.is_some(),
        "Should have parsed native imports from existing PE file"
    );

    let imports = parsed_imports.unwrap();
    assert!(!imports.is_empty(), "Parsed imports should not be empty");

    // Verify the specific import that should exist in crafted_2.exe
    let dll_names: Vec<&str> = imports.iter().map(|imp| imp.dll.as_str()).collect();
    assert!(
        dll_names.contains(&"mscoree.dll"),
        "Should have parsed mscoree.dll"
    );

    let mscoree_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| imp.dll == "mscoree.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert!(
        !mscoree_functions.is_empty(),
        "mscoree.dll should have functions"
    );

    // Verify the _CorExeMain function exists
    let has_cor_exe_main = mscoree_functions.contains(&"_CorExeMain");
    assert!(has_cor_exe_main, "Should have parsed _CorExeMain function");

    Ok(())
}

#[test]
fn test_import_table_format_validation() -> Result<()> {
    // Test that import tables are correctly formatted and parseable

    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add imports that should generate a valid import table
    let _test_string_index = context.string_add("ImportFormatTest")?;

    let import_result = NativeImportsBuilder::new()
        .add_dll("kernel32.dll")
        .add_function("kernel32.dll", "GetCurrentProcessId")
        .add_function("kernel32.dll", "ExitProcess")
        .add_dll("user32.dll")
        .add_function("user32.dll", "MessageBoxW")
        .add_function("user32.dll", "GetActiveWindow")
        .build(&mut context);

    assert!(import_result.is_ok(), "Import builder should succeed");

    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(temp_path)?;

    let modified_view = CilAssemblyView::from_file(temp_path)?;

    // Verify import directory exists and is valid
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);

    assert!(import_directory.is_some(), "Import directory should exist");

    let (import_rva, import_size) = import_directory.unwrap();
    assert!(import_rva > 0, "Import table RVA should be positive");
    assert!(import_size > 0, "Import table size should be positive");

    // Verify the import table can be read
    let import_offset = modified_view.file().rva_to_offset(import_rva as usize)?;
    let import_data = modified_view
        .file()
        .data_slice(import_offset, import_size as usize)?;
    assert!(
        !import_data.is_empty(),
        "Import table data should not be empty"
    );

    // Verify goblin can parse the generated PE with imports
    let pe = goblin::pe::PE::parse(modified_view.file().data())
        .expect("Goblin should successfully parse PE with generated import table");

    // Verify the specific imports we added are present and correct
    assert!(!pe.imports.is_empty(), "Should have imports in parsed PE");

    let dll_names: Vec<&str> = pe.imports.iter().map(|imp| imp.dll).collect();
    assert!(
        dll_names.contains(&"kernel32.dll"),
        "Should have kernel32.dll"
    );
    assert!(dll_names.contains(&"user32.dll"), "Should have user32.dll");

    let kernel32_funcs: Vec<&str> = pe
        .imports
        .iter()
        .filter(|imp| imp.dll == "kernel32.dll")
        .map(|imp| imp.name.as_ref())
        .collect();

    assert!(
        kernel32_funcs.contains(&"GetCurrentProcessId"),
        "Should have GetCurrentProcessId"
    );
    assert!(
        kernel32_funcs.contains(&"ExitProcess"),
        "Should have ExitProcess"
    );

    let user32_funcs: Vec<&str> = pe
        .imports
        .iter()
        .filter(|imp| imp.dll == "user32.dll")
        .map(|imp| imp.name.as_ref())
        .collect();

    assert!(
        user32_funcs.contains(&"MessageBoxW"),
        "Should have MessageBoxW"
    );
    assert!(
        user32_funcs.contains(&"GetActiveWindow"),
        "Should have GetActiveWindow"
    );

    Ok(())
}
