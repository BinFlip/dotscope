//! Integration test for method injection roundtrip
//!
//! This test verifies that:
//! 1. We can inject a method into an assembly
//! 2. The resulting assembly is valid and loadable
//! 3. Both original and injected methods can be disassembled
//! 4. Method bodies are preserved correctly

use dotscope::{
    metadata::{
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{CodedIndex, CodedIndexType, TableId},
        token::Token,
    },
    prelude::*,
};
use std::path::Path;
use tempfile::NamedTempFile;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/WindowsBase.dll";

/// Helper function to create a test assembly for method injection testing
fn create_test_assembly() -> Result<CilAssembly> {
    let path = Path::new(TEST_ASSEMBLY_PATH);
    if !path.exists() {
        panic!("Test assembly not found at: {}", path.display());
    }

    let view = CilAssemblyView::from_file(path)?;
    Ok(CilAssembly::new(view))
}

#[test]
fn test_method_injection_roundtrip() -> Result<()> {
    // Step 1: Create a modified assembly with method injection
    let temp_file = NamedTempFile::new()?;
    let modified_assembly = inject_hello_world_method(temp_file.path())?;

    // Step 2: Verify assembly basic integrity
    verify_assembly_integrity(&modified_assembly)?;

    // Step 3: Verify original methods still work
    verify_original_methods_intact(&modified_assembly)?;

    // Step 4: Find and verify our injected method
    verify_injected_method(&modified_assembly)?;

    Ok(())
}

fn inject_hello_world_method(output_path: &Path) -> Result<CilObject> {
    // Load assembly using factory
    let assembly = create_test_assembly()?;
    let mut context = BuilderContext::new(assembly);

    // Add user string
    let hello_index = context.userstring_add("Hello World from integration test!")?;
    let hello_string_token = Token::new(0x70000000 | hello_index);

    // Create external references
    let mscorlib_ref = create_mscorlib_ref(&mut context)?;
    let console_writeline_ref = create_console_writeline_ref(&mut context, mscorlib_ref)?;

    // Inject method
    let _method_token = MethodBuilder::new("TestInjectedMethod")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldstr(hello_string_token)?
                    .call(console_writeline_ref)?
                    .ret()?;
                Ok(())
            })
        })
        .build(&mut context)?;

    // Write modified assembly
    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(output_path)?;

    // Load the written assembly for verification
    CilObject::from_file(output_path)
}

/// Verify basic assembly integrity after modification
fn verify_assembly_integrity(assembly: &CilObject) -> Result<()> {
    // Check that essential heaps are present
    assert!(
        assembly.strings().is_some(),
        "Modified assembly should have strings heap"
    );
    assert!(
        assembly.blob().is_some(),
        "Modified assembly should have blobs heap"
    );
    assert!(
        assembly.userstrings().is_some(),
        "Modified assembly should have user strings heap"
    );
    assert!(
        assembly.tables().is_some(),
        "Modified assembly should have metadata tables"
    );

    // Verify core metadata tables exist and have content
    let tables = assembly.tables().unwrap();
    assert!(
        tables.table_row_count(TableId::Module) > 0,
        "Should have module table entries"
    );
    assert!(
        tables.table_row_count(TableId::TypeDef) > 0,
        "Should have type definition entries"
    );
    assert!(
        tables.table_row_count(TableId::MethodDef) > 0,
        "Should have method definition entries"
    );

    // Verify that our modifications were persisted
    let userstrings = assembly.userstrings().unwrap();
    let userstring_count = userstrings.iter().count();
    assert!(
        userstring_count > 0,
        "Should have user strings after modification"
    );

    Ok(())
}

fn verify_original_methods_intact(assembly: &CilObject) -> Result<()> {
    let methods = assembly.methods();
    let mut methods_with_bodies = 0;
    let mut methods_checked = 0;

    // Check first 100 methods to see if they have valid bodies
    for entry in methods.iter() {
        if methods_checked >= 100 {
            break;
        }

        let method = entry.value();
        if let Some(body) = method.body.get() {
            // Verify the method body is valid
            assert!(body.size_code > 0, "Method body should have non-zero size");
            methods_with_bodies += 1;
        }
        methods_checked += 1;
    }

    // We should have found many methods with bodies in a real assembly
    assert!(
        methods_with_bodies > 10,
        "Should find many methods with bodies in a real assembly, found: {methods_with_bodies}/{methods_checked}"
    );

    Ok(())
}

fn verify_injected_method(assembly: &CilObject) -> Result<()> {
    let methods = assembly.methods();

    // Look for our injected method
    let mut found_injected_method = false;

    for entry in methods.iter() {
        let method = entry.value();
        if method.name == "TestInjectedMethod" {
            found_injected_method = true;

            // Verify it has a method body
            let body = method
                .body
                .get()
                .ok_or_else(|| dotscope::Error::Malformed {
                    message: "Injected method should have a body".to_string(),
                    file: file!(),
                    line: line!(),
                })?;

            // Verify the body has reasonable size (our method should be small)
            assert!(
                body.size_code > 0 && body.size_code < 100,
                "Injected method body size should be reasonable: {}",
                body.size_code
            );

            // Verify method body properties
            assert!(
                body.size_header > 0,
                "Method should have a valid header size"
            );
            assert!(
                body.max_stack >= 1,
                "Method should have reasonable max stack size: {}",
                body.max_stack
            );

            // Try to get the method's basic blocks (this exercises the disassembler)
            let blocks: Vec<_> = method.blocks().collect();
            assert!(
                !blocks.is_empty(),
                "Method should have at least one basic block for disassembly"
            );

            // Verify we can iterate over the blocks without error
            for (index, block) in blocks.iter().enumerate() {
                assert!(
                    !block.1.instructions.is_empty() || index == 0,
                    "Basic block {index} should have instructions or be the first block"
                );
            }

            // Detailed instruction verification
            verify_injected_method_instructions(&blocks)?;

            break;
        }
    }

    assert!(
        found_injected_method,
        "Should find the injected method 'TestInjectedMethod' in the assembly"
    );
    Ok(())
}

/// Verify that the injected method has the correct instructions
fn verify_injected_method_instructions(
    blocks: &[(usize, &dotscope::assembly::BasicBlock)],
) -> Result<()> {
    // Our injected method should have exactly one basic block
    assert_eq!(
        blocks.len(),
        1,
        "Injected method should have exactly one basic block"
    );

    let (_, block) = &blocks[0];
    let instructions = &block.instructions;

    // Our method should have exactly 3 instructions: ldstr, call, ret
    assert_eq!(
        instructions.len(),
        3,
        "Injected method should have exactly 3 instructions (ldstr, call, ret), found: {}",
        instructions.len()
    );

    // Verify instruction sequence matches our injected method:
    // 1. ldstr (load string)
    // 2. call (call Console.WriteLine)
    // 3. ret (return)

    assert_eq!(
        instructions[0].mnemonic, "ldstr",
        "First instruction should be ldstr, found: {}",
        instructions[0].mnemonic
    );

    assert_eq!(
        instructions[1].mnemonic, "call",
        "Second instruction should be call, found: {}",
        instructions[1].mnemonic
    );

    assert_eq!(
        instructions[2].mnemonic, "ret",
        "Third instruction should be ret, found: {}",
        instructions[2].mnemonic
    );

    // Verify ldstr operand is a valid user string token
    if let Operand::Token(token) = &instructions[0].operand {
        // User string tokens start with 0x70
        assert!(
            (token.value() & 0xFF000000) == 0x70000000,
            "ldstr operand should be a user string token (0x70xxxxxx), found: 0x{:08X}",
            token.value()
        );
    } else {
        panic!(
            "ldstr operand should be a token, found: {:?}",
            &instructions[0].operand
        );
    }

    // Verify call operand is a valid method reference token
    if let Operand::Token(token) = &instructions[1].operand {
        // MemberRef tokens start with 0x0A
        assert!(
            (token.value() & 0xFF000000) == 0x0A000000,
            "call operand should be a MemberRef token (0x0Axxxxxx), found: 0x{:08X}",
            token.value()
        );
    } else {
        panic!(
            "call operand should be a token, found: {:?}",
            &instructions[1].operand
        );
    }

    // ret instruction should have no operand
    if let Operand::None = &instructions[2].operand {
        // This is expected
    } else {
        panic!(
            "ret instruction should have no operand, found: {:?}",
            &instructions[2].operand
        );
    }

    println!("✅ Injected method instructions verified successfully:");
    for (i, instruction) in instructions.iter().enumerate() {
        println!(
            "   {}: {} (operand: {:?})",
            i, instruction.mnemonic, instruction.operand
        );
    }

    Ok(())
}

/// Helper function to create an AssemblyRef for System.Runtime
fn create_mscorlib_ref(context: &mut BuilderContext) -> Result<Token> {
    AssemblyRefBuilder::new()
        .name("System.Runtime")
        .version(8, 0, 0, 0)
        .public_key_token(&[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a])
        .build(context)
}

/// Helper function to create a MemberRef for System.Console.WriteLine(string)
fn create_console_writeline_ref(
    context: &mut BuilderContext,
    mscorlib_ref: Token,
) -> Result<Token> {
    // Create TypeRef for System.Console
    let console_typeref = TypeRefBuilder::new()
        .name("Console")
        .namespace("System")
        .resolution_scope(CodedIndex::new(
            TableId::AssemblyRef,
            mscorlib_ref.row(),
            CodedIndexType::ResolutionScope,
        ))
        .build(context)?;

    // Create method signature for WriteLine(string)
    let signature = create_writeline_signature()?;

    // Create MemberRef for Console.WriteLine
    MemberRefBuilder::new()
        .name("WriteLine")
        .class(CodedIndex::new(
            TableId::TypeRef,
            console_typeref.row(),
            CodedIndexType::MemberRefParent,
        ))
        .signature(&signature)
        .build(context)
}

/// Helper function to create the method signature for Console.WriteLine(string)
fn create_writeline_signature() -> Result<Vec<u8>> {
    let signature = SignatureMethod {
        has_this: false,
        explicit_this: false,
        default: true,
        vararg: false,
        cdecl: false,
        stdcall: false,
        thiscall: false,
        fastcall: false,
        param_count_generic: 0,
        param_count: 1,
        return_type: SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::Void,
        },
        params: vec![SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::String,
        }],
        varargs: Vec::new(),
    };

    encode_method_signature(&signature)
}
