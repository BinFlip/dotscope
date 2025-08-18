//! # .NET Assembly Code Injection Example
//!
//! **What this example teaches:**
//! - Injecting new methods into existing .NET assemblies
//! - Creating external assembly references (mscorlib/System.Runtime)
//! - Building type references and member references for BCL types
//! - Adding user strings for `ldstr` instructions
//! - Using the high-level MethodBuilder and MethodBodyBuilder APIs
//! - Generating CIL bytecode using InstructionAssembler
//! - Finding suitable injection targets in existing assemblies
//! - Complete assembly modification workflow with validation
//!
//! **When to use this pattern:**
//! - Code instrumentation and profiling hooks
//! - Adding logging or debugging functionality
//! - Implementing aspect-oriented programming features
//! - Runtime patching and hot-fixing scenarios
//! - Educational purposes to understand .NET IL injection
//!
//! **Prerequisites:**
//! - Understanding of .NET metadata structures
//! - Basic knowledge of CIL (Common Intermediate Language)
//! - Familiarity with method signatures and calling conventions

use dotscope::{
    metadata::{
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{CodedIndex, CodedIndexType, TableId},
        token::Token,
    },
    prelude::*,
};
use std::{env, path::Path};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input-assembly> <output-assembly>", args[0]);
        eprintln!();
        eprintln!("This example demonstrates .NET assembly code injection:");
        eprintln!("  • Finding or creating external assembly references");
        eprintln!("  • Creating type and member references for BCL types");
        eprintln!("  • Adding user strings for string literals");
        eprintln!("  • Injecting new static methods with CIL implementation");
        eprintln!("  • Finding suitable injection targets in existing types");
        eprintln!("  • Complete workflow with validation and PE generation");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} input.dll injected.dll", args[0]);
        eprintln!();
        eprintln!("The injected method will be:");
        eprintln!("  public static void PrintHelloWorld()");
        eprintln!("  {{");
        eprintln!("      System.Console.WriteLine(\"Hello World from dotscope!\");");
        eprintln!("  }}");
        return Ok(());
    }

    let input_path = Path::new(&args[1]);
    let output_path = Path::new(&args[2]);

    println!("🚀 .NET Assembly Code Injection Tool");
    println!("📖 Input:  {}", input_path.display());
    println!("📝 Output: {}", output_path.display());
    println!();

    // Step 1: Load the assembly for modification
    println!("📂 Loading assembly for modification...");
    let view = CilAssemblyView::from_file(input_path).map_err(|e| {
        eprintln!("❌ Failed to load assembly: {e}");
        eprintln!("   Make sure the file is a valid .NET assembly");
        e
    })?;

    // Create mutable assembly and builder context
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);
    println!("✅ Assembly loaded successfully");
    println!();

    // Step 2: Find injection target using CilObject for type discovery
    println!("🔍 Finding suitable injection target...");
    let target_type_token = find_injection_target(&context)?;
    println!(
        "✅ Selected injection target: TypeDef token {:#08X}",
        target_type_token.value()
    );
    println!();

    // Step 3: Add user string for the hello world message
    println!("📝 Adding user string for hello world message...");
    let hello_index = context.userstring_add("Hello World from dotscope!")?;
    let hello_string_token = Token::new(0x70000000 | hello_index); // UserString table prefix
    println!(
        "✅ Added user string at index {}, token: {:#08X}",
        hello_index,
        hello_string_token.value()
    );
    println!();

    // Step 4: Create external references for System.Console.WriteLine
    println!("🔗 Creating external references for System.Console.WriteLine...");
    let mscorlib_ref = find_or_create_mscorlib_ref(&mut context)?;
    let console_writeline_ref = create_console_writeline_ref(&mut context, mscorlib_ref)?;
    println!(
        "✅ Created mscorlib reference: {:#08X}",
        mscorlib_ref.value()
    );
    println!(
        "✅ Created Console.WriteLine reference: {:#08X}",
        console_writeline_ref.value()
    );
    println!();

    // Step 5: Create the hello world method
    println!("🛠️  Injecting PrintHelloWorld method...");
    let method_token = MethodBuilder::new("PrintHelloWorld")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldstr(hello_string_token)? // Load the hello world string
                    .call(console_writeline_ref)? // Call Console.WriteLine
                    .ret()?; // Return void
                Ok(())
            })
        })
        .build(&mut context)?;

    println!(
        "✅ Injected method with token: {:#08X}",
        method_token.value()
    );
    println!();

    // Step 6: Validate and write the modified assembly
    println!("💾 Writing modified assembly...");
    let mut assembly = context.finish();
    assembly.validate_and_apply_changes().map_err(|e| {
        eprintln!("❌ Validation failed: {e}");
        e
    })?;

    assembly.write_to_file(output_path).map_err(|e| {
        eprintln!("❌ Failed to write assembly: {e}");
        e
    })?;

    println!(
        "✅ Successfully wrote modified assembly to {}",
        output_path.display()
    );
    println!();
    println!("🎉 Code injection completed successfully!");
    println!();
    println!("📋 Summary:");
    println!("   • Added 1 user string");
    println!("   • Created external references to System.Console.WriteLine");
    println!("   • Injected 1 static method: PrintHelloWorld()");
    println!("   • Generated valid PE file with proper metadata");
    println!();
    println!("💡 You can now call the injected method from other .NET code:");
    println!("   YourAssembly.YourType.PrintHelloWorld();");

    Ok(())
}

/// Find a suitable type for method injection using the assembly's TypeDef table
fn find_injection_target(_context: &BuilderContext) -> Result<Token> {
    // For this example, we'll use a simple approach and just use the first TypeDef
    // In a real implementation, you could:
    // 1. Load the assembly with CilObject to get rich type information
    // 2. Iterate through TypeDef table directly to find suitable classes
    // 3. Create a new class specifically for injection

    // Use the first TypeDef entry (which should exist in any assembly with types)
    let first_typedef_token = Token::new(0x02000001); // TypeDef table, RID 1

    println!(
        "   Using TypeDef token: {:#08X}",
        first_typedef_token.value()
    );
    println!(
        "   💡 In a real implementation, you could use CilObject to find ideal injection targets"
    );

    Ok(first_typedef_token)
}

/// Find existing mscorlib/System.Runtime reference or create a new one
fn find_or_create_mscorlib_ref(context: &mut BuilderContext) -> Result<Token> {
    // In a real implementation, we would search existing AssemblyRef table
    // for mscorlib, System.Runtime, System.Console, etc.
    // For this example, we'll create a new reference to System.Runtime

    let mscorlib_token = AssemblyRefBuilder::new()
        .name("System.Runtime")
        .version(8, 0, 0, 0) // .NET 8 version
        .public_key_token(&[
            0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a, // System.Runtime public key token
        ])
        .build(context)?;

    Ok(mscorlib_token)
}

/// Create TypeRef for System.Console and MemberRef for WriteLine method
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

    // Create method signature for Console.WriteLine(string)
    let writeline_signature = create_writeline_signature()?;

    // Create MemberRef for Console.WriteLine method
    let memberref_token = MemberRefBuilder::new()
        .name("WriteLine")
        .class(CodedIndex::new(
            TableId::TypeRef,
            console_typeref.row(),
            CodedIndexType::MemberRefParent,
        ))
        .signature(&writeline_signature)
        .build(context)?;

    Ok(memberref_token)
}

/// Create method signature for Console.WriteLine(string)
fn create_writeline_signature() -> Result<Vec<u8>> {
    let signature = SignatureMethod {
        has_this: false, // Static method
        explicit_this: false,
        default: true, // Default managed calling convention
        vararg: false,
        cdecl: false,
        stdcall: false,
        thiscall: false,
        fastcall: false,
        param_count_generic: 0,
        param_count: 1, // One string parameter
        return_type: SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::Void, // void return type
        },
        params: vec![SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::String, // string parameter
        }],
        varargs: Vec::new(),
    };

    encode_method_signature(&signature)
}
