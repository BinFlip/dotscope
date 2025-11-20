# dotscope

[![Crates.io](https://img.shields.io/crates/v/dotscope.svg)](https://crates.io/crates/dotscope)
[![Documentation](https://docs.rs/dotscope/badge.svg)](https://docs.rs/dotscope)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Build Status](https://github.com/BinFlip/dotscope/workflows/CI/badge.svg)](https://github.com/BinFlip/dotscope/actions)
[![Coverage](https://codecov.io/gh/BinFlip/dotscope/branch/main/graph/badge.svg)](https://codecov.io/gh/BinFlip/dotscope)

A high-performance, cross-platform framework for analyzing, reverse engineering, and modifying .NET PE executables. Built in pure Rust, `dotscope` provides comprehensive tooling for parsing CIL (Common Intermediate Language) bytecode, metadata structures, disassembling .NET assemblies, and creating modified assemblies without requiring Windows or the .NET runtime.

## Features

- **Efficient memory access** - Memory-mapped file access with minimal allocations and reference-based parsing
- **Complete metadata analysis** - Parse all ECMA-335 metadata tables and streams
- **Assembly modification** - Edit metadata tables, heaps, and PE structures with validation and integrity checking
- **Method injection** - Add new methods, classes, and metadata to existing assemblies with high-level builders
- **High-performance disassembly** - Fast CIL instruction decoding with control flow analysis
- **CIL encoding** - Generate CIL bytecode with label-based exception handling for method modification
- **Native PE operations** - Manage imports, exports, and native interoperability features
- **Cross-platform** - Works on Windows, Linux, macOS, and any Rust-supported platform
- **Memory safe** - Built in Rust with comprehensive error handling and fuzzing
- **Rich type system** - Full support for generics, signatures, and complex .NET types
- **Extensible architecture** - Modular design for custom analysis and tooling

## Quick Start

Add `dotscope` to your `Cargo.toml`:

```toml
[dependencies]
dotscope = "0.4.0"
```

### Raw Access Example

```rust
use dotscope::prelude::*;

fn main() -> dotscope::Result<()> {
    // Load assembly for raw access
    let view = CilAssemblyView::from_file("MyAssembly.dll".as_ref())?;
    
    // Direct access to metadata tables
    if let Some(tables) = view.tables() {
        let typedef_count = tables.table_row_count(TableId::TypeDef);
        println!("TypeDef rows: {}", typedef_count);
    }
    
    // Direct heap access
    if let Some(strings) = view.strings() {
        for (index, string) in strings.iter().take(5) {
            println!("String {}: {}", index, string);
        }
    }
    
    Ok(())
}
```

### Analysis Example

```rust
use dotscope::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load assembly for high-level analysis
    let assembly = CilObject::from_file("MyAssembly.dll".as_ref())?;
    
    // Access resolved information
    if let Some(module) = assembly.module() {
        println!("Module: {}", module.name);
    }
    
    // Iterate through resolved methods with type information
    let methods = assembly.methods();
    println!("Found {} methods", methods.len());
    
    // Examine resolved imports and exports
    let imports = assembly.imports();
    let exports = assembly.exports();
    println!("Imports: {}, Exports: {}", imports.len(), exports.len());
    
    Ok(())
}
```

### Assembly Modification Example

```rust
use dotscope::prelude::*;

fn main() -> dotscope::Result<()> {
    // Load assembly for modification
    let view = CilAssemblyView::from_file("input.dll".as_ref())?;
    let mut assembly = CilAssembly::new(view);
    
    // Add strings to metadata heaps
    let string_index = assembly.string_add("Hello from dotscope!")?;
    let user_string_index = assembly.userstring_add("Modified assembly")?;
    
    // Add native imports
    assembly.add_native_import_dll("kernel32.dll")?;
    assembly.add_native_import_function("kernel32.dll", "GetProcessId")?;
    
    // Validate and write modified assembly
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file("output.dll".as_ref())?;
    
    Ok(())
}
```

### Method Builder Example

```rust
use dotscope::prelude::*;

fn main() -> dotscope::Result<()> {
    // Load assembly and create builder context
    let view = CilAssemblyView::from_file("input.dll".as_ref())?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);
    
    // Add a user string
    let msg_index = context.userstring_add("Hello World!")?;
    let msg_token = Token::new(0x70000000 | msg_index);
    
    // Create method with CIL instructions
    let method_token = MethodBuilder::new("MyNewMethod")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(|body| {
            body.implementation(|asm| {
                asm.ldstr(msg_token)?
                    .pop()?  // Simple example: load string then pop it
                    .ret()
            })
        })
        .build(&mut context)?;
    
    // Save the modified assembly
    let mut assembly = context.finish();
    assembly.write_to_file("output.dll".as_ref())?;
    
    Ok(())
}
```

## Documentation

- **[API Documentation](https://docs.rs/dotscope)** - Complete API reference
- **[Examples](examples/)** - Working examples for common use cases
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project
- **[Security Policy](SECURITY.md)** - Security reporting and policy

## Architecture

`dotscope` is organized into several key modules:

### Core Components

- **[`prelude`]** - Convenient re-exports of commonly used types
- **[`metadata`]** - Complete ECMA-335 metadata parsing and type system
- **[`cilassembly`]** - Assembly modification with copy-on-write semantics and high-level builders
- **[`assembly`]** - CIL instruction encoding/decoding, control flow analysis, and method body construction
- **[`Error`] and [`Result`]** - Comprehensive error handling

### Raw Access (`CilAssemblyView`)

Low-level access to assembly structures provides:

- **Direct PE parsing**: Raw access to PE headers, sections, and data directories
- **Metadata streams**: Direct heap access without object resolution
- **Table iteration**: Raw table row access with manual index resolution
- **Memory-mapped data**: Efficient access to assembly contents
- **Foundation layer**: Base for both analysis and modification operations

### Analysis (`CilObject`)

High-level analysis with resolved objects provides:

- **Resolved references**: Automatic cross-reference resolution and object graphs
- **Type system**: Rich representation of .NET types, generics, and inheritance
- **Method bodies**: Parsed IL instructions with operand resolution
- **Import/export analysis**: Resolved dependency and export information
- **Convenience APIs**: Easy-to-use interfaces for common analysis tasks

### Modification (`CilAssembly`)

Mutable assembly editing provides:

- **Heap operations**: Add, update, remove items from all metadata heaps
- **Table operations**: Add, update, delete metadata table rows with validation
- **PE operations**: Manage native imports, exports, and forwarders
- **Builder APIs**: High-level builders for adding classes, methods, properties, events, and enums to existing assemblies
- **CIL Generation**: Full CIL instruction encoding with label resolution and exception handling for method modification
- **Validation**: Comprehensive integrity checking and reference resolution

### Assembly Engine

The assembly module provides comprehensive CIL processing:

**Decoding & Analysis:**

- **Instruction Decoding**: Parse individual CIL opcodes with full operand support
- **Control Flow Analysis**: Build basic blocks and control flow graphs
- **Stack Analysis**: Track stack effects and type flow
- **Exception Handling**: Parse and analyze try/catch/finally regions

**Encoding & Generation:**

- **Instruction Encoding**: Generate CIL bytecode from high-level instructions
- **Label Resolution**: Automatic branch target and exception handler resolution
- **Method Body Construction**: Build complete method bodies with local variables and exception handling
- **Assembly Modification**: Fluent API for adding new components to existing .NET assemblies

## Examples

Check out the [examples](examples/) directory for complete working examples with comprehensive documentation:

- **[Basic Usage](examples/basic.rs)** - Start here! Simple assembly loading and inspection with error handling
- **[Assembly Modification](examples/modify.rs)** - Complete guide to editing assemblies with heap and table operations
- **[Metadata Analysis](examples/metadata.rs)** - Deep dive into assembly metadata and dependency tracking  
- **[Disassembly](examples/disassembly.rs)** - CIL instruction disassembly and method body analysis
- **[Type System](examples/types.rs)** - Working with .NET types, generics, and inheritance
- **[Comprehensive Analysis](examples/comprehensive.rs)** - Full-featured analysis combining all capabilities
- **[Method Analysis](examples/method_analysis.rs)** - Exhaustive single-method inspection
- **[Low-Level API](examples/lowlevel.rs)** - Understanding dotscope internals and raw parsing
- **[Control Flow](examples/decode_blocks.rs)** - Basic block construction and flow analysis

Each example includes detailed documentation explaining:

- **What it teaches** - Key learning objectives and concepts
- **When to use** - Practical applications and use cases  
- **Prerequisites** - Required background knowledge
- **API patterns** - Consistent, production-ready code examples

See the [examples README](examples/README.md) for a recommended learning path.

## Use Cases

`dotscope` is perfect for:

- **Reverse Engineering**: Analyze .NET malware and vulnerable software
- **Security Research**: Find vulnerabilities and security issues
- **Assembly Patching**: Modify assemblies for instrumentation, hooking, or enhancement
- **Code Analysis**: Static analysis and quality metrics
- **Decompilation**: Build decompilers and analysis tools
- **Development Tools**: Create assembly editors, analyzers, and build tools
- **Educational**: Learn about .NET internals and PE format
- **Forensics**: Examine .NET assemblies in digital forensics

## Security

Security is a top priority:

- **Memory Safety**: Built on Rust's memory safety guarantees
- **Fuzzing**: Continuous fuzzing with cargo-fuzz
- **Input Validation**: Strict validation of all inputs
- **Audit Trail**: Regular dependency auditing

See our [Security Policy](SECURITY.md) for more information.

## Standards Compliance

`dotscope` implements the **ECMA-335 specification** (6th edition) for the Common Language Infrastructure. All metadata structures, CIL instructions, and type system features conform to this standard.

### References

- [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Official CLI specification
- [.NET Runtime](https://github.com/dotnet/runtime) - Microsoft's reference implementation

## Testing and Quality

We maintain high code quality through:

- **Comprehensive Test Suite**: Unit, integration, and fuzz testing
- **Continuous Integration**: Automated testing on multiple platforms
- **Code Coverage**: >90% test coverage target
- **Static Analysis**: Clippy, rustfmt, and security audits
- **Performance Testing**: Regular benchmarking and regression detection

### Running Tests

```bash
# Development cycle (recommended for frequent use)
make dev              # Format, lint, and test

# Full CI simulation
make ci               # Complete CI checks

# Security and quality
make audit            # Security audit
make coverage         # Generate coverage report
```

### Extended Testing

```bash
# Local fuzzing (60 seconds)
make fuzz

# Extended fuzzing (manual)
cd fuzz && cargo +nightly fuzz run cilobject --release -- -max_total_time=1800

# All quality checks
make check-all
```

## Future Features

We're continuously working to improve `dotscope` and add new capabilities. Here are features we'd like to implement in the future:

### Core Improvements

- Handling U/I (compilation dependend 64bit or 32bit) properly
- Improve correctness and API design
- Improve documentation and examples
- Add protections against large allocations (e.g. maliciously crafted files that aim to exhaust system memory)
- Improve type system hash calculations for deduplication
- Standard trait implementations (Debug, Display, Clone, etc.)
- Debug logging infrastructure
- Ecosystem integration improvements

### Enhanced Parsing and Security

- String/Blob caching infrastructure
- Non-embedded resource support

### Performance and Scalability

- Parallel loading optimizations
- Cross-assembly dependency resolution
- Project-wide analysis capabilities
- Assembly linking and merging
- Store and load full Assembly to/from JSON

### Advanced Analysis

- Control flow graph generation
- Data flow analysis
- Call graph construction
- Emulation engine

### Deobfuscation

- SSA (Static Single Assignment) generation
- Compiler optimizations applied to IL (dead code elimination, opaque predicate removal, etc.)
- String decryption capabilities

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Checklist

- Check existing issues and PRs
- Write tests for new features
- Update documentation
- Ensure CI passes
- Follow commit message conventions

## License

This project is licensed under the Apache License, Version 2.0.

See [LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0> for details.

## Acknowledgments

- The Rust community for excellent tooling and libraries
- Microsoft for the ECMA-335 specification
- The [goblin](https://github.com/m4b/goblin) project for PE parsing inspiration

## Support

- **Bug Reports**: [GitHub Issues](https://github.com/BinFlip/dotscope/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/BinFlip/dotscope/issues)
- **Questions**: [GitHub Discussions](https://github.com/BinFlip/dotscope/discussions)
- **Security Issues**: admin{at}binflip.rs
