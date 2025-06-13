# dotscope

[![Crates.io](https://img.shields.io/crates/v/dotscope.svg)](https://crates.io/crates/dotscope)
[![Documentation](https://docs.rs/dotscope/badge.svg)](https://docs.rs/dotscope)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Build Status](https://github.com/BinFlip/dotscope/workflows/CI/badge.svg)](https://github.com/BinFlip/dotscope/actions)
[![Coverage](https://codecov.io/gh/BinFlip/dotscope/branch/main/graph/badge.svg)](https://codecov.io/gh/BinFlip/dotscope)

A high-performance, cross-platform framework for analyzing and reverse engineering .NET PE executables. Built in pure Rust, `dotscope` provides comprehensive tooling for parsing CIL (Common Intermediate Language) bytecode, metadata structures, and disassembling .NET assemblies without requiring Windows or the .NET runtime.

## Features

- **Efficient memory access** - Memory-mapped file access with minimal allocations and reference-based parsing
- **Complete metadata analysis** - Parse all ECMA-335 metadata tables and streams
- **High-performance disassembly** - Fast CIL instruction decoding with control flow analysis
- **Cross-platform** - Works on Windows, Linux, macOS, and any Rust-supported platform
- **Memory safe** - Built in Rust with comprehensive error handling
- **Rich type system** - Full support for generics, signatures, and complex .NET types
- **Extensible architecture** - Modular design for custom analysis and tooling

## Quick Start

Add `dotscope` to your `Cargo.toml`:

```toml
[dependencies]
dotscope = "0.1"
```

### Basic Usage

```rust
use dotscope::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load and analyze a .NET assembly  
    let assembly = CilObject::from_file("MyAssembly.dll".as_ref())?;
    
    // Access basic information
    if let Some(module) = assembly.module() {
        println!("Module: {}", module.name);
    }
    
    // Iterate through methods
    let methods = assembly.methods();
    println!("Found {} methods", methods.len());
    
    // Examine imports and exports
    let imports = assembly.imports();
    let exports = assembly.exports();
    println!("Imports: {}, Exports: {}", imports.len(), exports.len());
    
    Ok(())
}
```

### Disassembly Example

```rust
use dotscope::{disassembler::decode_instruction, Parser};

fn disassemble_method() -> dotscope::Result<()> {
    let bytecode = &[0x00, 0x2A]; // nop, ret
    let mut parser = Parser::new(bytecode);
    
    let instruction = decode_instruction(&mut parser, 0x1000)?;
    println!("Mnemonic: {}", instruction.mnemonic);
    println!("Flow type: {:?}", instruction.flow_type);
    
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
- **[`disassembler`]** - CIL instruction decoding and control flow analysis
- **[`Error`] and [`Result`]** - Comprehensive error handling

### Metadata Analysis

The [`CilObject`] provides access to:

- **Streams**: Strings, user strings, GUIDs, and blob heaps
- **Tables**: All ECMA-335 metadata tables (types, methods, fields, etc.)
- **Type System**: Rich representation of .NET types and signatures
- **Resources**: Embedded resources and manifest information
- **Security**: Code access security and permission sets

### Disassembly Engine

The disassembler module provides:

- **Instruction Decoding**: Parse individual CIL opcodes with full operand support
- **Control Flow Analysis**: Build basic blocks and control flow graphs
- **Stack Analysis**: Track stack effects and type flow
- **Exception Handling**: Parse and analyze try/catch/finally regions

## Examples

Check out the [examples](examples/) directory for complete working examples with comprehensive documentation:

- **[Basic Usage](examples/basic.rs)** - Start here! Simple assembly loading and inspection with error handling
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
- **Code Analysis**: Static analysis and quality metrics
- **Decompilation**: Build decompilers and analysis tools
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
- PortablePDB support
- Non-embedded resource support

### Performance and Scalability

- Parallel loading optimizations
- Cross-assembly dependency resolution
- Project-wide analysis capabilities
- Assembly linking and merging
- Store and load full Assembly to/from JSON

### Assembly Modification

- Assembly modification and generation capabilities
- Instruction patching and injection
- Metadata table manipulation

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
