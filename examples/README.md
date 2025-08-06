# dotscope Examples

This directory contains comprehensive examples demonstrating the capabilities of the dotscope .NET assembly analysis framework. The examples are designed to be educational and practical, showing real-world usage patterns.

## Learning Path

Follow this recommended order to learn dotscope effectively:

### 1. **Beginner Level**

- **[`basic.rs`](basic.rs)** - Start here! Learn fundamental concepts
  - Loading .NET assemblies
  - Accessing basic metadata
  - Using the prelude for clean code
  - Safe error handling patterns

### 2. **Intermediate Level**

- **[`metadata.rs`](metadata.rs)** - Explore metadata structures
  - Direct metadata table access
  - String and blob heap analysis
  - Assembly dependency tracking

- **[`types.rs`](types.rs)** - Understand the type system
  - Type categorization and analysis
  - Generic type examination
  - Inheritance hierarchy exploration

- **[`disassembly.rs`](disassembly.rs)** - Learn IL analysis
  - CIL instruction decoding
  - Method body examination
  - Exception handler analysis

### 3. **Advanced Level**

- **[`comprehensive.rs`](comprehensive.rs)** - See it all together
  - Complete analysis workflow
  - Advanced features demonstration
  - Performance-oriented patterns

- **[`method_analysis.rs`](method_analysis.rs)** - Deep method inspection
  - Exhaustive method analysis
  - Signature parsing
  - Control flow examination

### 4. **Assembly Modification**

- **[`modify.rs`](modify.rs)** - Assembly modification basics
  - Adding strings, blobs, and metadata
  - Table row manipulation
  - Heap content modification

- **[`injectcode.rs`](injectcode.rs)** - Code injection example
  - Injecting new methods into existing assemblies
  - Creating external references to BCL types
  - CIL bytecode generation
  - Complete modification workflow

### 5. **Specialized Examples**

- **[`lowlevel.rs`](lowlevel.rs)** - Understanding internals
  - Raw PE structure parsing
  - Low-level API usage
  - Binary format details

- **[`decode_blocks.rs`](decode_blocks.rs)** - Control flow analysis
  - Basic block construction
  - Branch instruction handling
  - Flow control patterns

## Running Examples

All examples follow the same pattern:

```bash
# Run with a sample assembly
cargo run --example basic tests/samples/WindowsBase.dll

# Code injection example
cargo run --example injectcode tests/samples/WindowsBase.dll injected_output.dll

# Each example provides usage help
cargo run --example basic
```

### Sample Assemblies

The repository includes several test assemblies in `tests/samples/`:

- `WindowsBase.dll` - Good general-purpose example
- `crafted_2.exe` - Demonstrates specific features

## API Patterns

All examples demonstrate these consistent patterns:

### Error Handling

```rust
use dotscope::prelude::*;

fn main() -> Result<()> {
    // Using dotscope::Result<()> throughout
}
```

### Assembly Loading

```rust
let assembly = CilObject::from_file(path)?;
```

### Safe Metadata Access

```rust
// Always use pattern matching for optional data
if let Some(module) = assembly.module() {
    println!("Module: {}", module.name);
}

// Use .get() for safe method body access
if let Some(body) = method.body.get() {
    // Work with method body
}
```

## Documentation Integration

Each example includes:

- **What this example teaches** - Key learning objectives
- **When to use this pattern** - Practical applications
- **Prerequisites** - Required background knowledge
- Inline comments explaining API usage
- Error handling and troubleshooting guidance

## Use Case Examples

The examples cover these practical scenarios:

- **Security Analysis** - Finding vulnerabilities and security issues
- **Reverse Engineering** - Understanding assembly structure and behavior
- **Code Quality** - Static analysis and metrics collection
- **Assembly Modification** - Injecting code, patching, and instrumentation
- **Educational** - Learning .NET internals and PE format
- **Tool Building** - Creating custom analysis and decompilation tools

## Next Steps

After working through these examples:

1. Check the [API documentation](https://docs.rs/dotscope)
2. Read the [Contributing Guide](../CONTRIBUTING.md)
3. Explore the source code for deeper understanding
4. Build your own analysis tools using these patterns

## Contributing

Found an issue or want to improve an example? See the [Contributing Guide](../CONTRIBUTING.md) for how to help make these examples even better.
