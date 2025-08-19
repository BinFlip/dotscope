# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-08-19

### Added

- **Assembly Encoder and Builder System**: Complete CIL assembly encoder and builder implementation with high-performance benchmarks
- **High-Level Builders**: Added builders for classes, enums, events, interfaces, properties, and methods with full CIL method body support
- **Binary Modification Capabilities**: Full binary modification support with method injection and exception handler support using label-based targeting
- **PortablePDB Support**: Complete PortablePDB parsing implementation for enhanced debugging information
- **EnC (Edit and Continue) Tables**: Support for Edit and Continue metadata tables
- **Validation System**: Comprehensive validation framework to ensure modified binaries remain valid and loadable
- **Binary Serialization**: Capability to write modified assemblies back to disk

### Changed

- **Module Organization**: Renamed `disassembler` module to `assembly` in preparation for encoder implementation
- **File Structure**: Removed `self_reflecting` from File structure, storing PE information locally for improved performance

### Fixed

- Fixed regression in size field length calculation
- Fixed multiple issues causing modified binaries to be invalid
- Fixed clippy warnings for latest Rust versions
- Various binary modification stability improvements

### Improved

- Enhanced integration testing with Mono runtime verification
- Improved PE file handling and structure
- Better separation between parsing and encoding functionality
- Updated examples and documentation

## [0.3.2] - 2025-06-17

### Fixed

- Wrong release sequence for 3.1, this corrects the changes necessary

## [0.3.1] - 2025-06-17

### Improved

- Enhanced overall documentation across the codebase with better examples and clearer explanations

## [0.3.0] - 2025-06-14

### Added

- Implemented missing pointer tables (FieldPtr, MethodPtr, ParamPtr, EventPtr, PropertyPtr)
- New builder system and test scenarios for complex .NET features
- Support for parsing XML-based security permission sets

### Changed

- Reorganized metadata table structure for better maintainability
- Better separation of raw tables, loaders, and owned types

### Improved

- Extended marshaling support for native interop scenarios
- Improved validation of various entries while loading the binary
- Performance optimizations
- Improved type resolution and generic parameter handling
- Expanded test coverage with crafted test cases

## [0.2.1] - 2025-06-11

### Fixed

- **Type System Issues**: Resolved critical issues with type flavor classification and inheritance resolution
- **Method-to-Type Associations**: Fixed method discovery and association with declaring types  
- **Interface Relationships**: Improved interface inheritance chain resolution
- **Type Flavor Determination**: Added proper logic to classify value types, interfaces, and classes correctly
- **Parser Stability**: Enhanced robustness and error handling in metadata parsing

### Added

- **Enhanced Test Coverage**: Expanded test coverage analysis and validation for complex .NET features

### Improved

- **Type System Validation**: More accurate type classification and inheritance analysis
- **Test Infrastructure**: Enhanced validation and coverage analysis

## [0.2.0] - 2025-06-10

### Added

- **Custom Attribute System**: Complete implementation with constructor/property resolution and support for complex parameter types
- **Enhanced Generic Type System**: Improved MethodSpec handling, corrected generic parameter resolution (`T -> System.Int32`), improved type builder and resolver
- **Method Analysis Framework**: Improved IL disassembly + API

### Fixed

- **Type Safety**: Replaced unsafe casting with proper bounds checking and overflow detection
- **Memory Management**: Improved method-to-type associations and type flavor classification
- **Dependencies**: Updated all dependencies to address security advisories #4, #5, #6

### Changed

- **Breaking**: MethodSpec architecture - `CilType.generic_args` now contains MethodSpec instances instead of direct CilTypeRc
- **Performance**: Replaced RwLock with `boxcar::Vec` for better lock-free concurrency
- **Security**: Enhanced input validation and overflow protection for malformed assemblies

## [0.1.0] - 2025-06-08

### Added

#### Initial Release

dotscope is a Rust library for parsing and analyzing .NET assemblies (PE files with CLI metadata).

#### Core Features

- **PE File Parsing**: Read .NET assemblies from files or memory buffers
- **Metadata Analysis**: Parse ECMA-335 metadata tables, strings, and blob heaps
- **CIL Disassembly**: Decode IL bytecode into readable instructions with basic block analysis
- **Type System**: Access type definitions, method signatures, and field information
- **Resource Extraction**: Read embedded resources and manifest data

#### API Highlights

- `CilObject::from_file()` and `CilObject::from_buffer()` for loading assemblies
- Access to metadata tables (TypeDef, MethodDef, Field, etc.)
- CIL instruction decoding with control flow analysis
- Type resolution and signature parsing
- Comprehensive error handling with detailed context

#### Quality & Testing

- 90%+ test coverage with 400+ unit tests
- Fuzzing infrastructure for robustness testing
- Integration tests with real .NET assemblies
- Memory-safe parsing with bounds checking

#### Known Limitations

- Custom attribute parsing is not fully implemented
- Some advanced signature types need refinement
- Resource limits for DoS protection not yet implemented
