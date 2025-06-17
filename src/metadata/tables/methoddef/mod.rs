//! MethodDef table implementation for method definitions and implementations.
//!
//! This module provides complete support for the MethodDef metadata table, which defines
//! method implementations within types. The MethodDef table is central to the .NET type
//! system, providing method signatures, implementation details, and parameter information
//! essential for method invocation, reflection, and virtual dispatch.
//!
//! # Module Components
//! - [`MethodDefRaw`] - Raw table structure with unresolved indexes and heap references
//! - [`MethodDefLoader`] - Internal loader for processing table entries (crate-private)
//!
//! # Table Structure (ECMA-335 §22.26)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | RVA | 4-byte offset | Relative virtual address of method implementation |
//! | ImplFlags | 2-byte flags | Method implementation attributes |
//! | Flags | 2-byte flags | Method attributes and access modifiers |
//! | Name | String heap index | Method name identifier |
//! | Signature | Blob heap index | Method signature (calling convention, parameters, return type) |
//! | ParamList | Param table index | First parameter in the parameter list |
//!
//! # Method Implementation Types
//! The MethodDef table supports various method implementation patterns:
//! - **IL methods**: Managed code with Common Intermediate Language bytecode
//! - **Native methods**: Platform-specific native code implementations
//! - **Abstract methods**: Interface or abstract class method declarations without implementation
//! - **P/Invoke methods**: Platform invocation service for calling external library functions
//! - **Runtime methods**: Special methods implemented directly by the runtime system
//! - **Synchronized methods**: Thread-safe methods with automatic synchronization
//!
//! # Method Attributes and Access Control
//! Method flags control visibility, behavior, and implementation characteristics:
//! - **Access modifiers**: Private, public, protected, internal visibility levels
//! - **Virtual dispatch**: Virtual, abstract, final, and override method semantics
//! - **Special methods**: Constructors, property accessors, event handlers, and operators
//! - **Implementation flags**: Native, managed, synchronized, and security attributes
//!
//! # Parameter Management
//! Methods reference parameter information through the Param table:
//! - **Parameter metadata**: Names, types, default values, and custom attributes
//! - **Return type**: Special parameter at sequence 0 for return type information
//! - **Parameter lists**: Contiguous ranges in the Param table for method parameters
//! - **Optional parameters**: Default value support for method overloading
//!
//! # Virtual Method Dispatch
//! MethodDef entries support object-oriented method dispatch patterns:
//! - **Virtual methods**: Overridable methods with late binding and polymorphism
//! - **Interface implementations**: Method implementations for interface contracts
//! - **Abstract methods**: Pure virtual methods requiring derived class implementation
//! - **Method overriding**: Derived class method replacement with base class compatibility
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.26: MethodDef table specification
//! - ECMA-335, Partition II, §23.2.1: Method signature encoding and parsing
//! - ECMA-335, Partition I, §8.4.3: Virtual method dispatch and inheritance
mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;
