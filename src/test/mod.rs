//! Test utilities and mock data builders for unit testing
//!
//! This module provides comprehensive mock data builders for testing complex
//! .NET metadata structures. The goal is to create reusable, composable mock
//! builders that can generate realistic test data covering all major types.
//!
//! # Module Organization
//!
//! - **builders/** - Fluent API builders for creating mock metadata objects
//! - **factories/** - Migrated test factory methods organized by domain
//! - **scenarios/** - Pre-built complex scenarios and test data combinations  
//! - **helpers/** - Legacy helper functions and utilities
//! - **windowsbase.rs** - Windows-specific test helpers and verification
//!
//! # Mock Data Architecture
//!
//! ## 1. CORE BUILDERS (completed):
//! - ModuleRefBuilder - For module references
//! - AssemblyRefBuilder - For assembly references with versioning
//! - FileBuilder - For file metadata
//! - MethodBuilder - For methods with signatures and flags
//! - CilTypeBuilder - For types with inheritance and members
//! - ExportedTypeBuilder - For exported type definitions
//!
//! ## 2. ADVANCED BUILDERS (TODO):
//! - MethodBodyBuilder - for IL code, local vars, exception handlers
//! - SignatureBuilder - for complex method/type signatures
//! - CustomAttributeBuilder - for custom attributes with various data types
//! - GenericTypeBuilder - for generic types with constraints
//! - FieldBuilder - for fields with layouts, marshalling
//! - PropertyBuilder - for properties with getters/setters
//! - EventBuilder - for events with add/remove methods
//! - SecurityBuilder - for security attributes and permissions
//! - ResourceBuilder - for embedded resources
//!
//! ## 3. SCENARIO BUILDERS (TODO):
//! - ComplexTypeHierarchyBuilder - inheritance chains, interfaces
//! - GenericScenarioBuilder - generic classes, methods, constraints
//! - PInvokeScenarioBuilder - native interop scenarios
//! - AsyncMethodScenarioBuilder - async/await patterns
//! - ExceptionHandlingScenarioBuilder - try/catch/finally patterns
//! - LINQScenarioBuilder - LINQ expressions and delegates
//!
//! ## 4. INTEGRATION BUILDERS (TODO):
//! - AssemblyBuilder - complete assembly with multiple types/methods
//! - ModuleBuilder - complete module with dependencies
//! - PackageBuilder - multi-assembly scenarios
//!
//! ## 5. VALIDATION TEST DATA (TODO):
//! - MalformedDataBuilder - for validation error testing
//! - EdgeCaseBuilder - boundary conditions, limits
//! - PerformanceDataBuilder - large-scale data for performance tests
//!
//! # Usage Patterns
//!
//! ```rust,no_run
//! use dotscope::test::{builders::*, scenarios::*};
//!
//! // Fluent API usage
//! let assembly = AssemblyRefBuilder::new()
//!     .with_name("TestAssembly")
//!     .with_version(1, 0, 0, 0)
//!     .build();
//!
//! // Preset scenarios
//! let method = MethodBuilder::simple_void_method("TestMethod").build();
//! let class_type = CilTypeBuilder::simple_class("Test", "MyClass").build();
//!
//! // Complex scenarios
//! let (base_class, derived_class) = create_inheritance_scenario();
//! let standard_refs = create_standard_assembly_refs();
//! ```
//!
//! ### Examples (`examples/`)
//! Comprehensive examples showing how to use the builders for realistic scenarios:
//! - Field validation testing
//! - Method signature creation
//! - Custom attribute scenarios
//! - Generic type definitions

pub mod builders;
pub mod factories;
mod helpers;
mod scenarios;
mod validator;
mod windowsbase;

pub use builders::*;
pub use helpers::*;
pub use validator::*;
pub use windowsbase::*;
//pub use scenarios::*;
