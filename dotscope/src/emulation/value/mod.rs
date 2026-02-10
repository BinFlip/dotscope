//! Runtime value representation for CIL emulation.
//!
//! This module provides the core value types used during CIL bytecode emulation.
//! It implements the full CIL type system including primitives, references,
//! value types, and symbolic values for partial emulation.
//!
//! # Architecture
//!
//! The value system is built around several key types:
//!
//! - [`EmValue`] - The main runtime value enum representing all CIL value types
//! - [`SymbolicValue`] - Represents unknown/unresolved values during partial emulation
//! - [`HeapRef`] - Reference to heap-allocated objects
//! - [`ManagedPointer`] - Managed pointer for ref/out parameters
//!
//! # CIL Type Flavors
//!
//! The CIL type system is represented by [`CilFlavor`](crate::metadata::typesystem::CilFlavor),
//! which provides precise type information for emulation:
//!
//! | CilFlavor | CIL Types |
//! |-----------|-----------|
//! | `I4` | `int8`, `int16`, `int32`, `uint8`, `uint16` (on stack) |
//! | `I8` | `int64`, `uint64` |
//! | `I` | `native int`, `native uint` |
//! | `R4` | `float32` |
//! | `R8` | `float64` |
//! | `Boolean` | `bool` |
//! | `Char` | `char` |
//! | `Object` | Object references, arrays, strings |
//! | `ByRef` | Managed pointers (`&`, `ref`) |
//! | `ValueType` | User-defined value types (structs) |
//!
//! # Usage Examples
//!
//! ## Creating Values
//!
//! ```rust
//! use dotscope::emulation::EmValue;
//! use dotscope::metadata::typesystem::CilFlavor;
//!
//! // Primitive values
//! let i32_val = EmValue::I32(42);
//! let i64_val = EmValue::I64(1234567890);
//! let f64_val = EmValue::F64(3.14159);
//! let bool_val = EmValue::Bool(true);
//!
//! // Check CIL flavor
//! assert_eq!(i32_val.cil_flavor(), CilFlavor::I4);
//! assert_eq!(bool_val.cil_flavor(), CilFlavor::Boolean);
//! ```
//!
//! ## Arithmetic Operations
//!
//! ```rust
//! use dotscope::emulation::{EmValue, BinaryOp};
//! use dotscope::metadata::typesystem::PointerSize;
//!
//! let a = EmValue::I32(10);
//! let b = EmValue::I32(3);
//!
//! let sum = a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap();
//! assert_eq!(sum, EmValue::I32(13));
//!
//! let product = a.binary_op(&b, BinaryOp::Mul, PointerSize::Bit64).unwrap();
//! assert_eq!(product, EmValue::I32(30));
//! ```
//!
//! ## Type Conversions
//!
//! ```rust
//! use dotscope::emulation::{EmValue, ConversionType};
//! use dotscope::metadata::typesystem::PointerSize;
//!
//! let i32_val = EmValue::I32(42);
//! let i64_val = i32_val.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
//! assert_eq!(i64_val, EmValue::I64(42));
//! ```

mod emvalue;
mod ops;
mod symbolic;

pub use emvalue::{EmValue, HeapRef, ManagedPointer, PointerTarget};
pub use ops::{BinaryOp, CompareOp, ConversionType, UnaryOp};
pub use symbolic::{SymbolicValue, TaintSource};
