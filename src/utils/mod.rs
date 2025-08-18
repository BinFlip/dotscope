//! General utility functions for the dotscope framework.
//!
//! This module consolidates utility functions from across the framework into a central,
//! reusable location. It provides fundamental operations needed by multiple components,
//! promoting code reuse and maintainability.
//!
//! # Module Organization
//!
//! The utilities are organized by functional area:
//!
//! - [`crate::utils::compression`] - ECMA-335 compressed integer encoding/decoding
//! - [`crate::utils::alignment`] - Memory alignment operations for binary layouts
//! - [`crate::utils::heap_calc`] - Metadata heap size calculation functions
//!
//! # Design Principles
//!
//! - **Framework-Wide Reusability**: Functions can be used across all modules
//! - **High Performance**: Optimized for frequent usage throughout the pipeline
//! - **ECMA-335 Compliance**: All utilities maintain strict .NET specification compliance
//! - **Thread Safety**: All functions are thread-safe with immutable operations
//! - **Comprehensive Testing**: Extensive unit tests ensure reliability
//!
//! # Examples
//!
//! ## Compressed Integer Encoding
//!
//! ```rust,ignore
//! use dotscope::utils::compression::{write_compressed_uint, compressed_uint_size};
//!
//! let mut buffer = Vec::new();
//! write_compressed_uint(300, &mut buffer);
//! assert_eq!(compressed_uint_size(300), buffer.len() as u64);
//! ```
//!
//! ## Memory Alignment
//!
//! ```rust,ignore
//! use dotscope::utils::alignment::{align_to_4_bytes, align_to};
//!
//! assert_eq!(align_to_4_bytes(17), 20);
//! assert_eq!(align_to(1000, 512), 1024);
//! ```

mod alignment;
mod compression;
mod heap_calc;
mod io;

pub use alignment::{align_to, align_to_4_bytes};
pub use compression::compressed_uint_size;
pub use heap_calc::calculate_table_row_size;
#[allow(unused_imports)]
pub use io::{
    read_be, read_be_at, read_be_at_dyn, read_compressed_int, read_compressed_int_at,
    read_compressed_uint, read_compressed_uint_at, read_le, read_le_at, read_le_at_dyn,
    write_7bit_encoded_int, write_be, write_be_at, write_be_at_dyn, write_compressed_int,
    write_compressed_uint, write_le, write_le_at, write_le_at_dyn, write_prefixed_string_utf16,
    write_prefixed_string_utf8, write_string_at, write_string_utf8, CilIO,
};
