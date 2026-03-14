//! Centralized registry of synthetic token constants for the CIL emulator.
//!
//! The emulator needs tokens for types, fields, and methods that don't exist
//! in the loaded assembly's metadata (exception types, heap object types, BCL
//! helper objects, etc.). All such tokens are defined here so that:
//!
//! - Every synthetic value has a single named constant (no inline hex literals).
//! - Ranges are documented and collision-free.
//! - Detection helpers (`is_synthetic`, `is_exception_type`, …) live next to
//!   the constants they check.
//!
//! # Token Ranges
//!
//! | Range              | Table | Purpose                              |
//! |--------------------|-------|--------------------------------------|
//! | `0x7F00_xxxx`      | 0x7F  | Synthetic heap-object type tokens    |
//! | `0x7F01_xxxx`      | 0x7F  | Synthetic exception type tokens      |
//! | `0x7F02_xxxx`      | 0x7F  | Dynamic synthetic method tokens      |
//! | `0x7F04_xxxx`      | 0x7F  | Synthetic field tokens on syn. types |
//! | `0x7FFF_xxxx`      | 0x7F  | BCL helper object type tokens        |
//! | `0xEF00_xxxx`      | 0xEF  | Sentinel field tokens                |
//! | `0xF100_xxxx`      | 0xF1  | Generic instantiation tokens         |
//! | `0xFFFF_xxxx`      | 0xFF  | I/O sentinel field tokens            |
//!
//! Tables 0x7F, 0xEF, 0xF1, and 0xFF do not exist in ECMA-335, so these tokens
//! can never collide with real metadata tokens from a loaded assembly.
//!
//! # Known Issues
//!
//! - **`COMPRESSED_STREAM` / `ASSEMBLY_NAME` collision**: Both currently map to
//!   `0x7F00_0014`. `COMPRESSED_STREAM` should be reassigned to `0x7F00_0017`
//!   once all call sites are migrated (Phase 1, Step 17).

use crate::metadata::token::Token;

/// Reflection types — used for `System.Reflection` heap objects.
pub mod reflection {
    use crate::metadata::token::Token;

    /// `System.Type` reflection object.
    pub const TYPE: Token = Token::new(0x7F00_0001);
    /// `System.Reflection.MethodInfo` / `MethodBase` reflection object.
    pub const METHOD: Token = Token::new(0x7F00_0002);
    /// `System.Reflection.Module` reflection object.
    pub const MODULE: Token = Token::new(0x7F00_0003);
    /// `System.Reflection.FieldInfo` reflection object.
    pub const FIELD: Token = Token::new(0x7F00_0004);
    /// `System.Reflection.PropertyInfo` reflection object.
    pub const PROPERTY: Token = Token::new(0x7F00_0005);
    /// `System.Reflection.ParameterInfo` reflection object.
    pub const PARAMETER: Token = Token::new(0x7F00_0013);
    /// `System.Reflection.MethodBody` reflection object.
    pub const METHOD_BODY: Token = Token::new(0x7F00_0015);
    /// `System.Reflection.CustomAttributeData` object.
    pub const CUSTOM_ATTRIBUTE_DATA: Token = Token::new(0x7F00_0020);
    /// `System.Reflection.AssemblyName` object.
    pub const ASSEMBLY_NAME: Token = Token::new(0x7F00_0014);
}

/// Cryptography types — used for `System.Security.Cryptography` heap objects.
pub mod crypto {
    use crate::metadata::token::Token;

    /// `Rfc2898DeriveBytes` / key derivation object.
    pub const KEY_DERIVATION: Token = Token::new(0x7F00_0007);
    /// `HashAlgorithm` / `HMAC` object.
    pub const CRYPTO_ALGORITHM: Token = Token::new(0x7F00_1004);
    /// `Aes` / `DES` / `TripleDES` symmetric algorithm object.
    pub const SYMMETRIC_ALGORITHM: Token = Token::new(0x7F00_1005);
    /// `ICryptoTransform` object.
    pub const CRYPTO_TRANSFORM: Token = Token::new(0x7F00_1006);
}

/// I/O and stream types.
pub mod io {
    use crate::metadata::token::Token;

    /// `System.IO.Stream` / `MemoryStream` / `FileStream` object.
    pub const STREAM: Token = Token::new(0x7F00_0008);
    /// `System.Security.Cryptography.CryptoStream` object.
    pub const CRYPTO_STREAM: Token = Token::new(0x7F00_0009);
    /// `System.IO.Compression.DeflateStream` / `GZipStream` object.
    ///
    /// **COLLISION**: Currently shares value `0x7F00_0014` with
    /// [`reflection::ASSEMBLY_NAME`]. Should be reassigned to `0x7F00_0017`.
    pub const COMPRESSED_STREAM: Token = Token::new(0x7F00_0014);
}

/// Collection types — `System.Collections.Generic` heap objects.
pub mod collections {
    use crate::metadata::token::Token;

    /// `Dictionary<TKey, TValue>` object.
    pub const DICTIONARY: Token = Token::new(0x7F00_000D);
    /// `List<T>` object.
    pub const LIST: Token = Token::new(0x7F00_000E);
    /// `Stack<T>` object.
    pub const STACK: Token = Token::new(0x7F00_0010);
    /// `Queue<T>` object.
    pub const QUEUE: Token = Token::new(0x7F00_0011);
    /// `HashSet<T>` object.
    pub const HASH_SET: Token = Token::new(0x7F00_0012);
}

/// Dynamic code generation types.
pub mod codegen {
    use crate::metadata::token::Token;

    /// `System.Reflection.Emit.DynamicMethod` object.
    pub const DYNAMIC_METHOD: Token = Token::new(0x7F00_000A);
    /// `System.Reflection.Emit.ILGenerator` object.
    pub const IL_GENERATOR: Token = Token::new(0x7F00_000B);
}

/// System and text utility types.
pub mod system {
    use crate::metadata::token::Token;

    /// `System.String` heap object (primitive wrapper).
    pub const STRING: Token = Token::new(0x7F00_1001);
    /// `System.Array` / multi-dimensional array (primitive wrapper).
    pub const ARRAY: Token = Token::new(0x7F00_1002);
    /// `System.Text.Encoding` object.
    pub const ENCODING: Token = Token::new(0x7F00_1003);
    /// `System.Text.StringBuilder` object.
    pub const STRING_BUILDER: Token = Token::new(0x7F00_000F);
    /// `System.Threading.Thread` object.
    pub const THREAD: Token = Token::new(0x7F00_0016);
    /// `System.Threading.Tasks.Task` (stub for `Task.CompletedTask`).
    pub const TASK: Token = Token::new(0x7F00_0021);
    /// `System.Span<T>` wrapper object.
    pub const SPAN: Token = Token::new(0x7F00_0022);
    /// `System.Memory<T>` wrapper object.
    pub const MEMORY: Token = Token::new(0x7F00_0023);
    /// `System.TypedReference` (created by `mkrefany`).
    pub const TYPED_REFERENCE: Token = Token::new(0x7F00_0024);
    /// `System.Reflection.Emit.OpCode` value type.
    pub const OPCODE: Token = Token::new(0x7F00_0025);
    /// `System.Diagnostics.Process` object.
    pub const PROCESS: Token = Token::new(0x7F00_0026);
    /// `System.Diagnostics.ProcessModule` object.
    pub const PROCESS_MODULE: Token = Token::new(0x7F00_0027);
}

/// Well-known singleton objects used by `FakeObjects`.
pub mod singletons {
    use crate::metadata::token::Token;

    /// Fake `System.Reflection.Assembly` singleton.
    pub const ASSEMBLY: Token = Token::new(0x7F00_00F0);
    /// Fake `System.AppDomain` singleton.
    pub const APP_DOMAIN: Token = Token::new(0x7F00_00F1);
}

/// BCL helper type tokens for internal hook objects.
pub mod helpers {
    use crate::metadata::token::Token;

    /// `List<T>.Enumerator` helper object type.
    pub const LIST_ENUMERATOR: Token = Token::new(0x7FFF_0001);
    /// `RNGCryptoServiceProvider` / `RandomNumberGenerator` helper object type.
    pub const RNG: Token = Token::new(0x7FFF_0010);
}

/// Field tokens for `System.Exception` and its subclasses.
///
/// These use the 0xEF00_xxxx range (table 0xEF, unused in ECMA-335) for
/// sentinel fields on exception objects.
pub mod exception_fields {
    use crate::metadata::token::Token;

    /// `Exception.Message` field.
    pub const MESSAGE: Token = Token::new(0xEF00_0010);
    /// `Exception.InnerException` field.
    pub const INNER_EXCEPTION: Token = Token::new(0xEF00_0011);
    /// `Exception.HResult` field.
    pub const HRESULT: Token = Token::new(0xEF00_0012);
    /// `Exception.Source` field.
    pub const SOURCE: Token = Token::new(0xEF00_0013);
}

/// Field tokens for `List<T>.Enumerator` helper objects.
///
/// These use the 0xEF00_xxxx range (table 0xEF, unused in ECMA-335).
pub mod enumerator_fields {
    use crate::metadata::token::Token;

    /// Reference back to the parent `List<T>` object.
    pub const LIST_REF: Token = Token::new(0xEF00_0001);
    /// Current iteration position.
    pub const POSITION: Token = Token::new(0xEF00_0002);
}

/// Field tokens for `RNGCryptoServiceProvider` helper objects.
///
/// These use the 0xEF00_xxxx range (table 0xEF, unused in ECMA-335).
pub mod rng_fields {
    use crate::metadata::token::Token;

    /// Xorshift64 PRNG state stored on the RNG object.
    pub const STATE: Token = Token::new(0xEF00_FF01);
}

/// Field tokens for `CustomAttributeData` objects (0x7F04_xxxx range).
pub mod attribute_fields {
    use crate::metadata::token::Token;

    /// Interface type field on `CustomAttributeData`.
    pub const INTERFACE_TYPE: Token = Token::new(0x7F04_0001);
    /// Interface methods array field on `CustomAttributeData`.
    pub const INTERFACE_METHODS: Token = Token::new(0x7F04_0002);
    /// Target methods array field on `CustomAttributeData`.
    pub const TARGET_METHODS: Token = Token::new(0x7F04_0003);
}

/// Field tokens for I/O types (`BinaryReader`, `BinaryWriter`, `FileInfo`, `StreamReader`).
///
/// These use the `0xFFFF_xxxx` range (table 0xFF, unused in ECMA-335) for
/// sentinel fields that link I/O wrapper objects to their underlying streams.
pub mod io_fields {
    use crate::metadata::token::Token;

    /// Underlying `Stream` reference stored on a `BinaryReader` object.
    pub const BINARY_READER_STREAM: Token = Token::new(0xFFFF_0001);
    /// Underlying `Stream` reference stored on a `BinaryWriter` object.
    pub const BINARY_WRITER_STREAM: Token = Token::new(0xFFFF_0002);
    /// File path stored on a `FileInfo` object.
    pub const FILEINFO_PATH: Token = Token::new(0xFFFF_0020);
    /// Underlying `Stream` reference stored on a `StreamReader` object.
    pub const STREAMREADER_STREAM: Token = Token::new(0xFFFF_0030);
}

/// Field tokens for `Span<T>` and `Memory<T>` wrapper objects.
pub mod span_fields {
    use crate::metadata::token::Token;

    /// Underlying array reference in `Span<T>`.
    pub const SPAN_ARRAY: Token = Token::new(0x7F04_0022);
    /// Underlying array reference in `Memory<T>`.
    pub const MEMORY_ARRAY: Token = Token::new(0x7F04_0023);
}

/// Field tokens for `StackFrame` and `AssemblyName` objects.
pub mod misc_fields {
    use crate::metadata::token::Token;

    /// Method token stored on a `StackFrame` object.
    pub const STACKFRAME_METHOD: Token = Token::new(0x04FF_0001);
    /// Name string stored on an `AssemblyName` object.
    pub const ASSEMBLY_NAME_NAME: Token = Token::new(0x04FF_0010);
    /// `OpCode.Value` field on a boxed OpCode struct.
    pub const OPCODE_VALUE: Token = Token::new(0x7F00_0E01);
}

/// Field tokens for `System.Diagnostics.Process` and `ProcessModule` objects.
pub mod process_fields {
    use crate::metadata::token::Token;

    /// `Process.MainModule` — stores `ProcessModule` reference on a `Process` object.
    pub const MAIN_MODULE: Token = Token::new(0xEF00_0020);
    /// `ProcessModule.FileName` — stores filename string on a `ProcessModule` object.
    pub const FILE_NAME: Token = Token::new(0xEF00_0021);
}

/// Constants for dynamic token range detection.
pub mod ranges {
    /// Base address for synthetic method tokens (`DynamicMethod` / `ILGenerator`).
    ///
    /// Tokens are allocated as `SYNTHETIC_METHOD_BASE | id` where `id` starts at 1.
    pub const SYNTHETIC_METHOD_BASE: u32 = 0x7F02_0000;

    /// Mask for isolating the range prefix of synthetic method tokens.
    pub const SYNTHETIC_METHOD_MASK: u32 = 0xFFFF_0000;

    /// Base address for generic instantiation tokens.
    ///
    /// Tokens are allocated as `GENERIC_INSTANTIATION_BASE | id`.
    pub const GENERIC_INSTANTIATION_BASE: u32 = 0xF100_0000;

    /// Mask for isolating the range prefix of generic instantiation tokens.
    pub const GENERIC_INSTANTIATION_MASK: u32 = 0xFF00_0000;
}

/// Returns `true` if the token is a synthetic exception type (`0x7F01_xxxx`).
#[must_use]
pub fn is_exception_type(token: Token) -> bool {
    token.value() & 0xFFFF_0000 == 0x7F01_0000
}

/// Returns `true` if the token is a synthetic heap-object type (`0x7F00_xxxx`).
#[must_use]
pub fn is_heap_type(token: Token) -> bool {
    token.value() & 0xFFFF_0000 == 0x7F00_0000
}

/// Returns `true` if the token is a BCL helper type (`0x7FFF_xxxx`).
#[must_use]
pub fn is_helper_type(token: Token) -> bool {
    token.value() & 0xFFFF_0000 == 0x7FFF_0000
}

/// Returns `true` if the token is a synthetic method (`0x7F02_xxxx`).
#[must_use]
pub fn is_synthetic_method(token: Token) -> bool {
    token.value() & ranges::SYNTHETIC_METHOD_MASK == ranges::SYNTHETIC_METHOD_BASE
}

/// Returns `true` if the token is a generic instantiation (`0xF1xx_xxxx`).
#[must_use]
pub fn is_generic_instantiation(token: Token) -> bool {
    token.value() & ranges::GENERIC_INSTANTIATION_MASK == ranges::GENERIC_INSTANTIATION_BASE
}

/// Returns `true` if the token belongs to any synthetic range used by the emulator.
///
/// This covers exception types, heap types, helper types, synthetic methods,
/// synthetic fields (0x7F04), I/O fields (0xFF), and generic instantiations.
#[must_use]
pub fn is_synthetic(token: Token) -> bool {
    let table = token.value() >> 24;
    matches!(table, 0x7F | 0xEF | 0xF1 | 0xFF)
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            synthetic_exception,
            tokens::{
                self, codegen, collections, crypto, helpers, io, io_fields, ranges, reflection,
                singletons, system,
            },
        },
        metadata::token::Token,
    };

    #[test]
    fn exception_type_detection() {
        assert!(tokens::is_exception_type(
            synthetic_exception::BASE_EXCEPTION
        ));
        assert!(tokens::is_exception_type(
            synthetic_exception::NULL_REFERENCE
        ));
        assert!(tokens::is_exception_type(
            synthetic_exception::NOT_IMPLEMENTED
        ));
        assert!(!tokens::is_exception_type(reflection::TYPE));
        assert!(!tokens::is_exception_type(Token::new(0x0200_0001)));
    }

    #[test]
    fn heap_type_detection() {
        assert!(tokens::is_heap_type(reflection::TYPE));
        assert!(tokens::is_heap_type(system::STRING));
        assert!(tokens::is_heap_type(singletons::ASSEMBLY));
        assert!(!tokens::is_heap_type(helpers::LIST_ENUMERATOR));
        assert!(!tokens::is_heap_type(Token::new(0x7F01_0000)));
    }

    #[test]
    fn helper_type_detection() {
        assert!(tokens::is_helper_type(helpers::LIST_ENUMERATOR));
        assert!(tokens::is_helper_type(helpers::RNG));
        assert!(!tokens::is_helper_type(reflection::TYPE));
    }

    #[test]
    fn synthetic_method_detection() {
        assert!(tokens::is_synthetic_method(Token::new(
            ranges::SYNTHETIC_METHOD_BASE | 1
        )));
        assert!(tokens::is_synthetic_method(Token::new(
            ranges::SYNTHETIC_METHOD_BASE | 0xFFFF
        )));
        assert!(!tokens::is_synthetic_method(reflection::TYPE));
    }

    #[test]
    fn generic_instantiation_detection() {
        assert!(tokens::is_generic_instantiation(Token::new(
            ranges::GENERIC_INSTANTIATION_BASE | 42
        )));
        assert!(!tokens::is_generic_instantiation(reflection::TYPE));
    }

    #[test]
    fn is_synthetic_covers_all_ranges() {
        // Table 0x7F
        assert!(tokens::is_synthetic(reflection::TYPE));
        assert!(tokens::is_synthetic(helpers::LIST_ENUMERATOR));
        assert!(tokens::is_synthetic(Token::new(
            ranges::SYNTHETIC_METHOD_BASE | 1
        )));
        assert!(tokens::is_synthetic(Token::new(0x7F04_0001)));

        // Table 0xEF
        assert!(tokens::is_synthetic(Token::new(0xEF00_0010)));

        // Table 0xF1
        assert!(tokens::is_synthetic(Token::new(
            ranges::GENERIC_INSTANTIATION_BASE | 1
        )));

        // Table 0xFF (I/O fields)
        assert!(tokens::is_synthetic(io_fields::BINARY_READER_STREAM));
        assert!(tokens::is_synthetic(io_fields::FILEINFO_PATH));

        // Real metadata token
        assert!(!tokens::is_synthetic(Token::new(0x0200_0001)));
        assert!(!tokens::is_synthetic(Token::new(0x0600_0001)));
    }

    #[test]
    fn no_value_collisions_within_type_tokens() {
        let type_tokens = [
            reflection::TYPE,
            reflection::METHOD,
            reflection::MODULE,
            reflection::FIELD,
            reflection::PROPERTY,
            reflection::PARAMETER,
            reflection::METHOD_BODY,
            reflection::CUSTOM_ATTRIBUTE_DATA,
            reflection::ASSEMBLY_NAME,
            crypto::KEY_DERIVATION,
            crypto::CRYPTO_ALGORITHM,
            crypto::SYMMETRIC_ALGORITHM,
            crypto::CRYPTO_TRANSFORM,
            io::STREAM,
            io::CRYPTO_STREAM,
            // io::COMPRESSED_STREAM intentionally excluded — known collision
            collections::DICTIONARY,
            collections::LIST,
            collections::STACK,
            collections::QUEUE,
            collections::HASH_SET,
            codegen::DYNAMIC_METHOD,
            codegen::IL_GENERATOR,
            system::STRING,
            system::ARRAY,
            system::ENCODING,
            system::STRING_BUILDER,
            system::THREAD,
            system::TASK,
            system::SPAN,
            system::MEMORY,
            system::PROCESS,
            system::PROCESS_MODULE,
            singletons::ASSEMBLY,
            singletons::APP_DOMAIN,
            helpers::LIST_ENUMERATOR,
            helpers::RNG,
        ];

        for (i, a) in type_tokens.iter().enumerate() {
            for (j, b) in type_tokens.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a.value(),
                        b.value(),
                        "collision between type_tokens[{i}] (0x{:08X}) and type_tokens[{j}] (0x{:08X})",
                        a.value(),
                        b.value()
                    );
                }
            }
        }
    }
}
