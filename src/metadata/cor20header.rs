//! CLR 2.0 (Cor20) header parsing for .NET assemblies.
//!
//! This module provides parsing functionality for the CLI (Common Language Infrastructure) header
//! found in .NET assemblies. The CLI header is located at the `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`
//! data directory of PE files and contains essential metadata required by the .NET runtime.
//!
//! # Architecture
//!
//! The module implements parsing for the 72-byte CLI header structure defined by ECMA-335 II.24.3.3.
//! The header contains fixed-size fields arranged in a specific order, with comprehensive validation
//! of field values according to the specification.
//!
//! ## Header Structure
//!
//! The CLI header consists of:
//! - **Header information**: Size (4 bytes) and runtime version (4 bytes)
//! - **Metadata directory**: RVA and size of the metadata root (8 bytes)
//! - **Runtime control**: Flags and entry point token (8 bytes)
//! - **Optional directories**: Resources, strong names, VTable fixups (48 bytes)
//!
//! # Key Components
//!
//! - [`crate::metadata::cor20header::Cor20Header`] - Main structure representing the parsed CLI header
//! - Comprehensive field validation according to ECMA-335 requirements
//! - Support for all CLI header features including mixed-mode assemblies
//!
//! # Usage Examples
//!
//! ## Basic Header Parsing
//!
//! ```rust,ignore
//! use dotscope::metadata::cor20header::Cor20Header;
//!
//! // Parse CLI header from PE file data
//! let header_data: &[u8] = &[/* 72 bytes of CLI header */];
//! let cli_header = Cor20Header::read(header_data)?;
//!
//! println!("Runtime version: {}.{}",
//!     cli_header.major_runtime_version,
//!     cli_header.minor_runtime_version);
//! println!("Metadata at RVA: 0x{:X}, size: {} bytes",
//!     cli_header.meta_data_rva,
//!     cli_header.meta_data_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Runtime Flag Analysis
//!
//! ```rust,ignore
//! use dotscope::metadata::cor20header::Cor20Header;
//!
//! let header_bytes: &[u8] = &[/* CLI header data */];
//! let header = Cor20Header::read(&header_bytes)?;
//!
//! // Check common runtime flags
//! const COMIMAGE_FLAGS_ILONLY: u32 = 0x00000001;
//! const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x00000002;
//!
//! if header.flags & COMIMAGE_FLAGS_ILONLY != 0 {
//!     println!("Assembly contains only managed code");
//! }
//!
//! if header.flags & COMIMAGE_FLAGS_32BITREQUIRED != 0 {
//!     println!("Assembly requires 32-bit runtime");
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe. The [`crate::metadata::cor20header::Cor20Header`]
//! struct contains only primitive types and is [`std::marker::Send`] and [`std::marker::Sync`].
//! The parsing function is stateless and can be called concurrently from multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::File`] - PE file parsing to locate the CLI header
//! - [`crate::metadata`] - Metadata parsing using header information
//! - [`crate::Error`] - Error handling for malformed headers
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with CLI header specification (II.24.3.3)
//! - **PE Format**: Correct interpretation of data directory entries
//! - **Validation**: Comprehensive field validation per specification requirements
//!
//! # Reference
//! - [ECMA-335 II.24](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{file::parser::Parser, Result};

/// The CLI (Common Language Infrastructure) header for .NET assemblies.
///
/// This structure represents the main header for .NET assemblies, located at the beginning
/// of the `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` data directory in PE files. It contains
/// essential information required by the .NET runtime to load and execute the assembly.
///
/// The header has a fixed size of 72 bytes and contains metadata location, runtime version
/// requirements, entry point information, and various optional data directories for
/// resources, strong names, and COM interop features.
///
/// # Layout
///
/// The header follows the ECMA-335 II.24.3.3 specification with the following structure:
/// - Size and version information (8 bytes)
/// - Metadata directory (8 bytes)
/// - Runtime flags and entry point (8 bytes)
/// - Resources directory (8 bytes)
/// - Strong name signature directory (8 bytes)
/// - Reserved and optional directories (32 bytes)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::cor20header::Cor20Header;
///
/// // Parse from PE file's CLI header
/// let header_bytes: &[u8] = &[/* 72 bytes from PE file */];
/// let header = Cor20Header::read(header_bytes)?;
///
/// // Check runtime requirements
/// if header.major_runtime_version >= 4 {
///     println!("Requires .NET Framework 4.0 or later");
/// }
///
/// // Check if assembly is IL-only
/// const COMIMAGE_FLAGS_ILONLY: u32 = 0x00000001;
/// if header.flags & COMIMAGE_FLAGS_ILONLY != 0 {
///     println!("Assembly contains only managed code");
/// }
///
/// // Get metadata location
/// println!("Metadata at RVA 0x{:X}, {} bytes",
///     header.meta_data_rva, header.meta_data_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`Cor20Header`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive types.
/// Instances can be safely shared across threads and accessed concurrently.
pub struct Cor20Header {
    /// Size of the CLI header in bytes (always 72).
    pub cb: u32,
    /// The minimum major version of the .NET runtime required to run this assembly.
    pub major_runtime_version: u16,
    /// The minimum minor version of the .NET runtime required to run this assembly.
    pub minor_runtime_version: u16,
    /// RVA (Relative Virtual Address) of the metadata root directory.
    pub meta_data_rva: u32,
    /// Size of the metadata in bytes.
    pub meta_data_size: u32,
    /// Runtime flags describing assembly characteristics (`IL_ONLY`, `32BIT_REQUIRED`, etc.).
    pub flags: u32,
    /// Metadata token for the entry point method (`MethodDef`) or file for executables.
    pub entry_point_token: u32,
    /// RVA of implementation-specific resources (typically .NET resources).
    pub resource_rva: u32,
    /// Size of implementation-specific resources in bytes.
    pub resource_size: u32,
    /// RVA of the strong name signature hash for assembly verification.
    pub strong_name_signature_rva: u32,
    /// Size of the strong name signature hash in bytes.
    pub strong_name_signature_size: u32,
    /// Reserved field (always 0) - code manager table RVA.
    pub code_manager_table_rva: u32,
    /// Reserved field (always 0) - code manager table size.
    pub code_manager_table_size: u32,
    /// RVA of `VTable` fixups array for COM interop (mixed-mode assemblies).
    pub vtable_fixups_rva: u32,
    /// Size of `VTable` fixups array in bytes.
    pub vtable_fixups_size: u32,
    /// Reserved field (always 0) - export address table jump RVA.
    pub export_address_table_jmp_rva: u32,
    /// Reserved field (always 0) - export address table jump size.
    pub export_address_table_jmp_size: u32,
    /// Reserved field (always 0) - managed native header RVA.
    pub managed_native_header_rva: u32,
    /// Reserved field (always 0) - managed native header size.
    pub managed_native_header_size: u32,
}

impl Cor20Header {
    /// Parses a CLI header from raw byte data.
    ///
    /// This method reads and validates a 72-byte CLI header according to the ECMA-335
    /// specification. It performs comprehensive validation of all fields including:
    /// - Header size validation (must be exactly 72 bytes)
    /// - Runtime version range checking
    /// - Metadata RVA and size validation
    /// - Flags validation against defined constants
    /// - RVA/size pair consistency for optional directories
    /// - Reserved field validation (must be zero)
    ///
    /// # Arguments
    /// * `data` - A byte slice containing at least 72 bytes of CLI header data
    ///
    /// # Returns
    /// Returns a parsed and validated [`Cor20Header`] on success.
    ///
    /// # Errors
    /// Returns [`crate::Error::OutOfBounds`] if the data is too short, or
    /// [`crate::Error::Malformed`] if any field validation fails per ECMA-335 requirements:
    /// - Invalid header size (not 72 bytes)
    /// - Invalid runtime version (0 or > 10)
    /// - Zero metadata RVA or size
    /// - Undefined flag bits set
    /// - Inconsistent RVA/size pairs for directories
    /// - Non-zero reserved fields
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::cor20header::Cor20Header;
    ///
    /// // Read CLI header from PE file
    /// let pe_data: &[u8] = &[/* PE file contents */];
    /// let cli_header_offset = 0x2000; // Example offset from PE directories
    /// let cli_header_data = &pe_data[cli_header_offset..cli_header_offset + 72];
    ///
    /// let header = Cor20Header::read(cli_header_data)?;
    ///
    /// // Use parsed header
    /// println!("CLI Runtime: {}.{}",
    ///     header.major_runtime_version,
    ///     header.minor_runtime_version);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn read(data: &[u8]) -> Result<Cor20Header> {
        const VALID_FLAGS: u32 = 0x0000_001F; // Based on ECMA-335 defined flags

        if data.len() < 72 {
            return Err(out_of_bounds_error!());
        }

        let mut parser = Parser::new(data);

        let cb = parser.read_le::<u32>()?;
        if cb != 72 {
            return Err(malformed_error!(
                "Invalid CLR header size: expected 72, got {}",
                cb
            ));
        }

        let major_runtime_version = parser.read_le::<u16>()?;
        let minor_runtime_version = parser.read_le::<u16>()?;
        if major_runtime_version == 0 || major_runtime_version > 10 {
            return Err(malformed_error!(
                "Invalid major runtime version: {}",
                major_runtime_version
            ));
        }

        let meta_data_rva = parser.read_le::<u32>()?;

        if meta_data_rva == 0 {
            return Err(malformed_error!("Metadata RVA cannot be zero"));
        }

        let meta_data_size = parser.read_le::<u32>()?;
        if meta_data_size == 0 {
            return Err(malformed_error!("Metadata size cannot be zero"));
        } else if meta_data_size > 0x1000_0000 {
            return Err(malformed_error!(
                "Metadata size {} exceeds reasonable limit (256MB)",
                meta_data_size
            ));
        }

        let flags = parser.read_le::<u32>()?;
        if flags & !VALID_FLAGS != 0 {
            return Err(malformed_error!(
                "Invalid CLR flags: 0x{:08X} contains undefined bits",
                flags
            ));
        }

        // Read entry point token (no validation - can be any value)
        let entry_point_token = parser.read_le::<u32>()?;

        // Read and validate resources RVA/size pair
        let resource_rva = parser.read_le::<u32>()?;
        let resource_size = parser.read_le::<u32>()?;
        if (resource_rva == 0 && resource_size != 0) || (resource_rva != 0 && resource_size == 0) {
            return Err(malformed_error!("Resource values are invalid"));
        }

        // Read and validate strong name signature RVA/size pair
        let strong_name_signature_rva = parser.read_le::<u32>()?;
        let strong_name_signature_size = parser.read_le::<u32>()?;
        if (strong_name_signature_rva == 0 && strong_name_signature_size != 0)
            || (strong_name_signature_rva != 0 && strong_name_signature_size == 0)
        {
            return Err(malformed_error!("Strong name values are invalid"));
        }

        // Read and validate reserved fields (must be zero per ECMA-335)
        let code_manager_table_rva = parser.read_le::<u32>()?;
        let code_manager_table_size = parser.read_le::<u32>()?;
        if code_manager_table_rva != 0 || code_manager_table_size != 0 {
            return Err(malformed_error!(
                "Code Manager Table fields must be zero (reserved)"
            ));
        }

        // Read and validate VTable fixups RVA/size pair
        let vtable_fixups_rva = parser.read_le::<u32>()?;
        let vtable_fixups_size = parser.read_le::<u32>()?;
        if (vtable_fixups_rva == 0 && vtable_fixups_size != 0)
            || (vtable_fixups_rva != 0 && vtable_fixups_size == 0)
        {
            return Err(malformed_error!("VTable fixups are invalid"));
        }

        // Read and validate reserved fields (must be zero per ECMA-335)
        let export_address_table_jmp_rva = parser.read_le::<u32>()?;
        let export_address_table_jmp_size = parser.read_le::<u32>()?;
        if export_address_table_jmp_rva != 0 || export_address_table_jmp_size != 0 {
            return Err(malformed_error!(
                "Export Address Table Jump fields must be zero (reserved)"
            ));
        }

        let managed_native_header_rva = parser.read_le::<u32>()?;
        let managed_native_header_size = parser.read_le::<u32>()?;

        Ok(Cor20Header {
            cb,
            major_runtime_version,
            minor_runtime_version,
            meta_data_rva,
            meta_data_size,
            flags,
            entry_point_token,
            resource_rva,
            resource_size,
            strong_name_signature_rva,
            strong_name_signature_size,
            code_manager_table_rva,
            code_manager_table_size,
            vtable_fixups_rva,
            vtable_fixups_size,
            export_address_table_jmp_rva,
            export_address_table_jmp_size,
            managed_native_header_rva,
            managed_native_header_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let header_bytes = [
            0x48, 0x00, 0x00, 0x00, // cb = 72 (0x48)
            0x02, 0x00,             // major_runtime_version = 2
            0x03, 0x00,             // minor_runtime_version = 3
            0x00, 0x00, 0x00, 0x04, // meta_data_rva = 0x04000000
            0x00, 0x00, 0x00, 0x05, // meta_data_size = 0x05000000
            0x00, 0x00, 0x00, 0x00, // flags = 0 (valid flags)
            0x00, 0x00, 0x00, 0x07, // entry_point_token = 0x07000000
            0x00, 0x00, 0x00, 0x00, // resource_rva = 0 (no resources)
            0x00, 0x00, 0x00, 0x00, // resource_size = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_rva = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_size = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_rva = 0 (reserved)
            0x00, 0x00, 0x00, 0x00, // code_manager_table_size = 0 (reserved)
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_rva = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_size = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_rva = 0 (reserved)
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_size = 0 (reserved)
            0x00, 0x00, 0x00, 0x00, // managed_native_header_rva = 0 (reserved)
            0x00, 0x00, 0x00, 0x00  // managed_native_header_size = 0 (reserved)
        ];

        let parsed_header = Cor20Header::read(&header_bytes).unwrap();

        assert_eq!(parsed_header.cb, 72);
        assert_eq!(parsed_header.major_runtime_version, 2);
        assert_eq!(parsed_header.minor_runtime_version, 3);
        assert_eq!(parsed_header.meta_data_rva, 0x04000000);
        assert_eq!(parsed_header.meta_data_size, 0x05000000);
        assert_eq!(parsed_header.flags, 0);
        assert_eq!(parsed_header.entry_point_token, 0x07000000);
        assert_eq!(parsed_header.resource_rva, 0);
        assert_eq!(parsed_header.resource_size, 0);
        assert_eq!(parsed_header.strong_name_signature_rva, 0);
        assert_eq!(parsed_header.strong_name_signature_size, 0);
        assert_eq!(parsed_header.code_manager_table_rva, 0);
        assert_eq!(parsed_header.code_manager_table_size, 0);
        assert_eq!(parsed_header.vtable_fixups_rva, 0);
        assert_eq!(parsed_header.vtable_fixups_size, 0);
        assert_eq!(parsed_header.export_address_table_jmp_rva, 0);
        assert_eq!(parsed_header.export_address_table_jmp_size, 0);
        assert_eq!(parsed_header.managed_native_header_rva, 0);
        assert_eq!(parsed_header.managed_native_header_size, 0);
    }

    #[test]
    fn test_zero_metadata_rva() {
        #[rustfmt::skip]
        let header_bytes = [
            0x48, 0x00, 0x00, 0x00, // cb = 72
            0x02, 0x00,             // major_runtime_version = 2
            0x03, 0x00,             // minor_runtime_version = 3
            0x00, 0x00, 0x00, 0x00, // meta_data_rva = 0 (INVALID)
            0x00, 0x00, 0x00, 0x05, // meta_data_size = 0x05000000
            0x00, 0x00, 0x00, 0x00, // flags = 0
            0x00, 0x00, 0x00, 0x07, // entry_point_token
            0x00, 0x00, 0x00, 0x00, // resource_rva = 0
            0x00, 0x00, 0x00, 0x00, // resource_size = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_rva = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_size = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_rva = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_size = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_rva = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_size = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_rva = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_size = 0
            0x00, 0x00, 0x00, 0x00, // managed_native_header_rva = 0
            0x00, 0x00, 0x00, 0x00  // managed_native_header_size = 0
        ];

        let result = Cor20Header::read(&header_bytes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Metadata RVA cannot be zero"));
        }
    }

    #[test]
    fn test_zero_metadata_size() {
        #[rustfmt::skip]
        let header_bytes = [
            0x48, 0x00, 0x00, 0x00, // cb = 72
            0x02, 0x00,             // major_runtime_version = 2
            0x03, 0x00,             // minor_runtime_version = 3
            0x00, 0x00, 0x00, 0x04, // meta_data_rva = 0x04000000
            0x00, 0x00, 0x00, 0x00, // meta_data_size = 0 (INVALID)
            0x00, 0x00, 0x00, 0x00, // flags = 0
            0x00, 0x00, 0x00, 0x07, // entry_point_token
            0x00, 0x00, 0x00, 0x00, // resource_rva = 0
            0x00, 0x00, 0x00, 0x00, // resource_size = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_rva = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_size = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_rva = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_size = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_rva = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_size = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_rva = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_size = 0
            0x00, 0x00, 0x00, 0x00, // managed_native_header_rva = 0
            0x00, 0x00, 0x00, 0x00  // managed_native_header_size = 0
        ];

        let result = Cor20Header::read(&header_bytes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Metadata size cannot be zero"));
        }
    }

    #[test]
    fn test_invalid_flags() {
        #[rustfmt::skip]
        let header_bytes = [
            0x48, 0x00, 0x00, 0x00, // cb = 72
            0x02, 0x00,             // major_runtime_version = 2
            0x03, 0x00,             // minor_runtime_version = 3
            0x00, 0x00, 0x00, 0x04, // meta_data_rva = 0x04000000
            0x00, 0x00, 0x00, 0x05, // meta_data_size = 0x05000000
            0xFF, 0xFF, 0xFF, 0xFF, // flags = 0xFFFFFFFF (INVALID - has undefined bits)
            0x00, 0x00, 0x00, 0x07, // entry_point_token
            0x00, 0x00, 0x00, 0x00, // resource_rva = 0
            0x00, 0x00, 0x00, 0x00, // resource_size = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_rva = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_size = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_rva = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_size = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_rva = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_size = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_rva = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_size = 0
            0x00, 0x00, 0x00, 0x00, // managed_native_header_rva = 0
            0x00, 0x00, 0x00, 0x00  // managed_native_header_size = 0
        ];

        let result = Cor20Header::read(&header_bytes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid CLR flags"));
        }
    }

    #[test]
    fn test_invalid_strong_name_signature() {
        #[rustfmt::skip]
        let header_bytes = [
            0x48, 0x00, 0x00, 0x00, // cb = 72
            0x02, 0x00,             // major_runtime_version = 2
            0x03, 0x00,             // minor_runtime_version = 3
            0x00, 0x00, 0x00, 0x04, // meta_data_rva = 0x04000000
            0x00, 0x00, 0x00, 0x05, // meta_data_size = 0x05000000
            0x00, 0x00, 0x00, 0x00, // flags = 0
            0x00, 0x00, 0x00, 0x07, // entry_point_token
            0x00, 0x00, 0x00, 0x00, // resource_rva = 0
            0x00, 0x00, 0x00, 0x00, // resource_size = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_rva = 0
            0x01, 0x00, 0x00, 0x00, // strong_name_signature_size = 1 (INVALID - rva is 0 but size is not)
            0x00, 0x00, 0x00, 0x00, // code_manager_table_rva = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_size = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_rva = 0
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_size = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_rva = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_size = 0
            0x00, 0x00, 0x00, 0x00, // managed_native_header_rva = 0
            0x00, 0x00, 0x00, 0x00  // managed_native_header_size = 0
        ];

        let result = Cor20Header::read(&header_bytes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Strong name values are invalid"));
        }
    }

    #[test]
    fn test_invalid_vtable_fixups() {
        #[rustfmt::skip]
        let header_bytes = [
            0x48, 0x00, 0x00, 0x00, // cb = 72
            0x02, 0x00,             // major_runtime_version = 2
            0x03, 0x00,             // minor_runtime_version = 3
            0x00, 0x00, 0x00, 0x04, // meta_data_rva = 0x04000000
            0x00, 0x00, 0x00, 0x05, // meta_data_size = 0x05000000
            0x00, 0x00, 0x00, 0x00, // flags = 0
            0x00, 0x00, 0x00, 0x07, // entry_point_token
            0x00, 0x00, 0x00, 0x00, // resource_rva = 0
            0x00, 0x00, 0x00, 0x00, // resource_size = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_rva = 0
            0x00, 0x00, 0x00, 0x00, // strong_name_signature_size = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_rva = 0
            0x00, 0x00, 0x00, 0x00, // code_manager_table_size = 0
            0x01, 0x00, 0x00, 0x00, // vtable_fixups_rva = 1 (INVALID - rva is not 0 but size is 0)
            0x00, 0x00, 0x00, 0x00, // vtable_fixups_size = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_rva = 0
            0x00, 0x00, 0x00, 0x00, // export_address_table_jmp_size = 0
            0x00, 0x00, 0x00, 0x00, // managed_native_header_rva = 0
            0x00, 0x00, 0x00, 0x00  // managed_native_header_size = 0
        ];

        let result = Cor20Header::read(&header_bytes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("VTable fixups are invalid"));
        }
    }
}
