//! CLR 2.0 (Cor20) header parsing for .NET assemblies.
//!
//! This module defines the [`Cor20Header`] struct, which represents the main header for .NET assemblies
//! as found in the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR data directory of PE files.
//!
//! # Reference
//! - [ECMA-335 II.24](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{file::parser::Parser, Error::OutOfBounds, Result};

/// The main header of CIL, located at the beginning of the `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` data
/// directory of PE files.
///
/// This struct contains all fields defined by the ECMA-335 standard for the CLR 2.0 header.
pub struct Cor20Header {
    /// Size of header in bytes
    pub cb: u32,
    /// The minimum version of runtime required to run this program
    pub major_runtime_version: u16,
    /// The minor portion of the version
    pub minor_runtime_version: u16,
    /// RVA of the `MetaData`
    pub meta_data_rva: u32,
    /// Size of the `MetaData`
    pub meta_data_size: u32,
    /// Flags describing this runtime
    pub flags: u32,
    /// Token for the `MethodDef` or File of the entry point for the image
    pub entry_point_token: u32,
    /// RVA of implementation specific resources
    pub resource_rva: u32,
    /// Size of implementation specific resources
    pub resource_size: u32,
    /// RVA of the hash data for this pe file used by the CLI loader for binding and versioning
    pub strong_name_signature_rva: u32,
    /// Size of the hash data
    pub strong_name_signature_size: u32,
    /// Always 0
    pub code_manager_table_rva: u32,
    /// Always 0
    pub code_manager_table_size: u32,
    /// RVA of an array of locations in the file that contain an array of functions pointers
    pub vtable_fixups_rva: u32,
    /// Size of an array of locations in the file that contain an array of functions pointers
    pub vtable_fixups_size: u32,
    /// Always 0
    pub export_address_table_jmp_rva: u32,
    /// Always 0
    pub export_address_table_jmp_size: u32,
    /// Always 0
    pub managed_native_header_rva: u32,
    /// Always 0
    pub managed_native_header_size: u32,
}

impl Cor20Header {
    /// Create a `CilHeader` object from a sequence of bytes
    ///
    /// # Arguments
    /// * `data` - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the data is too short to contain a valid CLR header,
    /// or if any field validation fails per ECMA-335 II.24.3.3.
    pub fn read(data: &[u8]) -> Result<Cor20Header> {
        const VALID_FLAGS: u32 = 0x0000_001F; // Based on ECMA-335 defined flags

        if data.len() < 72 {
            return Err(OutOfBounds);
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
}
