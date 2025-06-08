//! CLR 2.0 (Cor20) header parsing for .NET assemblies.
//!
//! This module defines the [`Cor20Header`] struct, which represents the main header for .NET assemblies
//! as found in the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR data directory of PE files.
//!
//! # Reference
//! - [ECMA-335 II.24](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{file::io::read_le_at, Error::OutOfBounds, Result};

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
    /// * 'data'    - The byte slice from which this object shall be created
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too short to contain a valid CLR header.
    pub fn read(data: &[u8]) -> Result<Cor20Header> {
        // 68 - size of this in memory
        if data.len() < 68 {
            return Err(OutOfBounds);
        }

        let mut cursor = 0_usize;

        Ok(Cor20Header {
            cb: read_le_at::<u32>(data, &mut cursor)?,
            major_runtime_version: read_le_at::<u16>(data, &mut cursor)?,
            minor_runtime_version: read_le_at::<u16>(data, &mut cursor)?,
            meta_data_rva: read_le_at::<u32>(data, &mut cursor)?,
            meta_data_size: read_le_at::<u32>(data, &mut cursor)?,
            flags: read_le_at::<u32>(data, &mut cursor)?,
            entry_point_token: read_le_at::<u32>(data, &mut cursor)?,
            resource_rva: read_le_at::<u32>(data, &mut cursor)?,
            resource_size: read_le_at::<u32>(data, &mut cursor)?,
            strong_name_signature_rva: read_le_at::<u32>(data, &mut cursor)?,
            strong_name_signature_size: read_le_at::<u32>(data, &mut cursor)?,
            code_manager_table_rva: read_le_at::<u32>(data, &mut cursor)?,
            code_manager_table_size: read_le_at::<u32>(data, &mut cursor)?,
            vtable_fixups_rva: read_le_at::<u32>(data, &mut cursor)?,
            vtable_fixups_size: read_le_at::<u32>(data, &mut cursor)?,
            export_address_table_jmp_rva: read_le_at::<u32>(data, &mut cursor)?,
            export_address_table_jmp_size: read_le_at::<u32>(data, &mut cursor)?,
            managed_native_header_rva: read_le_at::<u32>(data, &mut cursor)?,
            managed_native_header_size: read_le_at::<u32>(data, &mut cursor)?,
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
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x02,
            0x00, 0x03,
            0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x10,
            0x10, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x11,
            0x00, 0x00, 0x00, 0x12,
            0x00, 0x00, 0x00, 0x13,
            0x00, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x15,
            0x00, 0x00, 0x00, 0x16,
            0x00, 0x00, 0x00, 0x17,
            0x00, 0x00, 0x00, 0x18,
            0x00, 0x00, 0x00, 0x19
        ];

        let parsed_header = Cor20Header::read(&header_bytes).unwrap();

        assert_eq!(parsed_header.cb, 0x01000000);
        assert_eq!(parsed_header.major_runtime_version, 0x0200);
        assert_eq!(parsed_header.minor_runtime_version, 0x0300);
        assert_eq!(parsed_header.meta_data_rva, 0x04000000);
        assert_eq!(parsed_header.meta_data_size, 0x05000000);
        assert_eq!(parsed_header.flags, 0x06000000);
        assert_eq!(parsed_header.entry_point_token, 0x07000000);
        assert_eq!(parsed_header.resource_rva, 0x08000000);
        assert_eq!(parsed_header.resource_size, 0x09000000);
        assert_eq!(parsed_header.strong_name_signature_rva, 0x10000000);
        assert_eq!(parsed_header.strong_name_signature_size, 0x10000010);
        assert_eq!(parsed_header.code_manager_table_rva, 0x11000000);
        assert_eq!(parsed_header.code_manager_table_size, 0x12000000);
        assert_eq!(parsed_header.vtable_fixups_rva, 0x13000000);
        assert_eq!(parsed_header.vtable_fixups_size, 0x14000000);
        assert_eq!(parsed_header.export_address_table_jmp_rva, 0x15000000);
        assert_eq!(parsed_header.export_address_table_jmp_size, 0x16000000);
        assert_eq!(parsed_header.managed_native_header_rva, 0x17000000);
        assert_eq!(parsed_header.managed_native_header_size, 0x18000000);
    }
}
