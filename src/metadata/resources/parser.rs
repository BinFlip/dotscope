use std::collections::BTreeMap;

use crate::{
    file::parser::Parser,
    metadata::resources::{ResourceEntry, ResourceType, RESOURCE_MAGIC},
    Result,
};

/// Function to parse a .NET resource buffer
///
/// ## Arguments
/// * 'data' - The data of the resource to parse
pub fn parse_dotnet_resource(data: &[u8]) -> Result<BTreeMap<String, ResourceEntry>> {
    let mut resource = Resource::parse(data)?;
    resource.read_resources(data)
}

/// This represents a parsed object of format `ResourceManager`. Raw access method for resource related
/// data. If you want to have a more abstract access, you can use the `parse_dotnet_resource` instead.
///
/// ### From `CoreCLR`:
/// ```rust,ignore
/// #[doc(no_compile)]
/// The system default file format (V1) is as follows:
///
///     What                                               Type of Data
/// ====================================================   ===========
///
///                        Resource Manager header
/// Magic Number (0xBEEFCACE)                               Int32
/// Resource Manager header version                         Int32
/// Num bytes to skip from here to get past this header     Int32
/// Class name of IResourceReader to parse this file        String
/// Class name of ResourceSet to parse this file            String
///
///                       RuntimeResourceReader header
/// ResourceReader version number                           Int32
/// [Only in debug V2 builds - "***DEBUG***"]               String
/// Number of resources in the file                         Int32
/// Number of types in the type table                       Int32
/// Name of each type                                       Set of Strings
/// Padding bytes for 8-byte alignment (use PAD)            Bytes (0-7)
/// Hash values for each resource name                      Int32 array, sorted
/// Virtual offset of each resource name                    Int32 array, coupled with hash values
/// Absolute location of Data section                       Int32
///
///                     RuntimeResourceReader Name Section
/// Name & virtual offset of each resource                  Set of (UTF-16 String, Int32) pairs
///
///                     RuntimeResourceReader Data Section
/// Type and Value of each resource                         Set of (Int32, blob of bytes) pairs
/// ```
#[derive(Default)]
pub struct Resource {
    /// Resource Manager header version
    pub res_mgr_header_version: u32,
    /// Size of the header
    pub header_size: u32,
    /// Class name of `IResourceReader` to parse this file
    pub reader_type: String,
    /// Class name of `ResourceSet` to parse this file
    pub resource_set_type: String,
    /// Offset of the `ResourceReader` Header
    pub rr_header_offset: usize,
    /// `ResourceReader` version number
    pub rr_version: u32,
    /// Number of resources in the file
    pub resource_count: u32,
    /// The type table - names of the types used in resources
    pub type_names: Vec<String>,
    /// The amount of padding used
    pub padding: usize,
    /// The name hash table - for faster lookups of resources by name
    pub name_hashes: Vec<u32>,
    /// Virtual offset of each resource name (in `RuntimeResourceReader` Name Section)
    pub name_positions: Vec<u32>,
    /// Absolute location of Data section
    pub data_section_offset: usize,
    /// Beginning of the name section
    pub name_section_offset: usize,
    /// Is a debug build
    pub is_debug: bool,
}

impl Resource {
    /// Creates a new Resource from raw data
    ///
    /// # Arguments
    /// * `data` - The buffer of the resource to read from
    ///
    /// # Errors
    /// Returns an error if the resource data is malformed or too small.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            // Need at least size + magic + version
            return Err(malformed_error!("Resource data too small"));
        }

        let mut parser = Parser::new(data);

        let size = parser.read_le::<u32>()? as usize;
        if size > (data.len() - 4) || size < 8 {
            return Err(malformed_error!(
                "The resource format is invalid! size - {}",
                size
            ));
        }

        let magic = parser.read_le::<u32>()?;
        if magic != RESOURCE_MAGIC {
            return Err(malformed_error!("Invalid resource magic: 0x{:X}", magic));
        }

        let mut res: Resource = Resource {
            res_mgr_header_version: parser.read_le::<u32>()?,
            header_size: parser.read_le::<u32>()?,
            reader_type: parser.read_prefixed_string_utf8()?,
            resource_set_type: parser.read_prefixed_string_utf8()?,
            ..Default::default()
        };

        res.rr_header_offset = parser.pos();

        res.rr_version = parser.read_le::<u32>()?;
        if res.rr_version == 2 && parser.peek_byte()? == b'*' {
            // Version 2, can have a '***DEBUG***' string here
            // Read it, but ignore. Will advance our parser accordingly
            let _ = parser.read_string_utf8()?;
            res.is_debug = true;
        }
        res.resource_count = parser.read_le::<u32>()?;

        let type_count = parser.read_le::<u32>()?;
        for _ in 0..type_count {
            res.type_names.push(parser.read_prefixed_string_utf8()?);
        }

        loop {
            let padding_byte = parser.peek_byte()?;
            if padding_byte != b'P'
                && padding_byte != b'A'
                && padding_byte != b'D'
                && padding_byte != 0
            {
                break;
            }
            res.padding += 1;
            parser.advance()?;
        }

        for _ in 0..res.resource_count {
            res.name_hashes.push(parser.read_le::<u32>()?);
        }

        for _ in 0..res.resource_count {
            res.name_positions.push(parser.read_le::<u32>()?);
        }

        // +4 because of the initial size, it's not part of the 'format' but from the embedding
        res.data_section_offset = parser.read_le::<u32>()? as usize + 4;
        res.name_section_offset = parser.pos();

        Ok(res)
    }

    /// Read resources into a map by name
    ///
    /// # Arguments
    /// * `data` - The data buffer to read from
    ///
    /// # Errors
    /// Returns an error if the resource data is malformed or cannot be parsed.
    pub fn read_resources(&mut self, data: &[u8]) -> Result<BTreeMap<String, ResourceEntry>> {
        let mut resources = BTreeMap::new();
        let mut parser = Parser::new(data);

        for i in 0..self.resource_count as usize {
            parser.seek(self.name_section_offset + self.name_positions[i] as usize)?;

            let name = parser.read_prefixed_string_utf16()?;
            let type_offset = parser.read_le::<u32>()?;

            parser.seek(self.data_section_offset + type_offset as usize)?;

            let type_code = parser.read_le::<u8>()?;

            let result = ResourceEntry {
                name: name.clone(),
                name_hash: self.name_hashes[i],
                data: ResourceType::from_type_byte(type_code, &mut parser)?,
            };

            resources.insert(name, result);
        }

        Ok(resources)
    }
}

#[cfg(test)]
mod tests {
    use crate::test::verify_wbdll_resource_buffer;

    #[test]
    fn wb_example() {
        let data =
            include_bytes!("../../../tests/samples/WB_FxResources.WindowsBase.SR.resources.bin");
        verify_wbdll_resource_buffer(data);
    }
}
