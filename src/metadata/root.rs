//! Metadata root header and stream directory for .NET assemblies.
//!
//! This module defines the [`Root`] struct, which represents the root metadata header and stream
//! directory as specified by ECMA-335. It provides access to all metadata streams, version info,
//! and structural metadata required for parsing .NET assemblies.
//!
//! # Overview
//!
//! The metadata root is the entry point for reading .NET assembly metadata. It contains the version
//! string, stream directory, and other header fields required to locate and interpret all metadata
//! streams (such as `#~`, `#Strings`, `#Blob`, etc.).
//!
//! # Example
//!
//! ```rust,no_run
//! use dotscope::metadata::root::Root;
//! let root = Root::read(&[
//!            0x42, 0x53, 0x4A, 0x42,
//!            0x00, 0x20,
//!            0x00, 0x30,
//!            0x00, 0x00, 0x00, 0x40,
//!            0x05, 0x00, 0x00, 0x00,
//!            b'H', b'E', b'L', b'L', b'O',
//!            0x00, 0x60,
//!            0x01, 0x00,
//!            0x1, 0x00, 0x00, 0x00, // StreamHeader
//!            0x5, 0x00, 0x00, 0x00,
//!            0x23, 0x7E, 0x00,
//!        ])?;
//! println!("Metadata version: {}", root.version);
//! for stream in &root.stream_headers {
//!     println!("Stream: {} (offset: {}, size: {})", stream.name, stream.offset, stream.size);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//!
//! - [ECMA-335 II.24.2.1: Metadata root](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{
    file::io::{read_le, read_le_at},
    metadata::streams::StreamHeader,
    Error::OutOfBounds,
    Result,
};

/// The MAGIC value indicating the CIL header
pub const CIL_HEADER_MAGIC: u32 = 0x424A_5342;

/// The header of the present Metadata, providing necessary information for parsing. The implemented structure is an
/// approximation and not a 1:1 representation, to allow better use within the framework.
///
/// The [`Root`] struct gives access to the version string, stream directory, and all stream headers
/// required to parse .NET assembly metadata. It is typically the first structure parsed when reading
/// metadata from a PE file.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::metadata::root::Root;
/// let root = Root::read(&[
///            0x42, 0x53, 0x4A, 0x42,
///            0x00, 0x20,
///            0x00, 0x30,
///            0x00, 0x00, 0x00, 0x40,
///            0x05, 0x00, 0x00, 0x00,
///            b'H', b'E', b'L', b'L', b'O',
///            0x00, 0x60,
///            0x01, 0x00,
///            0x1, 0x00, 0x00, 0x00, // StreamHeader
///            0x5, 0x00, 0x00, 0x00,
///            0x23, 0x7E, 0x00,
///        ])?;
/// println!("Version: {}", root.version);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Reference
/// - [ECMA-335 II.24.2.1: Metadata root](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
pub struct Root {
    /// Magic signature for physical metadata: 0x424A5342
    pub signature: u32,
    /// `MajorVersion`
    pub major_version: u16,
    /// `MinorVersion`
    pub minor_version: u16,
    /// Always 0
    pub reserved: u32,
    /// Number of bytes allocated to hold version string
    pub length: u32,
    /// 'VersionString\0'
    pub version: String,
    /// Reserved, always 0
    pub flags: u16,
    /// Number of Streams
    pub stream_number: u16,
    /// Streams
    pub stream_headers: Vec<StreamHeader>,
}

impl Root {
    /// Reads a [`Root`] metadata header from a byte slice.
    ///
    /// # Arguments
    /// * `data` - The byte slice from which this object shall be read
    ///
    /// # Errors
    /// Returns an error if the data is too short, the signature is invalid, or the stream directory is malformed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::root::Root;
    /// let root = Root::read(&[
    ///            0x42, 0x53, 0x4A, 0x42,
    ///            0x00, 0x20,
    ///            0x00, 0x30,
    ///            0x00, 0x00, 0x00, 0x40,
    ///            0x05, 0x00, 0x00, 0x00,
    ///            b'H', b'E', b'L', b'L', b'O',
    ///            0x00, 0x60,
    ///            0x01, 0x00,
    ///            0x1, 0x00, 0x00, 0x00, // StreamHeader
    ///            0x5, 0x00, 0x00, 0x00,
    ///            0x23, 0x7E, 0x00,
    ///        ])?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read(data: &[u8]) -> Result<Root> {
        if data.len() < 36 {
            return Err(OutOfBounds);
        }

        let signature = read_le::<u32>(data)?;
        if signature != CIL_HEADER_MAGIC {
            return Err(malformed_error!(
                "CIL_HEADER_MAGIC does not match - {}",
                signature
            ));
        }

        let version_string_length = read_le_at::<u32>(data, &mut (12))?;
        match u32::checked_add(version_string_length, 16_u32) {
            Some(str_end) => {
                let data_len = u32::try_from(data.len())
                    .map_err(|_| malformed_error!("Data length too large"))?;
                if str_end > data_len {
                    return Err(OutOfBounds);
                }
            }
            None => {
                return Err(malformed_error!(
                    "Version string length causing integer overflow - {} + {}",
                    version_string_length,
                    16
                ))
            }
        }

        let mut version_string: String = String::with_capacity(version_string_length as usize);
        for counter in 0..version_string_length {
            version_string.push(char::from(read_le_at::<u8>(
                data,
                &mut (16 + counter as usize),
            )?));
        }

        let stream_count = read_le_at::<u16>(data, &mut (version_string.len() + 18))?;
        if stream_count == 0 || stream_count > 5 || (stream_count * 9) as usize > data.len() {
            // 9 - min size that a valid StreamHeader can be; Must have streams, no duplicates, no more than 5 possible
            return Err(malformed_error!("Invalid stream count"));
        }

        let mut streams = Vec::with_capacity(stream_count as usize);
        let mut stream_offset = version_string.len() + 20;
        for _ in 0..stream_count {
            if stream_offset > data.len() {
                return Err(OutOfBounds);
            }

            let new_stream = StreamHeader::from(&data[stream_offset..])?;
            if new_stream.offset as usize > data.len()
                || new_stream.size as usize > data.len()
                || new_stream.name.len() > 32
            {
                return Err(OutOfBounds);
            }

            match u32::checked_add(new_stream.offset, new_stream.size) {
                Some(range) => {
                    if range as usize > data.len() {
                        return Err(OutOfBounds);
                    }
                }
                None => {
                    return Err(malformed_error!(
                        "Stream offset and size cause integer overflow - {} + {}",
                        new_stream.offset,
                        new_stream.size
                    ))
                }
            }

            let name_aligned = ((new_stream.name.len() + 1) + 3) & !3;
            stream_offset += 8 + name_aligned;

            streams.push(new_stream);
        }

        // ToDo: Verify, if any stream names are duplicates
        if streams.is_empty() {
            return Err(malformed_error!("No valid streams have been found"));
        }

        Ok(Root {
            signature,
            major_version: read_le::<u16>(&data[4..])?,
            minor_version: read_le::<u16>(&data[6..])?,
            reserved: read_le::<u32>(&data[8..])?,
            length: u32::try_from(version_string.len())
                .map_err(|_| malformed_error!("Version string length too large"))?,
            flags: read_le::<u16>(&data[16 + version_string.len()..])?,
            stream_number: u16::try_from(streams.len())
                .map_err(|_| malformed_error!("Too many streams"))?,
            stream_headers: streams,
            version: version_string,
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
            0x42, 0x53, 0x4A, 0x42,
            0x00, 0x20,
            0x00, 0x30,
            0x00, 0x00, 0x00, 0x40,
            0x05, 0x00, 0x00, 0x00,
            b'H', b'E', b'L', b'L', b'O',
            0x00, 0x60,
            0x01, 0x00,

            0x1, 0x00, 0x00, 0x00, // StreamHeader
            0x5, 0x00, 0x00, 0x00,
            0x23, 0x7E, 0x00,
        ];

        let parsed_header = Root::read(&header_bytes).unwrap();

        assert_eq!(parsed_header.signature, CIL_HEADER_MAGIC);
        assert_eq!(parsed_header.major_version, 0x2000);
        assert_eq!(parsed_header.minor_version, 0x3000);
        assert_eq!(parsed_header.reserved, 0x40000000);
        assert_eq!(parsed_header.length, 5);
        assert_eq!(parsed_header.version, "HELLO");
        assert_eq!(parsed_header.flags, 0x6000);
        assert_eq!(parsed_header.stream_number, 1);
        assert_eq!(parsed_header.stream_headers.len(), 1);
        assert_eq!(parsed_header.stream_headers[0].offset, 0x1);
        assert_eq!(parsed_header.stream_headers[0].size, 0x5);
        assert_eq!(parsed_header.stream_headers[0].name, "#~");
    }
}
