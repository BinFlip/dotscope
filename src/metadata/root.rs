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

        // Validate version string format and content
        if version_string.is_empty() {
            return Err(malformed_error!("Version string cannot be empty"));
        }

        // Check for common malformed version strings
        if !version_string.starts_with('v') {
            return Err(malformed_error!(
                "Version string '{}' must start with 'v' (ECMA-335 II.24.2.1)",
                version_string
            ));
        }

        // Validate version string contains reasonable content
        if version_string.len() > 255 {
            return Err(malformed_error!(
                "Version string length {} exceeds reasonable limit (255)",
                version_string.len()
            ));
        }

        let stream_count = read_le_at::<u16>(data, &mut (version_string.len() + 18))?;
        if stream_count == 0 || stream_count > 6 || (stream_count * 9) as usize > data.len() {
            // 9 - min size that a valid StreamHeader can be; Must have streams, no duplicates, no more than 6 possible
            return Err(malformed_error!("Invalid stream count"));
        }

        let mut streams = Vec::with_capacity(stream_count as usize);
        let mut stream_offset = version_string.len() + 20;
        let mut streams_seen = [false; 6];

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

            let stream_index = match new_stream.name.as_str() {
                "#Strings" => 0,
                "#US" => 1,
                "#Blob" => 2,
                "#GUID" => 3,
                "#~" => 4,
                "#-" => 5,
                _ => unreachable!("StreamHeader::from() should have validated the name"),
            };

            if streams_seen[stream_index] {
                return Err(malformed_error!(
                    "Duplicate stream name found: '{}'",
                    new_stream.name
                ));
            }
            streams_seen[stream_index] = true;

            let name_aligned = ((new_stream.name.len() + 1) + 3) & !3;
            stream_offset += 8 + name_aligned;

            streams.push(new_stream);
        }

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

    /// Validates that loaded streams do not overlap in memory
    ///
    /// This method should be called after all streams have been loaded and their actual
    /// positions and sizes are known. It performs comprehensive overlap detection that
    /// was deferred during initial parsing.
    ///
    /// # Arguments
    /// * `meta_root_offset` - The offset where the metadata root starts
    /// * `total_metadata_size` - The total size of the metadata section
    ///
    /// # Errors
    /// Returns an error if any streams overlap or extend beyond the metadata bounds
    pub fn validate_stream_layout(
        &self,
        meta_root_offset: usize,
        total_metadata_size: u32,
    ) -> Result<()> {
        let mut stream_ranges: Vec<(u32, u32, &str)> = Vec::new();

        // Validate stream doesn't exceed metadata bounds
        let metadata_end = meta_root_offset
            .checked_add(total_metadata_size as usize)
            .ok_or_else(|| {
                malformed_error!(
                    "Metadata size causes overflow: {} + {}",
                    meta_root_offset,
                    total_metadata_size
                )
            })?;

        // Calculate actual stream positions
        for stream in &self.stream_headers {
            let absolute_start = meta_root_offset
                .checked_add(stream.offset as usize)
                .ok_or_else(|| {
                    malformed_error!(
                        "Stream '{}' offset causes overflow: {} + {}",
                        stream.name,
                        meta_root_offset,
                        stream.offset
                    )
                })?;

            let absolute_end = absolute_start
                .checked_add(stream.size as usize)
                .ok_or_else(|| {
                    malformed_error!(
                        "Stream '{}' size causes overflow: {} + {}",
                        stream.name,
                        absolute_start,
                        stream.size
                    )
                })?;

            if absolute_end > metadata_end {
                return Err(malformed_error!(
                    "Stream '{}' extends beyond metadata bounds (end {} > metadata end {})",
                    stream.name,
                    absolute_end,
                    metadata_end
                ));
            }

            stream_ranges.push((
                u32::try_from(absolute_start).map_err(|_| {
                    malformed_error!(
                        "Stream '{}' start position {} exceeds u32 range",
                        stream.name,
                        absolute_start
                    )
                })?,
                u32::try_from(absolute_end).map_err(|_| {
                    malformed_error!(
                        "Stream '{}' end position {} exceeds u32 range",
                        stream.name,
                        absolute_end
                    )
                })?,
                &stream.name,
            ));
        }

        for (i, &(start1, end1, name1)) in stream_ranges.iter().enumerate() {
            for &(start2, end2, name2) in stream_ranges.iter().skip(i + 1) {
                if start1 < end2 && start2 < end1 {
                    return Err(malformed_error!(
                        "Stream '{}' ({}..{}) overlaps with stream '{}' ({}..{})",
                        name1,
                        start1,
                        end1,
                        name2,
                        start2,
                        end2
                    ));
                }
            }
        }

        Ok(())
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
            0x06, 0x00, 0x00, 0x00, // length = 6 for "v4.0.0"
            b'v', b'4', b'.', b'0', b'.', b'0',
            0x00, 0x60,
            0x01, 0x00,

            0x1, 0x00, 0x00, 0x00, // StreamHeader
            0x8, 0x00, 0x00, 0x00,
            0x23, 0x7E, 0x00,
        ];

        let parsed_header = Root::read(&header_bytes).unwrap();

        assert_eq!(parsed_header.signature, CIL_HEADER_MAGIC);
        assert_eq!(parsed_header.major_version, 0x2000);
        assert_eq!(parsed_header.minor_version, 0x3000);
        assert_eq!(parsed_header.reserved, 0x40000000);
        assert_eq!(parsed_header.length, 6);
        assert_eq!(parsed_header.version, "v4.0.0");
        assert_eq!(parsed_header.flags, 0x6000);
        assert_eq!(parsed_header.stream_number, 1);
        assert_eq!(parsed_header.stream_headers.len(), 1);
        assert_eq!(parsed_header.stream_headers[0].offset, 0x1);
        assert_eq!(parsed_header.stream_headers[0].size, 0x8);
        assert_eq!(parsed_header.stream_headers[0].name, "#~");
    }

    #[test]
    fn duplicate_stream_names_should_fail() {
        #[rustfmt::skip]
        let mut header_bytes = vec![
            0x42, 0x53, 0x4A, 0x42,  // CIL_HEADER_MAGIC
            0x00, 0x20,              // major_version
            0x00, 0x30,              // minor_version
            0x00, 0x00, 0x00, 0x40,  // reserved
            0x06, 0x00, 0x00, 0x00,  // length (version string length)
            b'v', b'4', b'.', b'0', b'.', b'0',  // version string
            0x00, 0x60,              // flags
            0x02, 0x00,              // stream_number (2 streams)

            // First StreamHeader - #~
            0x52, 0x00, 0x00, 0x00,  // offset (82 - past all headers)
            0x08, 0x00, 0x00, 0x00,  // size (8 bytes - aligned)
            0x23, 0x7E, 0x00, 0x00,  // "#~\0" + padding

            // Second StreamHeader - duplicate #~
            0x5A, 0x00, 0x00, 0x00,  // offset (90 - after first stream)
            0x08, 0x00, 0x00, 0x00,  // size (8 bytes - aligned)
            0x23, 0x7E, 0x00, 0x00,  // "#~\0" + padding (duplicate)
        ];

        // Add enough padding to reach offset 82 and then the stream data
        header_bytes.resize(98, 0x00);

        let result = Root::read(&header_bytes);
        assert!(result.is_err());

        if let Err(error) = result {
            let error_string = error.to_string();
            assert!(error_string.contains("Duplicate stream name found"));
            assert!(error_string.contains("#~"));
        }
    }
}
