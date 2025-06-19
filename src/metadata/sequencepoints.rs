//!
//! Sequence Points parsing and access for PortablePDB MethodDebugInformation.
//!
//! This module provides types and functions to parse and expose sequence points from the
//! PortablePDB format, mapping IL offsets to source code locations for debugging purposes.
//!
//! # Architecture
//!
//! Sequence points are stored in the [`crate::metadata::tables::methoddebuginformation::owned::MethodDebugInformation`] table as a compressed blob.
//! This module parses the blob and exposes a user-friendly API for accessing sequence point data.
//!
//! # Key Components
//!
//! - [`crate::metadata::sequencepoints::SequencePoint`] - Represents a single mapping from IL offset to source code location.
//! - [`crate::metadata::sequencepoints::SequencePoints`] - Collection of sequence points for a method.
//! - [`crate::metadata::sequencepoints::parse_sequence_points`] - Parses a sequence points blob into a collection.
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::sequencepoints::{parse_sequence_points, SequencePoints};
//!
//! let blob: &[u8] = &[1, 10, 2, 0, 5];
//! let points = parse_sequence_points(blob)?;
//! assert_eq!(points.0.len(), 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! Returns [`crate::Error`] if the blob is malformed or contains invalid compressed data.
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`] because they contain only owned data.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::methoddebuginformation::owned`] - for exposing parsed sequence points per method
//! - [`crate::file::parser::Parser`] - for binary parsing utilities
//!
//! # Sequence Points Blob Format
//!
//! The sequence points blob in PortablePDB is a compressed, delta-encoded list of mappings from IL offsets to source code locations.
//! It is stored as a blob in the [`crate::metadata::tables::methoddebuginformation::owned::MethodDebugInformation`] table.
//!
//! ## Layout
//!
//! Each sequence point entry consists of:
//! - **IL Offset**: (compressed unsigned int)
//! - **Start Line**: (compressed unsigned int for first entry, compressed signed int delta for subsequent entries)
//! - **Start Column**: (compressed unsigned int for first entry, compressed signed int delta for subsequent entries)
//! - **End Line Delta**: (compressed unsigned int, added to start line)
//! - **End Column Delta**: (compressed unsigned int, added to start column)
//!
//! The first entry uses absolute values for start line/col, subsequent entries use deltas.
//! All values are encoded using ECMA-335 compressed integer encoding (see II.23.2).
//!
//! ## Example
//!
//! For two sequence points:
//! - First: il_offset=1, start_line=10, start_col=2, end_line_delta=0, end_col_delta=5
//! - Second: il_offset_delta=2, start_line_delta=1, start_col_delta=1, end_line_delta=0, end_col_delta=2
//!
//! Encoded as:
//! ```text
//! [1, 10, 2, 0, 5, 4, 2, 2, 0, 2]
//! ```
//! Where 4 is the compressed int for delta 2, and 2 is the compressed int for delta 1.
//!
//! ## Hidden Sequence Points
//!
//! A sequence point is considered hidden if its start line is 0xFEEFEE. This is used to mark compiler-generated or non-user code.
//! The value 0xFEEFEE is encoded as a compressed unsigned int: [0xC0, 0xFE, 0xEF, 0xEE].
//!
//! ## References
//!
//! - [ECMA-335 II.24.2.6.2](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [PortablePDB Spec](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#sequence-points)

use crate::{file::parser::Parser, Result};

/// Represents a single sequence point mapping IL offset to source code location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencePoint {
    /// Offset in the method's IL stream.
    pub il_offset: u32,
    /// Starting line in the source file.
    pub start_line: u32,
    /// Starting column in the source file.
    pub start_col: u16,
    /// Ending line in the source file.
    pub end_line: u32,
    /// Ending column in the source file.
    pub end_col: u16,
    /// True if this is a hidden sequence point (start_line == 0xFEEFEE).
    pub is_hidden: bool,
}

/// Collection of sequence points for a method.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SequencePoints(pub Vec<SequencePoint>);

impl SequencePoints {
    /// Returns the sequence point for a given IL offset, if any.
    pub fn find_by_il_offset(&self, il_offset: u32) -> Option<&SequencePoint> {
        self.0.iter().find(|sp| sp.il_offset == il_offset)
    }
}

/// Parses a PortablePDB sequence points blob into a SequencePoints collection.
///
/// # Arguments
/// * `blob` - The raw sequence points blob from MethodDebugInformation.
///
/// # Returns
/// * `Ok(SequencePoints)` on success, or `Err(OutOfBounds)` on failure.
pub fn parse_sequence_points(blob: &[u8]) -> Result<SequencePoints> {
    let mut parser = Parser::new(blob);
    let mut points = Vec::new();
    let mut il_offset = 0u32;
    let mut start_line = 0u32;
    let mut start_col = 0u16;
    let mut first = true;

    // Document reference is handled at a higher level if present.
    while parser.has_more_data() {
        let il_offset_delta = parser.read_compressed_uint()?;
        il_offset = if first {
            il_offset_delta
        } else {
            il_offset + il_offset_delta
        };

        let start_line_delta = if first {
            parser.read_compressed_uint()? // Absolute
        } else {
            parser.read_compressed_int()? as u32 // Delta
        };
        start_line = if first {
            start_line_delta
        } else {
            start_line.wrapping_add(start_line_delta)
        };

        let start_col_delta = if first {
            parser.read_compressed_uint()? as u16 // Absolute
        } else {
            parser.read_compressed_int()? as u16 // Delta
        };
        start_col = if first {
            start_col_delta
        } else {
            start_col.wrapping_add(start_col_delta)
        };

        let end_line_delta = parser.read_compressed_uint()?;
        let end_col_delta = parser.read_compressed_uint()? as u16;
        let end_line = start_line + end_line_delta;
        let end_col = start_col + end_col_delta;

        let is_hidden = start_line == 0xFEEFEE;
        points.push(SequencePoint {
            il_offset,
            start_line,
            start_col,
            end_line,
            end_col,
            is_hidden,
        });
        first = false;
    }
    Ok(SequencePoints(points))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_blob() {
        let blob: &[u8] = &[];
        let result = parse_sequence_points(blob);
        assert!(result.is_ok());
        assert!(result.unwrap().0.is_empty());
    }

    #[test]
    fn parse_single_sequence_point() {
        // This is a synthetic blob: absolute il_offset=1, start_line=10, start_col=2, end_line_delta=0, end_col_delta=5
        let blob: &[u8] = &[1, 10, 2, 0, 5];
        let result = parse_sequence_points(blob).unwrap();
        assert_eq!(result.0.len(), 1);
        let sp = &result.0[0];
        assert_eq!(sp.il_offset, 1);
        assert_eq!(sp.start_line, 10);
        assert_eq!(sp.start_col, 2);
        assert_eq!(sp.end_line, 10);
        assert_eq!(sp.end_col, 7);
        assert!(!sp.is_hidden);
    }

    #[test]
    fn parse_hidden_sequence_point() {
        // il_offset=0, start_line=0xFEEFEE (hidden), start_col=0, end_line_delta=0, end_col_delta=0
        // 0xFEEFEE as ECMA-335 compressed uint: [0xC0, 0xFE, 0xEF, 0xEE]
        // Only 5 fields needed: il_offset, start_line, start_col, end_line_delta, end_col_delta
        let blob: &[u8] = &[0, 0xC0, 0xFE, 0xEF, 0xEE, 0, 0, 0];
        let result = parse_sequence_points(blob);
        if let Ok(points) = result {
            let sp = &points.0[0];
            assert!(sp.is_hidden);
            assert_eq!(sp.start_line, 0xFEEFEE);
            assert_eq!(sp.il_offset, 0);
            assert_eq!(sp.start_col, 0);
            assert_eq!(sp.end_line, 0xFEEFEE);
            assert_eq!(sp.end_col, 0);
        } else {
            panic!("Hidden sequence point parse failed: {:?}", result);
        }
    }

    #[test]
    fn parse_multiple_sequence_points_with_deltas() {
        // First: il_offset=1, start_line=10, start_col=2, end_line_delta=0, end_col_delta=5
        // Second: il_offset_delta=2, start_line_delta=1, start_col_delta=1, end_line_delta=0, end_col_delta=2
        // All values must be ECMA-335 compressed ints:
        // 1, 10, 2, 0, 5, 4, 2, 2, 0, 2
        let blob: &[u8] = &[1, 10, 2, 0, 5, 4, 2, 2, 0, 2];
        let result = parse_sequence_points(blob).unwrap();
        assert_eq!(result.0.len(), 2);
        let sp0 = &result.0[0];
        let sp1 = &result.0[1];
        assert_eq!(sp0.il_offset, 1);
        assert_eq!(sp0.start_line, 10);
        assert_eq!(sp0.start_col, 2);
        assert_eq!(sp0.end_line, 10);
        assert_eq!(sp0.end_col, 7);
        assert_eq!(sp1.il_offset, 5); // 1 + 4 (delta for 2 is 4 in compressed int)
        assert_eq!(sp1.start_line, 11); // 10 + 1 (delta for 1 is 2 in compressed int)
        assert_eq!(sp1.start_col, 3); // 2 + 1 (delta for 1 is 2 in compressed int)
        assert_eq!(sp1.end_line, 11);
        assert_eq!(sp1.end_col, 5);
    }
}
