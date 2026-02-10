//! Streaming heap writers for metadata heaps.
//!
//! This module provides streaming writers that process heap entries directly to output
//! without intermediate buffering. The design supports:
//!
//! - **Zero-copy for unmodified entries**: Original data written directly to output
//! - **Deduplication**: Identical entries share the same offset
//! - **Modification support**: Entries can be modified, deleted, or appended
//! - **Remapping**: Returns old→new offset mapping for patching table references
//!
//! # Architecture
//!
//! Each heap processor can operate in two modes:
//! - **Write mode**: Streams data to output while computing offsets
//! - **Compute mode**: Only computes offsets without writing (for pre-computation)
//!
//! Both modes share the same core logic to avoid duplication. The public API provides
//! separate functions for clarity, but internally they use unified implementations.

use std::collections::{HashMap, HashSet};

use rustc_hash::FxHashMap;

use crate::{
    cilassembly::{
        changes::HeapChanges,
        writer::{output::Output, signatures::remap_signature_tokens},
    },
    metadata::streams::{Blob, Guid, Strings, UserStrings},
    utils::{compressed_uint_size, hash_blob, hash_string, to_u32, write_compressed_uint},
    Result,
};

/// Result of streaming a heap to output.
#[derive(Debug)]
pub struct StreamResult {
    /// Number of bytes written to output.
    pub bytes_written: u64,
    /// Mapping from old heap offsets/indices to new offsets/indices.
    pub remapping: HashMap<u32, u32>,
}

impl StreamResult {
    /// Creates a new empty stream result.
    ///
    /// # Returns
    ///
    /// A new `StreamResult` with zero bytes written and empty remapping.
    pub fn new() -> Self {
        Self {
            bytes_written: 0,
            remapping: HashMap::new(),
        }
    }
}

impl Default for StreamResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Streams the #Strings heap to output with deduplication and modifications.
///
/// Processes the source string heap data, applying any modifications from the changes,
/// and writes the result to the output file with deduplication. When `referenced_offsets`
/// is provided, substring remappings are generated for any referenced offset that falls
/// within a string entry's byte range.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #Strings heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
/// * `referenced_offsets` - Set of all offsets referenced by metadata tables (for substring remapping)
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn stream_strings_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced_offsets: &HashSet<u32>,
) -> Result<StreamResult> {
    process_strings_heap(
        Some(output),
        start_offset,
        source_data,
        changes,
        referenced_offsets,
    )
}

/// Pre-computes string heap offsets and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// before method bodies are written. It computes what offsets entries will have
/// without actually writing to the output.
///
/// # Arguments
///
/// * `source_data` - The original #Strings heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_strings_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<String>,
) -> Result<StreamResult> {
    let empty = HashSet::new();
    process_strings_heap(None, 0, source_data, changes, &empty)
}

/// Unified string heap processor.
///
/// When `output` is `Some(output)`, writes to output at `start_offset`.
/// When `output` is `None`, only computes offsets (for pre-computation).
/// When `referenced_offsets` is non-empty, substring remappings are added
/// for any referenced offset that falls within a written string's byte range.
fn process_strings_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced_offsets: &HashSet<u32>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();

    // If this is a raw heap replacement with no modifications or appends,
    // write the source data directly. This is needed for tests that create
    // intentionally malformed heaps that won't parse correctly.
    if changes.has_replacement()
        && changes.additions_count() == 0
        && changes.modifications_count() == 0
        && changes.removals_count() == 0
    {
        if let Some(out) = output.as_mut() {
            out.write_at(start_offset, source_data)?;
        }
        result.bytes_written = source_data.len() as u64;
        return Ok(result);
    }

    let mut pos: u64 = 1; // Start after null byte

    // Track content → new_offset for deduplication
    let mut dedup_map: FxHashMap<u64, u32> = FxHashMap::default();
    dedup_map.insert(hash_string(""), 0);

    // Write null byte if in write mode
    if let Some(out) = output.as_mut() {
        out.write_at(start_offset, &[0u8])?;
    }

    // Process source heap
    if let Ok(strings) = Strings::from(source_data) {
        for (old_offset, original_str) in strings.iter() {
            let old_offset_u32 = u32::try_from(old_offset).map_err(|_| {
                crate::Error::LayoutFailed(format!(
                    "String offset {} exceeds u32 range",
                    old_offset
                ))
            })?;

            if changes.is_removed(old_offset_u32) {
                continue;
            }

            let final_str = changes
                .get_modification(old_offset_u32)
                .map_or(original_str, |s| s.as_str());

            let content_hash = hash_string(final_str);
            if let Some(&existing_offset) = dedup_map.get(&content_hash) {
                if old_offset_u32 != existing_offset {
                    result.remapping.insert(old_offset_u32, existing_offset);
                }
                continue;
            }

            let new_offset = u32::try_from(pos).map_err(|_| {
                crate::Error::LayoutFailed(format!("Heap position {} exceeds u32 range", pos))
            })?;
            let str_bytes = final_str.as_bytes();
            let entry_size = str_bytes.len() as u64 + 1; // +1 for null terminator

            // Write if in write mode
            if let Some(out) = output.as_mut() {
                out.write_at(start_offset + pos, str_bytes)?;
                out.write_at(start_offset + pos + str_bytes.len() as u64, &[0u8])?;
            }

            pos += entry_size;
            dedup_map.insert(content_hash, new_offset);

            // Add primary offset remapping if changed
            if old_offset_u32 != new_offset {
                result.remapping.insert(old_offset_u32, new_offset);
            }

            // Add substring remappings for any referenced offset within this string's range.
            // This handles .NET's ability to reference any offset within a string entry.
            let str_end = old_offset_u32 + to_u32(str_bytes.len())? + 1; // +1 for null
            for &ref_offset in referenced_offsets {
                // Check if this reference is a substring of this entry (not the primary offset)
                if ref_offset > old_offset_u32 && ref_offset < str_end {
                    let substring_delta = ref_offset - old_offset_u32;
                    let new_substring_offset = new_offset + substring_delta;
                    result.remapping.insert(ref_offset, new_substring_offset);
                }
            }
        }
    }

    // Process appended strings
    // Note: We need to skip positions that are keys in the remapping, as those old offsets
    // would cause newly allocated entries to be incorrectly remapped when heap patching
    // is applied to table rows. This is more space-efficient than starting after max_old_offset.
    for (new_string, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        let placeholder = change_ref.placeholder();
        let final_str = changes
            .get_modification(placeholder)
            .map_or(new_string.as_str(), |s| s.as_str());

        let content_hash = hash_string(final_str);
        if let Some(&existing_offset) = dedup_map.get(&content_hash) {
            change_ref.resolve_to_offset(existing_offset);
            continue;
        }

        // Skip positions that are remapping keys to avoid collision with old offsets
        // that would be incorrectly remapped when heap patching is applied
        while result.remapping.contains_key(&(pos as u32)) {
            pos += 1;
        }

        let new_offset = u32::try_from(pos).map_err(|_| {
            crate::Error::LayoutFailed(format!("Heap position {} exceeds u32 range", pos))
        })?;
        let str_bytes = final_str.as_bytes();
        let entry_size = str_bytes.len() as u64 + 1;

        if let Some(out) = output.as_mut() {
            out.write_at(start_offset + pos, str_bytes)?;
            out.write_at(start_offset + pos + str_bytes.len() as u64, &[0u8])?;
        }

        pos += entry_size;
        dedup_map.insert(content_hash, new_offset);
        change_ref.resolve_to_offset(new_offset);
    }

    result.bytes_written = pos;
    Ok(result)
}

/// Streams the #Blob heap to output with deduplication and modifications.
///
/// Processes the source blob heap data, applying any modifications from the changes,
/// and writes the result to the output file with deduplication. When `typedef_remap`
/// or `typeref_remap` is non-empty, signature blobs that contain TypeDef/TypeRef
/// tokens will have those tokens remapped to their new RIDs after row deletions.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #Blob heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
/// * `typedef_remap` - Mapping from old TypeDef RIDs to new RIDs (empty if no remapping needed)
/// * `typeref_remap` - Mapping from old TypeRef RIDs to new RIDs (empty if no remapping needed)
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn stream_blob_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<Vec<u8>>,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> Result<StreamResult> {
    process_blob_heap(
        Some(output),
        start_offset,
        source_data,
        changes,
        typedef_remap,
        typeref_remap,
    )
}

/// Pre-computes blob heap offsets and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// before method bodies are written.
///
/// # Arguments
///
/// * `source_data` - The original #Blob heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_blob_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<Vec<u8>>,
) -> Result<StreamResult> {
    let empty = HashMap::new();
    process_blob_heap(None, 0, source_data, changes, &empty, &empty)
}

/// Unified blob heap processor.
///
/// When `typedef_remap` or `typeref_remap` is non-empty, signature blobs that
/// contain TypeDef/TypeRef tokens will have those tokens remapped to their new RIDs.
fn process_blob_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<Vec<u8>>,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();
    let mut pos: u64 = 1; // Start after null byte

    let mut dedup_map: FxHashMap<u64, u32> = FxHashMap::default();
    dedup_map.insert(hash_blob(&[]), 0);

    // Write null byte if in write mode
    if let Some(out) = output.as_mut() {
        out.write_at(start_offset, &[0u8])?;
    }

    // Process source heap
    if let Ok(blobs) = Blob::from(source_data) {
        for (old_offset, original_blob) in blobs.iter() {
            let old_offset_u32 = u32::try_from(old_offset).map_err(|_| {
                crate::Error::LayoutFailed(format!("Blob offset {} exceeds u32 range", old_offset))
            })?;

            if changes.is_removed(old_offset_u32) {
                continue;
            }

            // Get the blob content (original or modified)
            let base_blob: &[u8] = changes
                .get_modification(old_offset_u32)
                .map_or(original_blob, Vec::as_slice);

            // Apply signature token remapping if TypeDef/TypeRef RIDs have shifted
            let remapped_blob: Option<Vec<u8>> = if (!typedef_remap.is_empty()
                || !typeref_remap.is_empty())
                && !base_blob.is_empty()
            {
                remap_signature_tokens(base_blob, typedef_remap, typeref_remap)
                    .ok()
                    .flatten()
            } else {
                None
            };

            let final_blob: &[u8] = remapped_blob.as_deref().unwrap_or(base_blob);

            let content_hash = hash_blob(final_blob);
            if let Some(&existing_offset) = dedup_map.get(&content_hash) {
                // Don't deduplicate empty blobs to offset 0 - this would change their semantics.
                // An empty blob at a non-zero offset is valid (e.g., method with no local variables),
                // but if we remap it to offset 0, it becomes a "null blob reference" which may be
                // interpreted differently when parsing (e.g., LocalVarSig parsing would fail).
                if existing_offset == 0 && old_offset_u32 != 0 && final_blob.is_empty() {
                    // Write the empty blob at its original position to preserve semantics
                    let new_offset = u32::try_from(pos).map_err(|_| {
                        crate::Error::LayoutFailed(format!(
                            "Heap position {} exceeds u32 range",
                            pos
                        ))
                    })?;

                    if let Some(out) = output.as_mut() {
                        // Write compressed length of 0
                        out.write_at(start_offset + pos, &[0u8])?;
                    }
                    pos += 1; // Empty blob is just 1 byte (length 0)

                    // Only add to remapping if the offset actually changed
                    if old_offset_u32 != new_offset {
                        result.remapping.insert(old_offset_u32, new_offset);
                    }
                    continue;
                }

                // Normal deduplication for non-empty blobs
                if old_offset_u32 != existing_offset {
                    result.remapping.insert(old_offset_u32, existing_offset);
                }
                continue;
            }

            let new_offset = u32::try_from(pos).map_err(|_| {
                crate::Error::LayoutFailed(format!("Heap position {} exceeds u32 range", pos))
            })?;
            let len_size = compressed_uint_size(final_blob.len());
            let entry_size = len_size + final_blob.len() as u64;

            if let Some(out) = output.as_mut() {
                let blob_len_u32 = u32::try_from(final_blob.len()).map_err(|_| {
                    crate::Error::LayoutFailed(format!(
                        "Blob length {} exceeds u32 range",
                        final_blob.len()
                    ))
                })?;
                let mut len_bytes = Vec::with_capacity(4);
                write_compressed_uint(blob_len_u32, &mut len_bytes);
                let write_pos = start_offset + pos;
                out.write_at(write_pos, &len_bytes)?;
                out.write_at(write_pos + len_bytes.len() as u64, final_blob)?;
            }

            pos += entry_size;
            dedup_map.insert(content_hash, new_offset);
            // Only add to remapping if the offset actually changed
            if old_offset_u32 != new_offset {
                result.remapping.insert(old_offset_u32, new_offset);
            }
        }
    }

    // Process appended blobs
    // Note: We need to skip positions that are keys in the remapping, as those old offsets
    // would cause newly allocated entries to be incorrectly remapped when heap patching
    // is applied to table rows. This is more space-efficient than starting after max_old_offset.
    for (new_blob, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        let placeholder = change_ref.placeholder();
        let base_blob: &[u8] = changes
            .get_modification(placeholder)
            .map_or(new_blob.as_slice(), Vec::as_slice);

        // Apply signature token remapping to new blobs as well
        // This is essential for regenerated methods whose local signatures contain
        // TypeDef/TypeRef tokens that need remapping when types are deleted
        let remapped_blob: Option<Vec<u8>> =
            if (!typedef_remap.is_empty() || !typeref_remap.is_empty()) && !base_blob.is_empty() {
                remap_signature_tokens(base_blob, typedef_remap, typeref_remap)
                    .ok()
                    .flatten()
            } else {
                None
            };

        let final_blob: &[u8] = remapped_blob.as_deref().unwrap_or(base_blob);

        let content_hash = hash_blob(final_blob);
        if let Some(&existing_offset) = dedup_map.get(&content_hash) {
            change_ref.resolve_to_offset(existing_offset);
            continue;
        }

        // Skip positions that are remapping keys to avoid collision with old offsets
        // that would be incorrectly remapped when heap patching is applied
        while result.remapping.contains_key(&(pos as u32)) {
            pos += 1;
        }

        let new_offset = u32::try_from(pos).map_err(|_| {
            crate::Error::LayoutFailed(format!("Heap position {} exceeds u32 range", pos))
        })?;
        let len_size = compressed_uint_size(final_blob.len());
        let entry_size = len_size + final_blob.len() as u64;

        if let Some(out) = output.as_mut() {
            let blob_len_u32 = u32::try_from(final_blob.len()).map_err(|_| {
                crate::Error::LayoutFailed(format!(
                    "Blob length {} exceeds u32 range",
                    final_blob.len()
                ))
            })?;
            let mut len_bytes = Vec::with_capacity(4);
            write_compressed_uint(blob_len_u32, &mut len_bytes);
            out.write_at(start_offset + pos, &len_bytes)?;
            out.write_at(start_offset + pos + len_bytes.len() as u64, final_blob)?;
        }

        pos += entry_size;
        dedup_map.insert(content_hash, new_offset);
        change_ref.resolve_to_offset(new_offset);
    }

    result.bytes_written = pos;
    Ok(result)
}

/// Streams the #GUID heap to output with deduplication and modifications.
///
/// GUID entries are fixed 16-byte values. Unlike other heaps, GUID indices are 1-based.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #GUID heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new index remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn stream_guid_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<[u8; 16]>,
) -> Result<StreamResult> {
    process_guid_heap(Some(output), start_offset, source_data, changes)
}

/// Pre-computes GUID heap indices and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// before method bodies are written.
///
/// # Arguments
///
/// * `source_data` - The original #GUID heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new index remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_guid_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<[u8; 16]>,
) -> Result<StreamResult> {
    process_guid_heap(None, 0, source_data, changes)
}

/// Unified GUID heap processor.
///
/// When `output` is `Some(output)`, writes to output at `start_offset`.
/// When `output` is `None`, only computes offsets (for pre-computation).
fn process_guid_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<[u8; 16]>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();
    let mut pos: u64 = 0;

    // If this is a raw heap replacement with no modifications or appends,
    // write the source data directly. This is needed for tests that create
    // intentionally malformed heaps that won't parse correctly.
    if changes.has_replacement()
        && changes.additions_count() == 0
        && changes.modifications_count() == 0
        && changes.removals_count() == 0
    {
        if let Some(out) = output.as_mut() {
            out.write_at(start_offset, source_data)?;
        }
        result.bytes_written = source_data.len() as u64;
        return Ok(result);
    }

    // Track content → new_index for deduplication (1-based indices)
    let mut dedup_map: FxHashMap<[u8; 16], u32> = FxHashMap::default();
    let mut current_index: u32 = 1;

    if let Ok(guids) = Guid::from(source_data) {
        for (old_index, guid) in guids.iter() {
            let old_index_u32 = u32::try_from(old_index).map_err(|_| {
                crate::Error::LayoutFailed(format!("GUID index {} exceeds u32 range", old_index))
            })?;

            // For GUIDs, changes use byte offset = (index - 1) * 16
            let byte_offset = (old_index_u32.saturating_sub(1)) * 16;

            // Check if deleted
            if changes.is_removed(byte_offset) {
                continue;
            }

            // Check if modified
            let final_guid: [u8; 16] = changes
                .get_modification(byte_offset)
                .copied()
                .unwrap_or_else(|| guid.to_bytes());

            // Deduplicate by content
            if let Some(&existing_index) = dedup_map.get(&final_guid) {
                // Only add to remapping if the index actually changed
                if old_index_u32 != existing_index {
                    result.remapping.insert(old_index_u32, existing_index);
                }
                continue;
            }

            // Write if in write mode
            if let Some(out) = output.as_mut() {
                out.write_at(start_offset + pos, &final_guid)?;
            }
            pos += 16;

            dedup_map.insert(final_guid, current_index);
            // Only add to remapping if the index actually changed
            if old_index_u32 != current_index {
                result.remapping.insert(old_index_u32, current_index);
            }
            current_index += 1;
        }
    }

    // Append new GUIDs from changes
    for (new_guid, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        // Check if this appended GUID was modified (update after add)
        let placeholder = change_ref.placeholder();
        let final_guid = changes.get_modification(placeholder).unwrap_or(new_guid);

        if let Some(&existing_index) = dedup_map.get(final_guid) {
            change_ref.resolve_to_offset(existing_index);
            continue;
        }

        if let Some(out) = output.as_mut() {
            out.write_at(start_offset + pos, final_guid)?;
        }
        pos += 16;

        dedup_map.insert(*final_guid, current_index);
        change_ref.resolve_to_offset(current_index);
        current_index += 1;
    }

    result.bytes_written = pos;
    Ok(result)
}

// =============================================================================
// UserString Heap
// =============================================================================

/// Streams the #US (user strings) heap to output with deduplication and modifications.
///
/// User strings are stored in UTF-16 format with a trailing flag byte. They are
/// referenced by `ldstr` IL instructions.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #US heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn stream_userstring_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
) -> Result<StreamResult> {
    process_userstring_heap(Some(output), start_offset, source_data, changes)
}

/// Pre-computes userstring heap offsets and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// for `ldstr` instructions before method bodies are written.
///
/// # Arguments
///
/// * `source_data` - The original #US heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_userstring_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<String>,
) -> Result<StreamResult> {
    process_userstring_heap(None, 0, source_data, changes)
}

/// Unified userstring heap processor.
///
/// When `output` is `Some(output)`, writes to output at `start_offset`.
/// When `output` is `None`, only computes offsets (for pre-computation).
fn process_userstring_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();

    // If this is a raw heap replacement with no modifications or appends,
    // write the source data directly. This is needed for tests that create
    // intentionally malformed heaps that won't parse correctly.
    if changes.has_replacement()
        && changes.additions_count() == 0
        && changes.modifications_count() == 0
        && changes.removals_count() == 0
    {
        if let Some(out) = output.as_mut() {
            out.write_at(start_offset, source_data)?;
        }
        result.bytes_written = source_data.len() as u64;
        return Ok(result);
    }

    let mut pos: u64 = 1; // Start after null byte

    // Track content → new_offset for deduplication
    let mut dedup_map: FxHashMap<u64, u32> = FxHashMap::default();
    dedup_map.insert(hash_string(""), 0);

    // Write null byte if in write mode
    if let Some(out) = output.as_mut() {
        out.write_at(start_offset, &[0u8])?;
    }

    if let Ok(userstrings) = UserStrings::from(source_data) {
        for (old_offset, original_str) in userstrings.iter() {
            let old_offset_u32 = u32::try_from(old_offset).map_err(|_| {
                crate::Error::LayoutFailed(format!(
                    "UserString offset {} exceeds u32 range",
                    old_offset
                ))
            })?;

            if changes.is_removed(old_offset_u32) {
                continue;
            }

            // Convert U16Str to UTF-8 for comparison
            let original_utf8 = original_str.to_string_lossy();
            let final_str = changes
                .get_modification(old_offset_u32)
                .map_or(original_utf8.as_ref(), |s| s.as_str());

            let content_hash = hash_string(final_str);
            if let Some(&existing_offset) = dedup_map.get(&content_hash) {
                // Only add to remapping if the offset actually changed
                if old_offset_u32 != existing_offset {
                    result.remapping.insert(old_offset_u32, existing_offset);
                }
                continue;
            }

            let new_offset = u32::try_from(pos).map_err(|_| {
                crate::Error::LayoutFailed(format!("Heap position {} exceeds u32 range", pos))
            })?;
            let entry_size = userstring_entry_size(final_str);

            // Write if in write mode
            if let Some(out) = output.as_mut() {
                write_userstring_entry(out, start_offset + pos, final_str)?;
            }

            pos += entry_size;
            dedup_map.insert(content_hash, new_offset);
            // Only add to remapping if the offset actually changed
            if old_offset_u32 != new_offset {
                result.remapping.insert(old_offset_u32, new_offset);
            }
        }
    }

    // Process appended userstrings
    for (new_string, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        let placeholder = change_ref.placeholder();
        let final_str = changes
            .get_modification(placeholder)
            .map_or(new_string.as_str(), |s| s.as_str());

        let content_hash = hash_string(final_str);
        if let Some(&existing_offset) = dedup_map.get(&content_hash) {
            change_ref.resolve_to_offset(existing_offset);
            continue;
        }

        let new_offset = u32::try_from(pos).map_err(|_| {
            crate::Error::LayoutFailed(format!("Heap position {} exceeds u32 range", pos))
        })?;
        let entry_size = userstring_entry_size(final_str);

        if let Some(out) = output.as_mut() {
            write_userstring_entry(out, start_offset + pos, final_str)?;
        }

        pos += entry_size;
        dedup_map.insert(content_hash, new_offset);
        change_ref.resolve_to_offset(new_offset);
    }

    result.bytes_written = pos;
    Ok(result)
}

/// Calculates the size of a userstring entry without writing.
fn userstring_entry_size(s: &str) -> u64 {
    let utf16_len = s.encode_utf16().count() * 2;
    let total_len = utf16_len + 1; // +1 for terminal byte
    compressed_uint_size(total_len) + total_len as u64
}

/// Writes a single user string entry to output.
///
/// Format: compressed_length + UTF-16LE bytes + terminal byte
fn write_userstring_entry(output: &mut Output, pos: u64, s: &str) -> Result<()> {
    let utf16_bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let total_len = utf16_bytes.len() + 1;

    // Write compressed length
    let total_len_u32 = u32::try_from(total_len).map_err(|_| {
        crate::Error::LayoutFailed(format!("UserString length {} exceeds u32 range", total_len))
    })?;
    let mut len_bytes = Vec::with_capacity(4);
    write_compressed_uint(total_len_u32, &mut len_bytes);
    output.write_at(pos, &len_bytes)?;

    // Write UTF-16LE bytes
    output.write_at(pos + len_bytes.len() as u64, &utf16_bytes)?;

    // Write terminal byte (0x01 if any byte has high bit set, 0x00 otherwise)
    let terminal = u8::from(utf16_bytes.iter().any(|&b| b & 0x80 != 0));
    output.write_at(
        pos + len_bytes.len() as u64 + utf16_bytes.len() as u64,
        &[terminal],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_stream_strings_heap_empty() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut output = Output::create(temp_file.path(), 4096).unwrap();

        let changes = HeapChanges::<String>::new_strings();
        let empty_refs = HashSet::new();
        let result = stream_strings_heap(&mut output, 0, &[0u8], &changes, &empty_refs).unwrap();

        assert_eq!(result.bytes_written, 1); // Just null byte
        assert!(result.remapping.is_empty());
    }

    #[test]
    fn test_stream_strings_heap_with_source() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut output = Output::create(temp_file.path(), 4096).unwrap();

        // Source heap: null + "Hello" + "World"
        let source = [
            0x00, // null
            b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 1
            b'W', b'o', b'r', b'l', b'd', 0x00, // "World" at offset 7
        ];

        let changes = HeapChanges::<String>::new_strings();
        let empty_refs = HashSet::new();
        let result = stream_strings_heap(&mut output, 0, &source, &changes, &empty_refs).unwrap();

        // Should write: null + Hello\0 + World\0 = 1 + 6 + 6 = 13
        assert_eq!(result.bytes_written, 13);
    }

    #[test]
    fn test_stream_strings_heap_deduplication() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut output = Output::create(temp_file.path(), 4096).unwrap();

        // Source heap with duplicate: null + "Hello" + "Hello"
        let source = [
            0x00, b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 1
            b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 7 (duplicate)
        ];

        let changes = HeapChanges::<String>::new_strings();
        let empty_refs = HashSet::new();
        let result = stream_strings_heap(&mut output, 0, &source, &changes, &empty_refs).unwrap();

        // Should write only one "Hello": null + Hello\0 = 1 + 6 = 7
        assert_eq!(result.bytes_written, 7);
        // Second occurrence should remap to first
        assert_eq!(result.remapping.get(&7), Some(&1));
    }
}
