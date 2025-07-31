//! Method body writing for the .NET assembly binary generation pipeline.
//!
//! This module provides method body writing capabilities for newly created methods
//! during assembly modification. It handles writing method bodies to a dedicated code
//! section and resolving placeholder RVAs to actual RVAs in the generated binary.
//!
//! # Key Components
//!
//! - [`MethodBodyWriter`] - Main writer for method body serialization and RVA resolution
//! - [`MethodBodyPlacement`] - Planning structure for method body placement in the binary
//! - [`RvaResolutionMap`] - Mapping from placeholder RVAs to actual RVAs
//!
//! # Architecture
//!
//! The method body writing system follows these principles:
//!
//! ## Code Section Allocation
//! Method bodies are written to a dedicated code section (typically .text):
//! - Calculates total space needed for all method bodies
//! - Finds available space in existing code sections or extends them
//! - Maintains proper alignment for method body headers
//! - Preserves existing code section content
//!
//! ## RVA Resolution
//! Placeholder RVAs (0xF0000000+) are resolved to actual code section RVAs:
//! - Maintains a mapping from placeholder RVAs to actual RVAs
//! - Updates method table entries that reference the placeholder RVAs
//! - Ensures all cross-references are consistently updated
//!
//! ## ECMA-335 Compliance
//! Ensures all method bodies conform to the ECMA-335 specification:
//! - Preserves method header format (tiny vs fat)
//! - Maintains proper exception handler layout
//! - Ensures correct alignment and padding
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::method_body::MethodBodyWriter;
//!
//! // Create method body writer
//! let mut writer = MethodBodyWriter::new(assembly, output, layout_plan)?;
//!
//! // Write all method bodies and get RVA resolution map
//! let rva_map = writer.write_all_method_bodies()?;
//!
//! // Apply RVA resolution to metadata tables
//! writer.apply_rva_resolution(&rva_map)?;
//! ```

use std::collections::HashMap;

use crate::{
    cilassembly::{
        write::{output::Output, planner::LayoutPlan},
        CilAssembly,
    },
    Error, Result,
};

/// Writer for method body serialization and RVA resolution.
///
/// This writer handles the complete method body writing process including:
/// - Writing method bodies to the code section
/// - Resolving placeholder RVAs to actual RVAs
/// - Updating metadata table references
pub struct MethodBodyWriter<'a> {
    /// Reference to the assembly containing method bodies
    assembly: &'a CilAssembly,
    /// Output buffer for writing method bodies
    output: &'a mut Output,
    /// Layout plan with section information
    layout_plan: &'a LayoutPlan,
    /// Current code section write position
    current_code_offset: u64,
    /// Map from placeholder RVAs to actual RVAs
    rva_resolution_map: HashMap<u32, u32>,
}

/// Planning information for method body placement in the binary.
#[derive(Debug, Clone)]
pub struct MethodBodyPlacement {
    /// RVA where method bodies will be written
    pub code_section_rva: u32,
    /// File offset where method bodies will be written
    pub code_section_offset: u64,
    /// Total space needed for all method bodies
    pub total_space_needed: u64,
}

/// Mapping from placeholder RVAs to actual RVAs after method body writing.
pub type RvaResolutionMap = HashMap<u32, u32>;

impl<'a> MethodBodyWriter<'a> {
    /// Creates a new method body writer.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly containing method bodies to write
    /// * `output` - Output buffer for binary generation
    /// * `layout_plan` - Layout plan with section information
    ///
    /// # Returns
    ///
    /// Returns a configured method body writer ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if the code section cannot be found or configured.
    pub fn new(
        assembly: &'a CilAssembly,
        output: &'a mut Output,
        layout_plan: &'a LayoutPlan,
    ) -> Result<Self> {
        // Find the code section where method bodies will be written
        let placement = Self::plan_method_body_placement(assembly, layout_plan)?;

        Ok(Self {
            assembly,
            output,
            layout_plan,
            current_code_offset: placement.code_section_offset,
            rva_resolution_map: HashMap::new(),
        })
    }

    /// Plans where method bodies will be placed in the binary.
    ///
    /// This method analyzes the layout plan to find appropriate space for method bodies,
    /// typically in the .text section or another executable section.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly containing method bodies
    /// * `layout_plan` - Layout plan with section information
    ///
    /// # Returns
    ///
    /// Returns placement information for method body writing.
    ///
    /// # Errors
    ///
    /// Returns an error if no suitable code section can be found.
    fn plan_method_body_placement(
        assembly: &CilAssembly,
        layout_plan: &LayoutPlan,
    ) -> Result<MethodBodyPlacement> {
        let changes = assembly.changes();

        // Calculate total space needed for all method bodies
        let total_space_needed = changes.method_bodies_total_size() as u64;
        if total_space_needed == 0 {
            // No method bodies to write
            return Ok(MethodBodyPlacement {
                code_section_rva: 0,
                code_section_offset: 0,
                total_space_needed: 0,
            });
        }

        // Find a suitable code section (typically .text)
        let code_section = layout_plan
            .file_layout
            .sections
            .iter()
            .find(|section| {
                // Look for executable sections, typically named .text
                section.name == ".text" || section.characteristics & 0x20000000 != 0
                // IMAGE_SCN_MEM_EXECUTE
            })
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No executable code section found for method body placement".to_string(),
            })?;

        // Calculate where to place method bodies in the code section
        // Place them at the end of the original virtual content
        let section_file_start = code_section.file_region.offset;

        // Calculate RVA based on placing method bodies at the end of the original virtual content
        // The layout planner has extended the virtual size to accommodate method bodies,
        // so we need to place them at the end of the original content
        let original_virtual_size = u64::from(code_section.virtual_size) - total_space_needed;
        let offset_within_section = original_virtual_size;
        let method_body_file_offset = section_file_start + original_virtual_size;

        let code_section_rva = code_section.virtual_address
            + u32::try_from(offset_within_section).map_err(|_| Error::WriteLayoutFailed {
                message: "Method body offset within section exceeds u32 range".to_string(),
            })?;

        // Align to 4-byte boundary for method bodies
        let aligned_rva = (code_section_rva + 3) & !3;

        Ok(MethodBodyPlacement {
            code_section_rva: aligned_rva,
            code_section_offset: method_body_file_offset,
            total_space_needed,
        })
    }

    /// Writes all method bodies to the code section and builds RVA resolution map.
    ///
    /// This method iterates through all stored method bodies, writes them to the
    /// code section, and builds a mapping from placeholder RVAs to actual RVAs.
    ///
    /// # Returns
    ///
    /// Returns the RVA resolution map for updating metadata table references.
    ///
    /// # Errors
    ///
    /// Returns an error if method body writing fails or RVA calculation fails.
    pub fn write_all_method_bodies(&mut self) -> Result<RvaResolutionMap> {
        let changes = self.assembly.changes();
        let placement = Self::plan_method_body_placement(self.assembly, self.layout_plan)?;

        if placement.total_space_needed == 0 {
            // No method bodies to write
            return Ok(HashMap::new());
        }

        let mut current_rva = placement.code_section_rva;
        let mut current_offset = placement.code_section_offset;

        // Write each method body and map its placeholder RVA to actual RVA
        for (placeholder_rva, method_body_bytes) in changes.method_bodies() {
            // Write the method body to the current offset
            self.output.write_at(current_offset, method_body_bytes)?;

            // Map placeholder RVA to actual RVA
            self.rva_resolution_map.insert(placeholder_rva, current_rva);

            // Advance to next method body position with proper alignment
            let method_body_size = method_body_bytes.len() as u64;
            let aligned_size = (method_body_size + 3) & !3; // 4-byte align

            current_offset += aligned_size;
            current_rva += u32::try_from(aligned_size).map_err(|_| Error::WriteLayoutFailed {
                message: "Method body size exceeds u32 range".to_string(),
            })?;
        }

        Ok(self.rva_resolution_map.clone())
    }

    /// Applies RVA resolution to update metadata table references.
    ///
    /// This method updates any metadata table entries that reference the
    /// placeholder RVAs, replacing them with the actual RVAs where the
    /// method bodies were written.
    ///
    /// # Arguments
    ///
    /// * `rva_map` - Map from placeholder RVAs to actual RVAs
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if all references were successfully updated.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata table updates fail.
    pub fn apply_rva_resolution(&mut self, _rva_map: &RvaResolutionMap) -> Result<()> {
        // TODO: Implement metadata table reference updates
        // This would need to scan through modified metadata tables and update
        // any RVA fields that contain placeholder RVAs

        // For now, this is a placeholder - the actual implementation would need
        // to coordinate with the table writer to update method table entries
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn test_method_body_placement_planning() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let mut assembly = view.to_owned();

        // Create a basic layout plan (this would normally be created by the planner)
        let layout_plan = crate::cilassembly::write::planner::LayoutPlan::create(&mut assembly)
            .expect("Failed to create layout plan");

        // Test placement planning
        let result = MethodBodyWriter::plan_method_body_placement(&assembly, &layout_plan);

        // For an assembly with no method bodies, this should succeed with zero space needed
        assert!(
            result.is_ok(),
            "Method body placement planning should succeed"
        );

        let placement = result.unwrap();
        assert_eq!(
            placement.total_space_needed, 0,
            "Should need zero space for no method bodies"
        );
    }

    #[test]
    fn test_method_body_writer_creation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let mut assembly = view.to_owned();

        let layout_plan = crate::cilassembly::write::planner::LayoutPlan::create(&mut assembly)
            .expect("Failed to create layout plan");

        // Create temporary output file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = Output::create(temp_file.path(), 1000).expect("Failed to create output");

        // Test writer creation
        let result = MethodBodyWriter::new(&assembly, &mut output, &layout_plan);
        assert!(result.is_ok(), "Method body writer creation should succeed");
    }
}
