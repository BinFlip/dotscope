//! Layout plan orchestration and coordination for binary generation.
//!
//! This module provides the [`LayoutPlan`] type and related functionality for
//! coordinating the complete layout planning process. LayoutPlan serves as the
//! central coordinator that brings together all aspects of layout planning.
//!
//! # Architecture
//!
//! LayoutPlan implements a type-driven approach where the plan itself provides
//! methods for creation, analysis, and coordination rather than relying on
//! external functions.

use crate::{
    cilassembly::{
        write::planner::{
            layout::FileLayout, memory::calculate_total_size_from_layout,
            metadata::identify_metadata_modifications, tables, updates, HeapExpansions,
            MetadataModifications, NativeTableRequirements, PeUpdates, TableModificationRegion,
        },
        CilAssembly,
    },
    metadata::tables::TableId,
    Result,
};

/// Layout plan for section-by-section copy with proper relocations.
///
/// This comprehensive plan contains all information needed for binary generation,
/// including file structure calculations, PE header updates, and metadata modifications.
/// It serves as the complete blueprint for transforming a modified assembly into
/// a valid binary file.
///
/// # Type-Driven API
/// Instead of using static `create_layout_plan()` functions, LayoutPlan provides
/// a `create()` method that encapsulates the planning process and makes the API
/// more discoverable and intuitive.
///
/// # Structure
/// The plan calculates the complete new file structure including:
/// - PE section relocations when metadata grows
/// - New stream offsets after section relocation
/// - Updated metadata root structure
/// - Complete file layout from start to finish
/// - All required PE header modifications
///
/// # Examples
/// ```rust,ignore
/// use crate::cilassembly::write::planner::layout::LayoutPlan;
/// use crate::cilassembly::CilAssembly;
///
/// # let assembly = CilAssembly::empty(); // placeholder
/// // Create a complete layout plan using type-driven API
/// let layout_plan = LayoutPlan::create(&assembly)?;
///
/// // Access components with rich methods
/// let tables_offset = layout_plan.tables_stream_offset(&assembly)?;
/// let metadata_section = layout_plan.file_layout.find_metadata_section()?;
///
/// // Check what updates are needed
/// if layout_plan.pe_updates.section_table_needs_update {
///     println!("PE section table needs updating");
/// }
/// # Ok::<(), crate::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct LayoutPlan {
    /// Total size needed for the output file in bytes.
    /// Calculated from the complete file layout including all expansions.
    pub total_size: u64,

    /// Size of the original file in bytes.
    /// Used for comparison and validation purposes.
    pub original_size: u64,

    /// Complete file layout plan with section placements.
    /// Contains detailed structure of the entire output file.
    pub file_layout: FileLayout,

    /// PE structure updates needed for header modifications.
    /// Specifies what changes are required in PE headers and section table.
    pub pe_updates: PeUpdates,

    /// Metadata modifications that need to be applied.
    /// Contains detailed information about metadata root and stream changes.
    pub metadata_modifications: MetadataModifications,

    /// Heap expansion information with calculated sizes.
    /// Provides size calculations for all metadata heap additions.
    pub heap_expansions: HeapExpansions,

    /// Table modification regions requiring updates.
    /// Contains information about modified metadata tables.
    pub table_modifications: Vec<TableModificationRegion>,

    /// Native PE table requirements for import/export table generation.
    /// Contains space allocation and placement information for native PE tables.
    pub native_table_requirements: NativeTableRequirements,
}

impl LayoutPlan {
    /// Creates a layout plan for copy-with-modifications approach.
    ///
    /// This function performs comprehensive analysis of assembly changes and creates
    /// a complete layout plan for binary generation. It calculates all required
    /// modifications, expansions, and relocations needed to produce a valid output file.
    ///
    /// # Arguments
    /// * `assembly` - The assembly containing modifications to analyze
    ///
    /// # Returns
    /// Returns a complete layout plan with all layout information.
    ///
    /// # Errors
    /// Returns an error if layout planning fails due to invalid assembly structure
    /// or calculation errors.
    ///
    /// # Process
    /// 1. Analyzes heap expansions and metadata modifications
    /// 2. Calculates section relocations and size changes
    /// 3. Determines PE header updates required
    /// 4. Creates complete file layout with proper alignment
    ///
    /// # Examples
    /// ```rust,ignore
    /// let layout_plan = LayoutPlan::create(&assembly)?;
    /// println!("Total size: {} bytes", layout_plan.total_size);
    /// ```
    pub fn create(assembly: &CilAssembly) -> Result<Self> {
        // Get the original file size from the assembly view
        let original_size = assembly.file().file_size();

        // Calculate heap expansions needed
        let heap_expansions = HeapExpansions::calculate(assembly)?;

        // Identify metadata modifications needed
        let mut metadata_modifications = identify_metadata_modifications(assembly)?;

        // Identify table modification regions
        let table_modifications = tables::identify_table_modifications(assembly)?;

        // Calculate native PE table requirements
        let native_table_requirements = tables::calculate_native_table_requirements(assembly)?;

        // Calculate complete file layout with proper section placement
        let mut file_layout =
            FileLayout::calculate(assembly, &heap_expansions, &mut metadata_modifications)?;

        // Update file layout to accommodate native table requirements
        updates::update_layout_for_native_tables(&mut file_layout, &native_table_requirements)?;

        // Determine PE updates needed
        let pe_updates = updates::calculate_pe_updates(assembly, &file_layout)?;

        // Calculate total size based on file layout and native table requirements
        let total_size =
            calculate_total_size_from_layout(assembly, &file_layout, &native_table_requirements);

        Ok(LayoutPlan {
            total_size,
            original_size,
            file_layout,
            pe_updates,
            metadata_modifications,
            heap_expansions,
            table_modifications,
            native_table_requirements,
        })
    }

    /// Returns the absolute file offset where the tables stream (#~ or #-) begins.
    ///
    /// This method calculates the offset by:
    /// 1. Finding the section containing metadata in the layout plan
    /// 2. Locating the tables stream within the metadata streams
    /// 3. Returning the calculated file offset for the tables stream
    ///
    /// # Arguments
    /// * `assembly` - The assembly for additional context (currently unused)
    ///
    /// # Returns
    /// Returns the absolute file offset of the tables stream.
    ///
    /// # Errors
    /// Returns an error if the tables stream cannot be located.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let tables_offset = layout_plan.tables_stream_offset(&assembly)?;
    /// println!("Tables stream starts at offset: 0x{:X}", tables_offset);
    /// ```
    pub fn tables_stream_offset(&self, _assembly: &CilAssembly) -> Result<u64> {
        // Find the section containing metadata
        let metadata_section = self.file_layout.find_metadata_section()?;

        // Find the tables stream within the metadata section
        let tables_stream = metadata_section
            .metadata_streams
            .iter()
            .find(|stream| stream.name == "#~" || stream.name == "#-")
            .ok_or_else(|| crate::Error::WriteLayoutFailed {
                message: "Tables stream (#~ or #-) not found in metadata section".to_string(),
            })?;

        Ok(tables_stream.file_region.offset)
    }

    /// Checks if this layout plan requires any updates to the original file.
    ///
    /// This is useful for optimization - if no updates are needed, the file
    /// can potentially be copied as-is.
    ///
    /// # Returns
    /// Returns `true` if any updates are required.
    ///
    /// # Examples
    /// ```rust,ignore
    /// if layout_plan.requires_updates() {
    ///     println!("File needs modifications");
    /// } else {
    ///     println!("File can be copied as-is");
    /// }
    /// ```
    pub fn requires_updates(&self) -> bool {
        self.pe_updates.section_table_needs_update
            || self.pe_updates.checksum_needs_update
            || self.metadata_modifications.root_needs_update
            || !self.table_modifications.is_empty()
            || self.heap_expansions.requires_relocation()
            || self.native_table_requirements.needs_import_tables
            || self.native_table_requirements.needs_export_tables
    }

    /// Returns the size increase compared to the original file.
    ///
    /// # Returns
    /// Returns the number of bytes the output file will be larger than the input.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let increase = layout_plan.size_increase();
    /// if increase > 0 {
    ///     println!("File will grow by {} bytes", increase);
    /// }
    /// ```
    pub fn size_increase(&self) -> u64 {
        self.total_size.saturating_sub(self.original_size)
    }

    /// Returns a summary of the modifications planned.
    ///
    /// This is useful for logging and debugging to understand what changes
    /// will be applied to the assembly.
    ///
    /// # Returns
    /// Returns a formatted string with modification details.
    ///
    /// # Examples
    /// ```rust,ignore
    /// println!("Layout plan: {}", layout_plan.summary());
    /// ```
    pub fn summary(&self) -> String {
        let updates_needed = if self.requires_updates() { "Yes" } else { "No" };
        let size_change = if self.total_size > self.original_size {
            format!("+{} bytes", self.size_increase())
        } else if self.total_size < self.original_size {
            format!("-{} bytes", self.original_size - self.total_size)
        } else {
            "unchanged".to_string()
        };

        format!(
            "LayoutPlan: {} sections, size {} -> {} ({}), updates needed: {}",
            self.file_layout.sections.len(),
            self.original_size,
            self.total_size,
            size_change,
            updates_needed
        )
    }

    /// Returns the table modification for a specific table ID.
    ///
    /// # Arguments
    /// * `table_id` - The table ID to find modifications for
    ///
    /// # Returns
    /// Returns the table modification region if found.
    ///
    /// # Examples
    /// ```rust,ignore
    /// if let Some(modification) = layout_plan.find_table_modification(TableId::TypeDef) {
    ///     println!("TypeDef table will be modified");
    /// }
    /// ```
    pub fn find_table_modification(&self, table_id: TableId) -> Option<&TableModificationRegion> {
        self.table_modifications
            .iter()
            .find(|modification| modification.table_id == table_id)
    }

    /// Returns the names of all modified tables.
    ///
    /// # Returns
    /// Returns an iterator over the table IDs that will be modified.
    ///
    /// # Examples
    /// ```rust,ignore
    /// for table_id in layout_plan.modified_table_ids() {
    ///     println!("Table {:?} will be modified", table_id);
    /// }
    /// ```
    pub fn modified_table_ids(&self) -> impl Iterator<Item = TableId> + '_ {
        self.table_modifications
            .iter()
            .map(|modification| modification.table_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_layout_plan_create() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let result = LayoutPlan::create(&assembly);
        assert!(result.is_ok(), "Layout plan creation should succeed");

        let plan = result.unwrap();
        assert!(plan.original_size > 0, "Original size should be positive");
        assert!(
            plan.total_size > 0,
            "Total size should be positive. Got: total={}, original={}",
            plan.total_size,
            plan.original_size
        );
    }

    #[test]
    fn test_layout_plan_basic_properties() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout_plan = LayoutPlan::create(&assembly).expect("Failed to create layout plan");

        // Basic sanity checks
        assert!(
            layout_plan.total_size > 0,
            "Total size should be positive. Got: total={}, original={}",
            layout_plan.total_size,
            layout_plan.original_size
        );
        assert!(
            layout_plan.original_size > 0,
            "Original size should be positive"
        );
        assert!(
            !layout_plan.file_layout.sections.is_empty(),
            "Should have sections in file layout"
        );
    }

    #[test]
    fn test_tables_stream_offset() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout_plan = LayoutPlan::create(&assembly).expect("Failed to create layout plan");

        let tables_offset = layout_plan.tables_stream_offset(&assembly);
        assert!(
            tables_offset.is_ok(),
            "Should be able to find tables stream offset"
        );

        let offset = tables_offset.unwrap();
        assert!(offset > 0, "Tables stream offset should be positive");
    }
}
