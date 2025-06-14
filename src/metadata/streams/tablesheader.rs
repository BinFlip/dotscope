use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::{
    file::io::read_le,
    metadata::tables::{
        AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
        AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, ConstantRaw, CustomAttributeRaw,
        DeclSecurityRaw, EventMapRaw, EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw,
        FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw,
        GenericParamRaw, ImplMapRaw, InterfaceImplRaw, ManifestResourceRaw, MemberRefRaw,
        MetadataTable, MethodDefRaw, MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw,
        MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw, ParamPtrRaw, ParamRaw,
        PropertyMapRaw, PropertyPtrRaw, PropertyRaw, RowDefinition, StandAloneSigRaw, TableData,
        TableId, TableInfo, TableInfoRef, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
    Error::OutOfBounds,
    Result,
};

/// The `TablesHeader` structure represents the header in the '#~' stream. '#~' which contains all the metadata used
/// for reflection and execution of the CIL binary.
///
/// This structure provides efficient access to metadata tables, allowing reference-based parsing and traversal
/// of .NET assemblies without loading the entire metadata into memory at once.
///
/// ## Efficient Table Access Examples
///
/// ### Basic Table Access
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw, FieldRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Check if a table is present before accessing it
/// if tables_header.has_table(TableId::TypeDef) {
///     // Get efficient access to the TypeDef table
///     if let Some(typedef_table) = tables_header.table::<TypeDefRaw>(TableId::TypeDef) {
///         println!("TypeDef table has {} rows", typedef_table.row_count());
///         
///         // Access individual rows by index (0-based)
///         if let Some(first_type) = typedef_table.get(0) {
///             println!("First type: flags={}, name_idx={}, namespace_idx={}",
///                     first_type.flags, first_type.type_name, first_type.type_namespace);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Iterating Over Table Rows
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MethodDefRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Iterate over all methods in the assembly
/// if let Some(method_table) = tables_header.table::<MethodDefRaw>(TableId::MethodDef) {
///     for (index, method) in method_table.iter().enumerate() {
///         println!("Method {}: RVA={:#x}, impl_flags={}, flags={}, name_idx={}",
///                 index, method.rva, method.impl_flags, method.flags, method.name);
///         
///         // Break after first 10 for demonstration
///         if index >= 9 { break; }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Parallel Processing with Rayon
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, FieldRaw}};
/// use rayon::prelude::*;
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Process field metadata in parallel
/// if let Some(field_table) = tables_header.table::<FieldRaw>(TableId::Field) {
///     let field_count = field_table.par_iter()
///         .filter(|field| field.flags & 0x0010 != 0) // FieldAttributes.Static
///         .count();
///     
///     println!("Found {} static fields", field_count);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Cross-Table Analysis
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Analyze types and their methods together
/// if let (Some(typedef_table), Some(method_table)) = (
///     tables_header.table::<TypeDefRaw>(TableId::TypeDef),
///     tables_header.table::<MethodDefRaw>(TableId::MethodDef)
/// ) {
///     for (type_idx, type_def) in typedef_table.iter().enumerate().take(5) {
///         println!("Type {}: methods {}-{}",
///                 type_idx, type_def.method_list,
///                 type_def.method_list.saturating_add(10)); // Simplified example
///         
///         // In real usage, you'd calculate the actual method range
///         // by looking at the next type's method_list or using table bounds
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Working with Table Summaries
/// ```rust,no_run
/// use dotscope::metadata::streams::TablesHeader;
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Get overview of all present tables
/// let summaries = tables_header.table_summary();
///
/// for summary in summaries {
///     println!("Table {:?}: {} rows", summary.table_id, summary.row_count);
/// }
///
/// // Check for specific tables by ID
/// if tables_header.has_table_by_id(0x02) { // TypeDef table ID
///     println!("TypeDef table is present");
/// }
///
/// println!("Total metadata tables: {}", tables_header.table_count());
/// # Ok(())
/// # }
/// ```
///
/// ### Memory-Efficient Pattern
/// ```rust,no_run
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Process large tables without loading all data at once
/// if let Some(ca_table) = tables_header.table::<CustomAttributeRaw>(TableId::CustomAttribute) {
///     println!("Processing {} custom attributes", ca_table.row_count());
///     
///     // Process in chunks to manage memory usage
///     const CHUNK_SIZE: u32 = 100;
///     let total_rows = ca_table.row_count();
///     
///     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
///         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
///         
///         for i in chunk_start..chunk_end {
///             if let Some(attr) = ca_table.get(i) {
///                 // Process individual custom attribute
///                 // attr.parent, attr.type_def, attr.value are available
///                 // without copying the entire table into memory
///             }
///         }
///         
///         // Optional: yield control or log progress
///         println!("Processed chunk {}-{}", chunk_start, chunk_end);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Performance Notes
///
/// - All table access uses reference-based parsing - no data is duplicated in memory
/// - Row access via `get()` and iteration is lazy - rows are parsed only when requested
/// - Parallel iteration with `par_iter()` can significantly speed up processing of large tables
/// - The lifetime parameter `'a` ensures memory safety by tying table references to the original data
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.6 && II.22
pub struct TablesHeader<'a> {
    /// Major version of table schemeta, shall be 2
    pub major_version: u8,
    /// Minor version of table schemata, shall be 0
    pub minor_version: u8,
    /// Bit vector of present tables, let n be the number of bits that are 1.
    pub valid: u64,
    /// Bit vector of sorted tables
    pub sorted: u64,
    /// Information about specific tables, e.g their row count, and their reference index sizes
    pub info: TableInfoRef,
    /// The offset of physical tables, relative to the `TablesHeader`
    tables_offset: usize,
    /// Reference to table data
    tables: Vec<Option<TableData<'a>>>,
}

/// Summary information for a metadata table
#[derive(Debug, Clone)]
pub struct TableSummary {
    pub table_id: TableId,
    pub row_count: u32,
}

impl<'a> TablesHeader<'a> {
    /// Create a `TablesHeader` object from a sequence of bytes
    ///
    /// # Arguments
    /// * 'data' - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the data is too short or if no valid table rows are found
    pub fn from(data: &'a [u8]) -> Result<TablesHeader<'a>> {
        if data.len() < 24 {
            return Err(OutOfBounds);
        }

        let valid_bitvec = read_le::<u64>(&data[8..])?;
        if valid_bitvec == 0 {
            return Err(malformed_error!("No valid rows in any of the tables"));
        }

        let mut tables_header = TablesHeader {
            major_version: read_le::<u8>(&data[4..])?,
            minor_version: read_le::<u8>(&data[5..])?,
            valid: valid_bitvec,
            sorted: read_le::<u64>(&data[16..])?,
            info: Arc::new(TableInfo::new(data, valid_bitvec)?),
            tables_offset: (24 + valid_bitvec.count_ones() * 4) as usize,
            tables: Vec::with_capacity(TableId::GenericParamConstraint as usize + 1),
        };

        // with_capacity has allocated the buffer, but we can't 'insert' elements, only push
        // to make the vector grow - as .insert doesn't adjust length, only push does.
        tables_header
            .tables
            .resize_with(TableId::GenericParamConstraint as usize + 1, || None);

        let mut current_offset = tables_header.tables_offset as usize;
        for table_id in TableId::iter() {
            if current_offset > data.len() {
                return Err(OutOfBounds);
            }

            tables_header.add_table(&data[current_offset..], table_id, &mut current_offset)?;
        }

        Ok(tables_header)
    }

    /// Get the table count
    #[must_use]
    pub fn table_count(&self) -> u32 {
        self.valid.count_ones()
    }

    /// Get a specific table for efficient access
    ///
    /// This method provides type-safe access to metadata tables without copying data.
    /// The returned table reference allows efficient iteration and random access to rows.
    ///
    /// ## Arguments
    /// * `table_id` - The type of table to lookup
    ///
    /// ## Returns
    /// * `Some(&MetadataTable<T>)` - Reference to the table if present
    /// * `None` - If the table is not present in this assembly
    ///
    /// ## Example
    /// ```rust,no_run
    /// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw}};
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// // Safe access with type checking
    /// if let Some(typedef_table) = tables.table::<TypeDefRaw>(TableId::TypeDef) {
    ///     // Efficient access to all type definitions
    ///     for type_def in typedef_table.iter().take(5) {
    ///         println!("Type: flags={:#x}, name_idx={}, namespace_idx={}",
    ///                 type_def.flags, type_def.type_name, type_def.type_namespace);
    ///     }
    ///     
    ///     // Random access to specific rows
    ///     if let Some(first_type) = typedef_table.get(0) {
    ///         println!("First type name index: {}", first_type.type_name);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Safety Note
    /// The generic type parameter `T` must match the table type for `table_id`.
    /// Using the wrong type will result in undefined behavior due to the internal cast.
    /// Always use the corresponding `*Raw` types:
    /// - `TableId::TypeDef` → `TypeDefRaw`
    /// - `TableId::MethodDef` → `MethodDefRaw`
    /// - `TableId::Field` → `FieldRaw`
    /// - etc.
    #[must_use]
    pub fn table<T: RowDefinition<'a>>(
        &self,
        table_id: TableId,
    ) -> Option<&'a MetadataTable<'a, T>> {
        match &self.tables.get(table_id as usize).unwrap_or(&None) {
            Some(t) => match t {
                TableData::Module(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::TypeRef(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::TypeDef(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::FieldPtr(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::Field(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::MethodPtr(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::MethodDef(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::ParamPtr(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::Param(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::InterfaceImpl(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::MemberRef(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::Constant(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::CustomAttribute(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::FieldMarshal(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::DeclSecurity(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::ClassLayout(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::FieldLayout(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::StandAloneSig(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::EventMap(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::EventPtr(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::Event(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::PropertyMap(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::PropertyPtr(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::Property(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::MethodSemantics(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::MethodImpl(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::ModuleRef(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::TypeSpec(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::ImplMap(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::FieldRVA(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::Assembly(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::AssemblyProcessor(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::AssemblyOS(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::AssemblyRef(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::AssemblyRefProcessor(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::AssemblyRefOS(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::File(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::ExportedType(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::ManifestResource(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::NestedClass(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::GenericParam(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::MethodSpec(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
                TableData::GenericParamConstraint(table) => unsafe {
                    Some(&*std::ptr::from_ref(table).cast::<MetadataTable<T>>())
                },
            },
            None => None,
        }
    }

    /// Add a table to the tables header
    // ToDo: table.size() needs a better fix than this.
    #[allow(clippy::cast_possible_truncation)]
    fn add_table(
        &mut self,
        data: &'a [u8],
        table_type: TableId,
        current_offset: &mut usize,
    ) -> Result<()> {
        let t_info = self.info.get(table_type);
        if t_info.rows == 0 {
            // We filtered out empty tables earlier, this case shouldn't happen here
            return Ok(());
        }

        let table = match table_type {
            TableId::Module => {
                let table = MetadataTable::<ModuleRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Module(table)
            }
            TableId::TypeRef => {
                let table = MetadataTable::<TypeRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::TypeRef(table)
            }
            TableId::TypeDef => {
                let table = MetadataTable::<TypeDefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::TypeDef(table)
            }
            TableId::FieldPtr => {
                let table =
                    MetadataTable::<FieldPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldPtr(table)
            }
            TableId::Field => {
                let table = MetadataTable::<FieldRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Field(table)
            }
            TableId::MethodPtr => {
                let table =
                    MetadataTable::<MethodPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodPtr(table)
            }
            TableId::MethodDef => {
                let table =
                    MetadataTable::<MethodDefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodDef(table)
            }
            TableId::ParamPtr => {
                let table =
                    MetadataTable::<ParamPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ParamPtr(table)
            }
            TableId::Param => {
                let table = MetadataTable::<ParamRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Param(table)
            }
            TableId::InterfaceImpl => {
                let table =
                    MetadataTable::<InterfaceImplRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::InterfaceImpl(table)
            }
            TableId::MemberRef => {
                let table =
                    MetadataTable::<MemberRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MemberRef(table)
            }
            TableId::Constant => {
                let table =
                    MetadataTable::<ConstantRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Constant(table)
            }
            TableId::CustomAttribute => {
                let table =
                    MetadataTable::<CustomAttributeRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::CustomAttribute(table)
            }
            TableId::FieldMarshal => {
                let table =
                    MetadataTable::<FieldMarshalRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldMarshal(table)
            }
            TableId::DeclSecurity => {
                let table =
                    MetadataTable::<DeclSecurityRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::DeclSecurity(table)
            }
            TableId::ClassLayout => {
                let table =
                    MetadataTable::<ClassLayoutRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ClassLayout(table)
            }
            TableId::FieldLayout => {
                let table =
                    MetadataTable::<FieldLayoutRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldLayout(table)
            }
            TableId::StandAloneSig => {
                let table =
                    MetadataTable::<StandAloneSigRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::StandAloneSig(table)
            }
            TableId::EventMap => {
                let table =
                    MetadataTable::<EventMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::EventMap(table)
            }
            TableId::EventPtr => {
                let table =
                    MetadataTable::<EventPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::EventPtr(table)
            }
            TableId::Event => {
                let table = MetadataTable::<EventRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Event(table)
            }
            TableId::PropertyMap => {
                let table =
                    MetadataTable::<PropertyMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::PropertyMap(table)
            }
            TableId::PropertyPtr => {
                let table =
                    MetadataTable::<PropertyPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::PropertyPtr(table)
            }
            TableId::Property => {
                let table =
                    MetadataTable::<PropertyRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Property(table)
            }
            TableId::MethodSemantics => {
                let table =
                    MetadataTable::<MethodSemanticsRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodSemantics(table)
            }
            TableId::MethodImpl => {
                let table =
                    MetadataTable::<MethodImplRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodImpl(table)
            }
            TableId::ModuleRef => {
                let table =
                    MetadataTable::<ModuleRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ModuleRef(table)
            }
            TableId::TypeSpec => {
                let table =
                    MetadataTable::<TypeSpecRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::TypeSpec(table)
            }
            TableId::ImplMap => {
                let table = MetadataTable::<ImplMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ImplMap(table)
            }
            TableId::FieldRVA => {
                let table =
                    MetadataTable::<FieldRvaRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldRVA(table)
            }
            TableId::Assembly => {
                let table =
                    MetadataTable::<AssemblyRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Assembly(table)
            }
            TableId::AssemblyProcessor => {
                let table = MetadataTable::<AssemblyProcessorRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::AssemblyProcessor(table)
            }
            TableId::AssemblyOS => {
                let table =
                    MetadataTable::<AssemblyOsRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::AssemblyOS(table)
            }
            TableId::AssemblyRef => {
                let table =
                    MetadataTable::<AssemblyRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::AssemblyRef(table)
            }
            TableId::AssemblyRefProcessor => {
                let table = MetadataTable::<AssemblyRefProcessorRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::AssemblyRefProcessor(table)
            }
            TableId::AssemblyRefOS => {
                let table =
                    MetadataTable::<AssemblyRefOsRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::AssemblyRefOS(table)
            }
            TableId::File => {
                let table = MetadataTable::<FileRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::File(table)
            }
            TableId::ExportedType => {
                let table =
                    MetadataTable::<ExportedTypeRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ExportedType(table)
            }
            TableId::ManifestResource => {
                let table = MetadataTable::<ManifestResourceRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::ManifestResource(table)
            }
            TableId::NestedClass => {
                let table =
                    MetadataTable::<NestedClassRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::NestedClass(table)
            }
            TableId::GenericParam => {
                let table =
                    MetadataTable::<GenericParamRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::GenericParam(table)
            }
            TableId::MethodSpec => {
                let table =
                    MetadataTable::<MethodSpecRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodSpec(table)
            }
            TableId::GenericParamConstraint => {
                let table = MetadataTable::<GenericParamConstraintRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::GenericParamConstraint(table)
            }
        };

        self.tables.insert(table_type as usize, Some(table));
        Ok(())
    }

    /// Check if a specific table is present
    ///
    /// Use this method to safely check for table presence before accessing it.
    /// This avoids potential panics when working with assemblies that may not
    /// contain all possible metadata tables.
    ///
    /// ## Arguments
    /// * `table_id` - The table ID to check for presence
    ///
    /// ## Example
    /// ```rust,no_run
    /// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, EventRaw}};
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// // Safe pattern: check before access
    /// if tables.has_table(TableId::Event) {
    ///     if let Some(event_table) = tables.table::<EventRaw>(TableId::Event) {
    ///         println!("Assembly has {} events", event_table.row_count());
    ///     }
    /// } else {
    ///     println!("No events defined in this assembly");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn has_table(&self, table_id: TableId) -> bool {
        (self.valid & (1u64 << (table_id as u8))) != 0
    }

    /// Check if a table is present by its numeric ID
    ///
    /// This method provides a way to check for table presence using the raw
    /// numeric table identifiers (0-63) as defined in the ECMA-335 specification.
    ///
    /// ## Arguments
    /// * `table_id` - The numeric table ID (0-63) to check for presence
    ///
    /// ## Returns
    /// * `true` - If the table is present
    /// * `false` - If the table is not present or `table_id` > 63
    ///
    /// ## Example
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// // Check for specific tables by their numeric IDs
    /// if tables.has_table_by_id(0x02) { // TypeDef
    ///     println!("TypeDef table present");
    /// }
    /// if tables.has_table_by_id(0x06) { // MethodDef  
    ///     println!("MethodDef table present");
    /// }
    /// if tables.has_table_by_id(0x04) { // Field
    ///     println!("Field table present");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn has_table_by_id(&self, table_id: u8) -> bool {
        if table_id > 63 {
            return false;
        }
        (self.valid & (1u64 << table_id)) != 0
    }

    /// Get an iterator over all present tables
    ///
    /// This method returns an iterator that yields `TableId` values for all tables
    /// that are present in this assembly's metadata. Useful for discovering what
    /// metadata is available without having to check each table individually.
    ///
    /// ## Example
    /// ```rust,no_run
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// println!("Present metadata tables:");
    /// for table_id in tables.present_tables() {
    ///     let row_count = tables.table_row_count(table_id);
    ///     println!("  {:?}: {} rows", table_id, row_count);
    /// }
    /// # }
    /// ```
    pub fn present_tables(&self) -> impl Iterator<Item = TableId> + '_ {
        TableId::iter().filter(|&table_id| self.has_table(table_id))
    }

    /// Get the row count for a specific table
    ///
    /// Returns the number of rows in the specified table. This information
    /// is available even if you don't access the table data itself.
    ///
    /// ## Arguments
    /// * `table_id` - The table to get the row count for
    ///
    /// ## Returns
    /// * Row count (0 if table is not present)
    ///
    /// ## Example
    /// ```rust,no_run
    /// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
    ///
    /// # fn example(tables: &TablesHeader) {
    /// let type_count = tables.table_row_count(TableId::TypeDef);
    /// let method_count = tables.table_row_count(TableId::MethodDef);
    /// let field_count = tables.table_row_count(TableId::Field);
    ///
    /// println!("Assembly contains:");
    /// println!("  {} types", type_count);
    /// println!("  {} methods", method_count);
    /// println!("  {} fields", field_count);
    /// # }
    /// ```
    #[must_use]
    pub fn table_row_count(&self, table_id: TableId) -> u32 {
        self.info.get(table_id).rows
    }

    /// Get a summary of all present tables with their row counts
    #[must_use]
    pub fn table_summary(&self) -> Vec<TableSummary> {
        self.present_tables()
            .map(|table_id| TableSummary {
                table_id,
                row_count: self.table_row_count(table_id),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::verify_tableheader;

    #[test]
    fn wb_stream_0() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data).unwrap();

        verify_tableheader(&header);
    }
}
