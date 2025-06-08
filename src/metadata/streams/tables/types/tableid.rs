use strum::{EnumCount, EnumIter};

/// Identifiers for the different metadata tables defined in the ECMA-335 specification.
///
/// Each variant represents a specific type of metadata table that can be present in a .NET assembly.
/// The numeric values correspond to the table IDs as defined in the CLI specification.
///
/// ## Table Categories
///
/// ### Core Type System
/// - **`Module`**: Assembly module information
/// - **`TypeDef`**: Type definitions (classes, interfaces, enums, etc.)
/// - **`TypeRef`**: Type references to external assemblies
/// - **`Field`**: Field definitions within types
/// - **`MethodDef`**: Method definitions
/// - **`Param`**: Method parameter definitions
///
/// ### Type Relationships
/// - **`InterfaceImpl`**: Interface implementations by types
/// - **`NestedClass`**: Nested class relationships
/// - **`ClassLayout`**: Memory layout information for types
/// - **`FieldLayout`**: Field layout within types
///
/// ### Member References
/// - **`MemberRef`**: References to external members (methods, fields)
/// - **`MethodImpl`**: Method implementation mappings
/// - **`MethodSemantics`**: Property/event accessor mappings
///
/// ### Metadata and Attributes
/// - **`CustomAttribute`**: Custom attribute applications
/// - **`Constant`**: Compile-time constant values
/// - **`FieldMarshal`**: P/Invoke marshalling information
/// - **`DeclSecurity`**: Declarative security permissions
///
/// ### Signatures and Specifications
/// - **`StandAloneSig`**: Standalone method signatures
/// - **`TypeSpec`**: Generic type specifications
/// - **`MethodSpec`**: Generic method specifications
/// - **`GenericParam`**: Generic parameter definitions
/// - **`GenericParamConstraint`**: Generic parameter constraints
///
/// ### Events and Properties
/// - **`Event`**: Event definitions
/// - **`EventMap`**: Type-to-event mappings
/// - **`Property`**: Property definitions  
/// - **`PropertyMap`**: Type-to-property mappings
///
/// ### Assembly Information
/// - **`Assembly`**: Current assembly metadata
/// - **`AssemblyRef`**: External assembly references
/// - **`AssemblyProcessor`**: Processor-specific assembly info
/// - **`AssemblyOS`**: OS-specific assembly info
/// - **`AssemblyRefProcessor`**: External assembly processor info
/// - **`AssemblyRefOS`**: External assembly OS info
///
/// ### Files and Resources
/// - **`File`**: File references in the assembly
/// - **`ExportedType`**: Types exported from this assembly
/// - **`ManifestResource`**: Embedded or linked resources
///
/// ### Platform Interop
/// - **`ImplMap`**: P/Invoke implementation mappings
/// - **`FieldRVA`**: Field relative virtual addresses for initialized data
/// - **`ModuleRef`**: External module references
///
/// ## Reference
/// * [ECMA-335 Partition II, Section 22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata Tables
#[derive(Clone, Copy, PartialEq, Debug, EnumIter, EnumCount, Eq, Hash)]
pub enum TableId {
    /// `Module` table (0x00) - Contains information about the current module/assembly.
    ///
    /// Each assembly has exactly one Module row that describes the module itself,
    /// including its name, MVID (Module Version ID), and generation information.
    Module = 0x00,

    /// `TypeRef` table (0x01) - References to types defined in external assemblies.
    ///
    /// Contains references to types that are imported from other assemblies,
    /// including the type name, namespace, and resolution scope.
    TypeRef = 0x01,

    /// `TypeDef` table (0x02) - Definitions of types within this assembly.
    ///
    /// Contains all type definitions (classes, interfaces, enums, delegates, etc.)
    /// defined within this assembly, including their flags, name, namespace,
    /// base type, and member lists.
    TypeDef = 0x02,

    /// `Field` table (0x04) - Field definitions within types.
    ///
    /// Contains all field definitions, including their attributes, name,
    /// and signature. Fields are owned by types defined in the `TypeDef` table.
    Field = 0x04,

    /// `MethodDef` table (0x06) - Method definitions within types.
    ///
    /// Contains all method definitions including constructors, instance methods,
    /// static methods, and finalizers. Includes method attributes, name,
    /// signature, and RVA (if the method has IL code).
    MethodDef = 0x06,

    /// `Param` table (0x08) - Parameter definitions for methods.
    ///
    /// Contains parameter information for methods, including parameter attributes,
    /// sequence number, and name. Each parameter belongs to a method in `MethodDef`.
    Param = 0x08,

    /// `InterfaceImpl` table (0x09) - Interface implementations by types.
    ///
    /// Records which interfaces are implemented by which types. Each row
    /// represents a type implementing a specific interface.
    InterfaceImpl = 0x09,

    /// `MemberRef` table (0x0A) - References to external members.
    ///
    /// Contains references to methods and fields that are defined in external
    /// assemblies or modules, including the member name and signature.
    MemberRef = 0x0A,

    /// `Constant` table (0x0B) - Compile-time constant values.
    ///
    /// Contains constant values for fields, parameters, and properties.
    /// Includes the constant type and value data.
    Constant = 0x0B,

    /// `CustomAttribute` table (0x0C) - Custom attribute applications.
    ///
    /// Records the application of custom attributes to various metadata elements
    /// such as types, methods, fields, assemblies, etc. Contains the attribute
    /// constructor and value blob.
    CustomAttribute = 0x0C,

    /// `FieldMarshal` table (0x0D) - P/Invoke marshalling information for fields.
    ///
    /// Contains marshalling information for fields that require special
    /// handling during P/Invoke calls, such as string marshalling or
    /// struct layout specifications.
    FieldMarshal = 0x0D,

    /// `DeclSecurity` table (0x0E) - Declarative security permissions.
    ///
    /// Contains declarative security attributes applied to types and methods,
    /// specifying required permissions, demanded permissions, and other
    /// security-related metadata.
    DeclSecurity = 0x0E,

    /// `ClassLayout` table (0x0F) - Memory layout information for types.
    ///
    /// Specifies explicit layout information for types, including packing size
    /// and class size. Used for types that require specific memory layouts
    /// for interop scenarios.
    ClassLayout = 0x0F,

    /// `FieldLayout` table (0x10) - Explicit field positioning within types.
    ///
    /// Contains explicit offset information for fields in types with
    /// explicit layout. Each row specifies the byte offset of a field
    /// within its containing type.
    FieldLayout = 0x10,

    /// `StandAloneSig` table (0x11) - Standalone method signatures.
    ///
    /// Contains method signatures that are not directly associated with
    /// a method definition, such as signatures for function pointers
    /// or unmanaged calling conventions.
    StandAloneSig = 0x11,

    /// `EventMap` table (0x12) - Mapping from types to their events.
    ///
    /// Establishes the relationship between types and the events they define.
    /// Each row maps a type to a range of events in the Event table.
    EventMap = 0x12,

    /// `Event` table (0x14) - Event definitions within types.
    ///
    /// Contains event definitions, including event attributes, name, and
    /// event type. Events are used for the publisher-subscriber pattern
    /// in .NET programming.
    Event = 0x14,

    /// `PropertyMap` table (0x15) - Mapping from types to their properties.
    ///
    /// Establishes the relationship between types and the properties they define.
    /// Each row maps a type to a range of properties in the Property table.
    PropertyMap = 0x15,

    /// `Property` table (0x17) - Property definitions within types.
    ///
    /// Contains property definitions, including property attributes, name,
    /// and property signature. Properties provide controlled access to
    /// type members through getter and setter methods.
    Property = 0x17,

    /// `MethodSemantics` table (0x18) - Property and event accessor mappings.
    ///
    /// Associates methods with properties and events, specifying whether
    /// a method is a getter, setter, adder, remover, or fire method.
    MethodSemantics = 0x18,

    /// `MethodImpl` table (0x19) - Method implementation mappings.
    ///
    /// Specifies which method implementations correspond to interface
    /// method declarations. Used for explicit interface implementations
    /// and method overrides.
    MethodImpl = 0x19,

    /// `ModuleRef` table (0x1A) - References to external modules.
    ///
    /// Contains references to external modules (DLLs) that are used
    /// by this assembly, primarily for P/Invoke scenarios.
    ModuleRef = 0x1A,

    /// `TypeSpec` table (0x1B) - Generic type specifications.
    ///
    /// Contains instantiated generic types and other complex type
    /// specifications that cannot be represented by simple `TypeRef`
    /// or `TypeDef` entries.
    TypeSpec = 0x1B,

    /// `ImplMap` table (0x1C) - P/Invoke implementation mappings.
    ///
    /// Contains P/Invoke mapping information for methods that call
    /// unmanaged code, including the target DLL and entry point name.
    ImplMap = 0x1C,

    /// `FieldRVA` table (0x1D) - Field relative virtual addresses.
    ///
    /// Contains RVA (Relative Virtual Address) information for fields
    /// that have initial data, such as static fields with initializers
    /// or mapped data fields.
    FieldRVA = 0x1D,

    /// `Assembly` table (0x20) - Current assembly metadata.
    ///
    /// Contains metadata about the current assembly, including version
    /// information, security permissions, and assembly attributes.
    /// Each assembly has exactly one Assembly row.
    Assembly = 0x20,

    /// `AssemblyProcessor` table (0x21) - Processor-specific assembly information.
    ///
    /// Contains processor architecture information for the assembly,
    /// though this table is rarely used in practice.
    AssemblyProcessor = 0x21,

    /// `AssemblyOS` table (0x22) - Operating system-specific assembly information.
    ///
    /// Contains operating system information for the assembly,
    /// though this table is rarely used in practice.
    AssemblyOS = 0x22,

    /// `AssemblyRef` table (0x23) - References to external assemblies.
    ///
    /// Contains references to other assemblies that this assembly depends on,
    /// including version information and public key tokens.
    AssemblyRef = 0x23,

    /// `AssemblyRefProcessor` table (0x24) - Processor info for external assemblies.
    ///
    /// Contains processor architecture information for referenced assemblies,
    /// though this table is rarely used in practice.
    AssemblyRefProcessor = 0x24,

    /// `AssemblyRefOS` table (0x25) - OS info for external assemblies.
    ///
    /// Contains operating system information for referenced assemblies,
    /// though this table is rarely used in practice.
    AssemblyRefOS = 0x25,

    /// `File` table (0x26) - File references within the assembly.
    ///
    /// Contains references to files that are part of the assembly,
    /// such as modules and resources that are stored in separate files.
    File = 0x26,

    /// `ExportedType` table (0x27) - Types exported from this assembly.
    ///
    /// Contains information about types that are defined in this assembly
    /// but forwarded from other assemblies, enabling type forwarding scenarios.
    ExportedType = 0x27,

    /// `ManifestResource` table (0x28) - Assembly resources.
    ///
    /// Contains information about resources embedded in or linked to the assembly,
    /// including resource names, attributes, and location information.
    ManifestResource = 0x28,

    /// `NestedClass` table (0x29) - Nested class relationships.
    ///
    /// Establishes parent-child relationships between types, indicating
    /// which types are nested within other types.
    NestedClass = 0x29,

    /// `GenericParam` table (0x2A) - Generic parameter definitions.
    ///
    /// Contains generic parameter information for generic types and methods,
    /// including parameter names, constraints, and variance information.
    GenericParam = 0x2A,

    /// `MethodSpec` table (0x2B) - Generic method specifications.
    ///
    /// Contains instantiated generic methods with specific type arguments,
    /// allowing references to generic methods with concrete type parameters.
    MethodSpec = 0x2B,

    /// `GenericParamConstraint` table (0x2C) - Generic parameter constraints.
    ///
    /// Specifies constraints on generic parameters, such as base class
    /// constraints, interface constraints, and special constraints
    /// (`new()`, class, struct).
    GenericParamConstraint = 0x2C,
}
