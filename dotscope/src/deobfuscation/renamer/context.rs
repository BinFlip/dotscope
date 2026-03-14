//! Contextual feature data for rename decisions.
//!
//! These data-only structs carry extracted features from SSA analysis
//! to the [`RenameProvider`](super::RenameProvider) for name inference.

/// What kind of identifier we're renaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierKind {
    /// A type definition (class, struct, enum, interface).
    Type,
    /// A method definition.
    Method,
    /// A field definition.
    Field,
    /// A method parameter.
    Parameter,
}

/// Contextual features extracted for a single identifier.
///
/// Populated by the feature extraction phase and consumed by
/// [`RenameProvider::suggest_name()`](super::RenameProvider::suggest_name).
#[derive(Debug, Clone, Default)]
pub struct RenameContext {
    /// What kind of identifier.
    pub kind: Option<IdentifierKind>,

    /// Method calls made within the method body (fully qualified external names).
    ///
    /// These are the strongest naming signal — obfuscators cannot rename
    /// BCL/framework method names.
    pub call_targets: Vec<String>,

    /// String literals found in the same method body.
    pub string_literals: Vec<String>,

    /// Known API calls this identifier participates in, with parameter position.
    pub api_calls: Vec<ApiCallInfo>,

    /// The .NET type (for fields/params) or return type (for methods).
    pub dotnet_type: Option<String>,

    /// Parameter types and any known names (for methods).
    pub parameters: Vec<ParamInfo>,

    /// Field accesses (load/store) within the method body.
    pub field_accesses: Vec<String>,

    /// Base class (from metadata type hierarchy).
    pub base_class: Option<String>,

    /// Implemented interfaces (from InterfaceImpl table).
    pub interfaces: Vec<String>,

    /// Parent type name (if already renamed in a previous cascade phase).
    pub parent_type: Option<String>,

    /// Sibling members already renamed in this type.
    pub siblings: Vec<String>,

    /// For small methods: call-site skeleton as C#-like pseudocode.
    pub call_site_skeleton: Option<String>,

    /// For large methods: phase narrative from decomposition.
    pub phase_narrative: Vec<PhaseInfo>,

    /// Context from methods that call this one.
    ///
    /// Propagated from callers via the call graph — includes nearby string
    /// literals (e.g., format strings like `"Add(10, 5) = {0}"`) and what
    /// the return value is passed to.
    pub caller_context: Vec<CallerInfo>,

    /// Names already used in this scope that should not be reused.
    ///
    /// When a provider suggests a duplicate, the context is cloned with this
    /// field populated and re-queried. Providers should treat these as
    /// negative constraints.
    pub rejected_names: Vec<String>,
}

/// A labeled phase within a method, produced by phase decomposition.
#[derive(Debug, Clone)]
pub struct PhaseInfo {
    /// Human-readable label, e.g. "Load encrypted resource from assembly".
    pub label: String,

    /// External call targets in this phase.
    pub call_targets: Vec<String>,

    /// Opcode distribution for this phase.
    pub opcode_profile: Option<OpcodeProfile>,

    /// Structural annotation: "loop", "try/catch", "conditional", "linear".
    pub structure: Option<String>,
}

/// Compact opcode distribution by semantic category.
#[derive(Debug, Clone, Default)]
pub struct OpcodeProfile {
    /// Number of call/callvirt instructions.
    pub calls: u32,
    /// Number of ldstr instructions.
    pub strings: u32,
    /// Number of field load/store instructions.
    pub field_io: u32,
    /// Number of and/or/xor/not/shl/shr instructions.
    pub bitwise: u32,
    /// Number of add/sub/mul/div/rem/neg instructions.
    pub arithmetic: u32,
    /// Number of array load/store/length instructions.
    pub array: u32,
    /// Number of ceq/clt/cgt/branch comparison instructions.
    pub comparison: u32,
    /// Number of conv.* instructions.
    pub conversion: u32,
}

/// Parameter info for method contexts.
#[derive(Debug, Clone)]
pub struct ParamInfo {
    /// The .NET type name (e.g., "System.String", "System.Byte[]").
    pub dotnet_type: String,

    /// Known name from MemberRef resolution (anchor data).
    pub known_name: Option<String>,
}

/// Context from a known API call where this identifier is used.
#[derive(Debug, Clone)]
pub struct ApiCallInfo {
    /// Fully qualified method: "System.IO.File::ReadAllText".
    pub method_name: String,

    /// Which argument position this identifier occupies (0-based), if applicable.
    pub argument_position: Option<usize>,
}

/// Context from a caller method.
///
/// Provides naming signals from methods that call the target, including
/// format strings and what the return value feeds into.
#[derive(Debug, Clone)]
pub struct CallerInfo {
    /// The caller method's name (committed rename or original if non-obfuscated).
    pub caller_name: String,

    /// String literals near the call site in the caller (e.g., format strings).
    pub nearby_strings: Vec<String>,

    /// What the return value is passed to (e.g., "Format", "WriteLine").
    pub return_usage: Option<String>,
}
