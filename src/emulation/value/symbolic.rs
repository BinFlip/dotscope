//! Symbolic values for partial emulation.
//!
//! This module provides the [`SymbolicValue`] type for tracking unknown values
//! during CIL emulation. When the emulator encounters values that cannot be
//! determined (method parameters, return values from unstubbed calls, etc.),
//! it represents them symbolically rather than failing.
//!
//! # Use Cases
//!
//! Symbolic values enable several important analysis scenarios:
//!
//! - **Partial emulation**: Continue execution even when some values are unknown
//! - **Taint tracking**: Track data flow from untrusted sources
//! - **Constraint collection**: Build constraints for symbolic execution
//!
//! # Example
//!
//! ```rust
//! use dotscope::emulation::{SymbolicValue, TaintSource};
//! use dotscope::metadata::typesystem::CilFlavor;
//!
//! // Create a symbolic value representing an unknown parameter
//! let param = SymbolicValue::parameter(0, CilFlavor::I4);
//!
//! // Create a tainted value from user input
//! let input = SymbolicValue::new(CilFlavor::Object, TaintSource::UserInput);
//! assert!(input.is_tainted());
//! ```

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::metadata::typesystem::CilFlavor;

/// Global counter for generating unique symbolic value IDs.
static SYMBOLIC_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a unique ID for a symbolic value.
fn next_symbolic_id() -> u64 {
    SYMBOLIC_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Resets the symbolic ID counter (for testing purposes).
#[cfg(test)]
pub fn reset_symbolic_id_counter() {
    SYMBOLIC_ID_COUNTER.store(1, Ordering::Relaxed);
}

/// A symbolic (unknown) value for partial emulation.
///
/// Symbolic values represent unknown or partially-known values during
/// emulation. Each symbolic value has:
///
/// - A unique ID for tracking
/// - A CIL type flavor indicating what kind of value it represents
/// - A taint source indicating the origin of the value
/// - Optional constraints collected during execution
///
/// # Identity
///
/// Each symbolic value has a unique ID. Two symbolic values with different
/// IDs are considered distinct, even if they have the same type and source.
/// This enables precise tracking of data flow.
#[derive(Clone, Debug)]
pub struct SymbolicValue {
    /// Unique identifier for this symbolic value.
    pub id: u64,

    /// The CIL type flavor of this symbolic value.
    pub cil_flavor: CilFlavor,

    /// The source/origin of this symbolic value.
    pub source: TaintSource,

    /// Optional name for debugging (e.g., parameter name).
    pub name: Option<String>,

    /// Dependencies on other symbolic values (for derived values).
    pub dependencies: Vec<u64>,
}

impl SymbolicValue {
    /// Creates a new symbolic value with the given type and source.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{SymbolicValue, TaintSource};
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// let sym = SymbolicValue::new(CilFlavor::I4, TaintSource::Unknown);
    /// ```
    #[must_use]
    pub fn new(cil_flavor: CilFlavor, source: TaintSource) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source,
            name: None,
            dependencies: Vec::new(),
        }
    }

    /// Creates a symbolic value representing a method parameter.
    ///
    /// # Arguments
    ///
    /// * `index` - The parameter index (0-based)
    /// * `cil_flavor` - The type of the parameter
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::SymbolicValue;
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// let param0 = SymbolicValue::parameter(0, CilFlavor::I4);
    /// assert!(matches!(param0.source, dotscope::emulation::TaintSource::Parameter(0)));
    /// ```
    #[must_use]
    pub fn parameter(index: u16, cil_flavor: CilFlavor) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source: TaintSource::Parameter(index),
            name: Some(format!("arg{index}")),
            dependencies: Vec::new(),
        }
    }

    /// Creates a symbolic value representing a local variable.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index (0-based)
    /// * `cil_flavor` - The type of the local
    #[must_use]
    pub fn local(index: u16, cil_flavor: CilFlavor) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source: TaintSource::Local(index),
            name: Some(format!("loc{index}")),
            dependencies: Vec::new(),
        }
    }

    /// Creates a symbolic value representing a field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    /// * `cil_flavor` - The type of the field
    #[must_use]
    pub fn field(field_token: u32, cil_flavor: CilFlavor) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source: TaintSource::Field(field_token),
            name: Some(format!("field_{field_token:08X}")),
            dependencies: Vec::new(),
        }
    }

    /// Creates a symbolic value representing a method return value.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The metadata token of the called method
    /// * `cil_flavor` - The return type
    #[must_use]
    pub fn return_value(method_token: u32, cil_flavor: CilFlavor) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source: TaintSource::MethodReturn(method_token),
            name: Some(format!("ret_{method_token:08X}")),
            dependencies: Vec::new(),
        }
    }

    /// Creates a symbolic value derived from other values through computation.
    ///
    /// # Arguments
    ///
    /// * `cil_flavor` - The result type
    /// * `source` - The source type (typically `TaintSource::Computation`)
    #[must_use]
    pub fn derived(cil_flavor: CilFlavor, source: TaintSource) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source,
            name: None,
            dependencies: Vec::new(),
        }
    }

    /// Creates a derived symbolic value with explicit dependencies.
    ///
    /// # Arguments
    ///
    /// * `cil_flavor` - The result type
    /// * `dependencies` - IDs of symbolic values this depends on
    #[must_use]
    pub fn derived_from(cil_flavor: CilFlavor, dependencies: Vec<u64>) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source: TaintSource::Computation,
            name: None,
            dependencies,
        }
    }

    /// Creates a symbolic value representing external/user input.
    ///
    /// Values from this source should be treated as potentially malicious.
    #[must_use]
    pub fn user_input(cil_flavor: CilFlavor) -> Self {
        SymbolicValue {
            id: next_symbolic_id(),
            cil_flavor,
            source: TaintSource::UserInput,
            name: Some("user_input".to_string()),
            dependencies: Vec::new(),
        }
    }

    /// Sets a human-readable name for this symbolic value.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Returns `true` if this value originates from a tainted source.
    ///
    /// Tainted sources include user input, external data, and values
    /// derived from tainted values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{SymbolicValue, TaintSource};
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// let user = SymbolicValue::user_input(CilFlavor::I4);
    /// assert!(user.is_tainted());
    ///
    /// let param = SymbolicValue::parameter(0, CilFlavor::I4);
    /// assert!(param.is_tainted()); // Parameters are untrusted
    ///
    /// let unknown = SymbolicValue::new(CilFlavor::I4, TaintSource::Unknown);
    /// assert!(!unknown.is_tainted());
    /// ```
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        self.source.is_tainted()
    }

    /// Returns `true` if this value represents a method parameter.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::SymbolicValue;
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// let param = SymbolicValue::parameter(0, CilFlavor::I4);
    /// assert!(param.is_parameter());
    /// ```
    #[must_use]
    pub fn is_parameter(&self) -> bool {
        matches!(self.source, TaintSource::Parameter(_))
    }

    /// Returns `true` if this value represents a local variable.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::SymbolicValue;
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// let local = SymbolicValue::local(0, CilFlavor::I4);
    /// assert!(local.is_local());
    /// ```
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self.source, TaintSource::Local(_))
    }

    /// Returns `true` if this value was derived from computation.
    ///
    /// Computed values result from operations on other symbolic values.
    #[must_use]
    pub fn is_computed(&self) -> bool {
        matches!(self.source, TaintSource::Computation)
    }

    /// Returns the parameter index if this is a parameter value.
    ///
    /// # Returns
    ///
    /// - `Some(index)` if this symbolic value represents a method parameter
    /// - `None` if this is not a parameter value
    #[must_use]
    pub fn parameter_index(&self) -> Option<u16> {
        match self.source {
            TaintSource::Parameter(idx) => Some(idx),
            _ => None,
        }
    }

    /// Returns the local variable index if this is a local value.
    ///
    /// # Returns
    ///
    /// - `Some(index)` if this symbolic value represents a local variable
    /// - `None` if this is not a local variable value
    #[must_use]
    pub fn local_index(&self) -> Option<u16> {
        match self.source {
            TaintSource::Local(idx) => Some(idx),
            _ => None,
        }
    }
}

impl fmt::Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.name {
            write!(f, "{}#{}", name, self.id)
        } else {
            write!(f, "sym#{}", self.id)
        }
    }
}

/// Source/origin of a symbolic value for taint tracking.
///
/// Taint sources identify where symbolic values originate, enabling
/// data flow analysis and security auditing. Some sources are considered
/// "tainted" (potentially malicious), while others are neutral.
///
/// # Taint Propagation
///
/// When operations are performed on tainted values, the result is also
/// tainted. The [`TaintSource::Computation`] variant is used for values
/// derived from other values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// Origin is unknown.
    ///
    /// This is the default for values that cannot be tracked.
    /// Not considered tainted.
    Unknown,

    /// Value comes from a method parameter.
    ///
    /// Parameters are considered tainted because they come from
    /// outside the current method's control.
    Parameter(u16),

    /// Value comes from a local variable that was initialized symbolically.
    ///
    /// Locals are considered tainted if they were never assigned
    /// a concrete value.
    Local(u16),

    /// Value comes from a field load.
    ///
    /// The u32 is the field's metadata token.
    Field(u32),

    /// Value comes from a static field load.
    ///
    /// Static fields are potentially tainted as they can be modified
    /// by other code.
    StaticField(u32),

    /// Value comes from an array element load.
    ArrayElement,

    /// Value comes from a method return value.
    ///
    /// The u32 is the called method's metadata token.
    MethodReturn(u32),

    /// Value comes from external/user input (e.g., Console.ReadLine).
    ///
    /// Always tainted - represents potentially malicious data.
    UserInput,

    /// Value comes from a file, network, or other external source.
    ///
    /// Always tainted - represents potentially malicious data.
    ExternalData,

    /// Value was computed from other values.
    ///
    /// Taint status depends on the input values' taint status.
    /// If any input is tainted, the computation result is tainted.
    Computation,

    /// Value comes from a constant in the metadata.
    ///
    /// Constants are not tainted as they are embedded in the assembly.
    Constant,

    /// Value comes from exception handling (catch block).
    Exception,
}

impl TaintSource {
    /// Returns `true` if this source is considered tainted.
    ///
    /// Tainted sources include:
    /// - User input
    /// - External data
    /// - Parameters (untrusted input)
    /// - Fields (can be modified externally)
    /// - Array elements (contents can change)
    /// - Method returns (behavior unknown)
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        match self {
            TaintSource::Unknown | TaintSource::Constant => false,
            // Computation taint depends on inputs, but by default we mark it tainted
            // to be conservative. The actual taint analysis would check dependencies.
            TaintSource::Parameter(_)
            | TaintSource::Local(_)
            | TaintSource::Field(_)
            | TaintSource::StaticField(_)
            | TaintSource::ArrayElement
            | TaintSource::MethodReturn(_)
            | TaintSource::UserInput
            | TaintSource::ExternalData
            | TaintSource::Exception
            | TaintSource::Computation => true,
        }
    }

    /// Returns a human-readable description of this source.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            TaintSource::Unknown => "unknown",
            TaintSource::Parameter(_) => "parameter",
            TaintSource::Local(_) => "local variable",
            TaintSource::Field(_) => "instance field",
            TaintSource::StaticField(_) => "static field",
            TaintSource::ArrayElement => "array element",
            TaintSource::MethodReturn(_) => "method return",
            TaintSource::UserInput => "user input",
            TaintSource::ExternalData => "external data",
            TaintSource::Computation => "computed",
            TaintSource::Constant => "constant",
            TaintSource::Exception => "exception",
        }
    }
}

impl fmt::Display for TaintSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintSource::Unknown => write!(f, "unknown"),
            TaintSource::Parameter(i) => write!(f, "param[{i}]"),
            TaintSource::Local(i) => write!(f, "local[{i}]"),
            TaintSource::Field(t) => write!(f, "field[{t:08X}]"),
            TaintSource::StaticField(t) => write!(f, "static[{t:08X}]"),
            TaintSource::ArrayElement => write!(f, "array[]"),
            TaintSource::MethodReturn(t) => write!(f, "call[{t:08X}]"),
            TaintSource::UserInput => write!(f, "user_input"),
            TaintSource::ExternalData => write!(f, "external"),
            TaintSource::Computation => write!(f, "computed"),
            TaintSource::Constant => write!(f, "const"),
            TaintSource::Exception => write!(f, "exception"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbolic_value_creation() {
        reset_symbolic_id_counter();

        let sym1 = SymbolicValue::new(CilFlavor::I4, TaintSource::Unknown);
        let sym2 = SymbolicValue::new(CilFlavor::I8, TaintSource::UserInput);

        assert_eq!(sym1.id, 1);
        assert_eq!(sym2.id, 2);
        assert_eq!(sym1.cil_flavor, CilFlavor::I4);
        assert_eq!(sym2.cil_flavor, CilFlavor::I8);
    }

    #[test]
    fn test_symbolic_parameter() {
        reset_symbolic_id_counter();

        let param = SymbolicValue::parameter(0, CilFlavor::I4);

        assert!(param.is_parameter());
        assert!(!param.is_local());
        assert_eq!(param.parameter_index(), Some(0));
        assert!(matches!(param.source, TaintSource::Parameter(0)));
    }

    #[test]
    fn test_symbolic_local() {
        reset_symbolic_id_counter();

        let local = SymbolicValue::local(2, CilFlavor::Object);

        assert!(local.is_local());
        assert!(!local.is_parameter());
        assert_eq!(local.local_index(), Some(2));
    }

    #[test]
    fn test_symbolic_derived() {
        reset_symbolic_id_counter();

        let a = SymbolicValue::parameter(0, CilFlavor::I4);
        let b = SymbolicValue::parameter(1, CilFlavor::I4);
        let derived = SymbolicValue::derived_from(CilFlavor::I4, vec![a.id, b.id]);

        assert!(derived.is_computed());
        assert_eq!(derived.dependencies.len(), 2);
    }

    #[test]
    fn test_taint_sources() {
        // Untainted sources
        assert!(!TaintSource::Unknown.is_tainted());
        assert!(!TaintSource::Constant.is_tainted());

        // Tainted sources
        assert!(TaintSource::UserInput.is_tainted());
        assert!(TaintSource::ExternalData.is_tainted());
        assert!(TaintSource::Parameter(0).is_tainted());
        assert!(TaintSource::Field(0x04000001).is_tainted());
        assert!(TaintSource::MethodReturn(0x06000001).is_tainted());
    }

    #[test]
    fn test_symbolic_value_is_tainted() {
        let user_input = SymbolicValue::user_input(CilFlavor::Object);
        assert!(user_input.is_tainted());

        let param = SymbolicValue::parameter(0, CilFlavor::I4);
        assert!(param.is_tainted());

        let unknown = SymbolicValue::new(CilFlavor::I4, TaintSource::Unknown);
        assert!(!unknown.is_tainted());
    }

    #[test]
    fn test_symbolic_value_with_name() {
        let sym = SymbolicValue::new(CilFlavor::I4, TaintSource::Unknown).with_name("myValue");

        assert_eq!(sym.name, Some("myValue".to_string()));
    }

    #[test]
    fn test_symbolic_value_display() {
        reset_symbolic_id_counter();

        let named = SymbolicValue::parameter(0, CilFlavor::I4);
        assert!(format!("{}", named).starts_with("arg0#"));

        reset_symbolic_id_counter();
        let unnamed = SymbolicValue::new(CilFlavor::I4, TaintSource::Computation);
        assert!(format!("{}", unnamed).starts_with("sym#"));
    }

    #[test]
    fn test_taint_source_display() {
        assert_eq!(format!("{}", TaintSource::Parameter(0)), "param[0]");
        assert_eq!(format!("{}", TaintSource::Local(5)), "local[5]");
        assert_eq!(
            format!("{}", TaintSource::Field(0x04000001)),
            "field[04000001]"
        );
        assert_eq!(format!("{}", TaintSource::UserInput), "user_input");
    }

    #[test]
    fn test_taint_source_description() {
        assert_eq!(TaintSource::Unknown.description(), "unknown");
        assert_eq!(TaintSource::Parameter(0).description(), "parameter");
        assert_eq!(TaintSource::UserInput.description(), "user input");
        assert_eq!(TaintSource::Computation.description(), "computed");
    }

    #[test]
    fn test_symbolic_field() {
        let field = SymbolicValue::field(0x04000001, CilFlavor::I4);

        assert!(matches!(field.source, TaintSource::Field(0x04000001)));
        assert!(field.is_tainted());
    }

    #[test]
    fn test_symbolic_return_value() {
        let ret = SymbolicValue::return_value(0x06000001, CilFlavor::Object);

        assert!(matches!(ret.source, TaintSource::MethodReturn(0x06000001)));
        assert!(ret.is_tainted());
    }
}
