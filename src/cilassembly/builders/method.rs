//! High-level method builder for creating complete method definitions.
//!
//! This module provides [`MethodBuilder`] for creating complete method definitions
//! including metadata, signatures, parameters, and implementations. It orchestrates
//! the existing low-level builders to provide a fluent, high-level API.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        method::{MethodAccessFlags, MethodImplCodeType, MethodModifiers},
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{MethodDefBuilder, ParamAttributes, ParamBuilder, TableId},
        token::Token,
    },
    Result,
};

use super::method_body::MethodBodyBuilder;

/// High-level builder for creating complete method definitions.
///
/// `MethodBuilder` provides a fluent API for creating methods with metadata,
/// signatures, parameters, and implementations. It composes the existing
/// low-level builders ([`crate::metadata::tables::MethodDefBuilder`],
/// [`crate::cilassembly::builders::MethodBodyBuilder`], etc.) to provide
/// a convenient high-level interface.
///
/// # Design
///
/// The builder follows a composition approach:
/// - Uses existing `MethodDefBuilder` for metadata table creation
/// - Uses `MethodBodyBuilder` for CIL implementation
/// - Uses existing signature builders for method signatures
/// - Orchestrates all components through `BuilderContext`
///
/// # Examples
///
/// ## Simple Static Method
///
/// ```rust,no_run
/// use dotscope::prelude::*;
/// use dotscope::MethodBuilder;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let method_token = MethodBuilder::new("Add")
///     .public()
///     .static_method()
///     .parameter("a", TypeSignature::I4)
///     .parameter("b", TypeSignature::I4)
///     .returns(TypeSignature::I4)
///     .implementation(|body| {
///         body.implementation(|asm| {
///             asm.ldarg_0()?
///                .ldarg_1()?
///                .add()?
///                .ret()?;
///             Ok(())
///         })
///     })
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Instance Constructor
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let ctor_token = MethodBuilder::constructor()
///     .parameter("name", TypeSignature::String)
///     .parameter("age", TypeSignature::I4)
///     .implementation(|body| {
///         body.implementation(|asm| {
///             // Call base constructor
///             asm.ldarg_0()?  // this
///                .call(Token::new(0x0A000001))? // base ctor token
///                // Initialize fields...
///                .ret()?;
///             Ok(())
///         })
///     })
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Property Getter
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let getter_token = MethodBuilder::property_getter("Name", TypeSignature::String)
///     .implementation(|body| {
///         body.implementation(|asm| {
///             asm.ldarg_0()?  // this
///                .ldfld(Token::new(0x04000001))? // field token
///                .ret()?;
///             Ok(())
///         })
///     })
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## P/Invoke Method with Custom Calling Convention
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let pinvoke_token = MethodBuilder::new("GetLastError")
///     .public()
///     .static_method()
///     .calling_convention_stdcall() // Windows API calling convention
///     .returns(TypeSignature::I4)
///     .extern_method() // No IL implementation - native code
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Variable Argument Method
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let printf_token = MethodBuilder::new("printf")
///     .public()
///     .static_method()
///     .calling_convention_vararg() // Supports variable arguments
///     .parameter("format", TypeSignature::String)
///     .returns(TypeSignature::I4)
///     .extern_method()
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct MethodBuilder {
    /// Method name
    name: String,

    /// Access flags (public, private, etc.)
    access_flags: MethodAccessFlags,

    /// Method modifiers (static, virtual, etc.)
    modifiers: MethodModifiers,

    /// Implementation flags (IL, native, etc.)
    impl_flags: MethodImplCodeType,

    /// Return type
    return_type: TypeSignature,

    /// Parameters
    parameters: Vec<(String, TypeSignature)>,

    /// Method body builder
    body_builder: Option<MethodBodyBuilder>,

    /// Whether this method has a 'this' parameter
    has_this: bool,

    /// Calling convention: explicit 'this'
    explicit_this: bool,

    /// Calling convention: default managed
    default_calling_convention: bool,

    /// Calling convention: variable arguments
    vararg: bool,

    /// Calling convention: C declaration (cdecl)
    cdecl: bool,

    /// Calling convention: standard call (stdcall)
    stdcall: bool,

    /// Calling convention: this call (thiscall)
    thiscall: bool,

    /// Calling convention: fast call (fastcall)
    fastcall: bool,
}

impl MethodBuilder {
    /// Create a new method builder with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - Method name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("MyMethod");
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            access_flags: MethodAccessFlags::PRIVATE, // Default to private
            modifiers: MethodModifiers::empty(),
            impl_flags: MethodImplCodeType::IL,
            return_type: TypeSignature::Void,
            parameters: Vec::new(),
            body_builder: None,
            has_this: true, // Default to instance method
            explicit_this: false,
            default_calling_convention: true, // Default to managed calling convention
            vararg: false,
            cdecl: false,
            stdcall: false,
            thiscall: false,
            fastcall: false,
        }
    }

    /// Create a constructor method builder.
    ///
    /// This sets up the method with the appropriate name (".ctor"), flags,
    /// and return type for an instance constructor.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let ctor = MethodBuilder::constructor();
    /// ```
    #[must_use]
    pub fn constructor() -> Self {
        Self::new(".ctor").public().special_name().rtspecial_name()
    }

    /// Create a static constructor method builder.
    ///
    /// This sets up the method with the appropriate name (".cctor"), flags,
    /// and return type for a static constructor (type initializer).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let static_ctor = MethodBuilder::static_constructor();
    /// ```
    #[must_use]
    pub fn static_constructor() -> Self {
        Self::new(".cctor")
            .private()
            .static_method()
            .special_name()
            .rtspecial_name()
    }

    /// Create a property getter method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("get_PropertyName"),
    /// flags, and return type for a property getter.
    ///
    /// # Arguments
    ///
    /// * `property_name` - Name of the property
    /// * `return_type` - Type that the property returns
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let getter = MethodBuilder::property_getter("Name", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn property_getter(property_name: &str, return_type: TypeSignature) -> Self {
        Self::new(&format!("get_{property_name}"))
            .public()
            .special_name()
            .returns(return_type)
    }

    /// Create a property setter method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("set_PropertyName"),
    /// flags, and a value parameter for a property setter.
    ///
    /// # Arguments
    ///
    /// * `property_name` - Name of the property
    /// * `value_type` - Type of the property value
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let setter = MethodBuilder::property_setter("Name", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn property_setter(property_name: &str, value_type: TypeSignature) -> Self {
        Self::new(&format!("set_{property_name}"))
            .public()
            .special_name()
            .parameter("value", value_type)
    }

    /// Create an event add method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("add_EventName"),
    /// flags, and a delegate parameter for an event add accessor.
    ///
    /// # Arguments
    ///
    /// * `event_name` - The name of the event
    /// * `delegate_type` - The type of the event delegate
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let add_method = MethodBuilder::event_add("OnClick", TypeSignature::Object);
    /// ```
    #[must_use]
    pub fn event_add(event_name: &str, delegate_type: TypeSignature) -> Self {
        Self::new(&format!("add_{event_name}"))
            .public()
            .special_name()
            .parameter("value", delegate_type)
    }

    /// Create an event remove method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("remove_EventName"),
    /// flags, and a delegate parameter for an event remove accessor.
    ///
    /// # Arguments
    ///
    /// * `event_name` - The name of the event
    /// * `delegate_type` - The type of the event delegate
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let remove_method = MethodBuilder::event_remove("OnClick", TypeSignature::Object);
    /// ```
    #[must_use]
    pub fn event_remove(event_name: &str, delegate_type: TypeSignature) -> Self {
        Self::new(&format!("remove_{event_name}"))
            .public()
            .special_name()
            .parameter("value", delegate_type)
    }

    /// Set the method as public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.access_flags = MethodAccessFlags::PUBLIC;
        self
    }

    /// Set the method as private.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").private();
    /// ```
    #[must_use]
    pub fn private(mut self) -> Self {
        self.access_flags = MethodAccessFlags::PRIVATE;
        self
    }

    /// Set the method as protected.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").protected();
    /// ```
    #[must_use]
    pub fn protected(mut self) -> Self {
        self.access_flags = MethodAccessFlags::FAMILY;
        self
    }

    /// Set the method as internal (assembly-level access).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").internal();
    /// ```
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.access_flags = MethodAccessFlags::ASSEMBLY;
        self
    }

    /// Set the method as static.
    ///
    /// Static methods do not have a 'this' parameter and belong to the type
    /// rather than an instance.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").static_method();
    /// ```
    #[must_use]
    pub fn static_method(mut self) -> Self {
        self.modifiers |= MethodModifiers::STATIC;
        self.has_this = false;
        self
    }

    /// Set the method as virtual.
    ///
    /// Virtual methods can be overridden in derived classes.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").virtual_method();
    /// ```
    #[must_use]
    pub fn virtual_method(mut self) -> Self {
        self.modifiers |= MethodModifiers::VIRTUAL;
        self
    }

    /// Set the method as abstract.
    ///
    /// Abstract methods have no implementation and must be overridden.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").abstract_method();
    /// ```
    #[must_use]
    pub fn abstract_method(mut self) -> Self {
        self.modifiers |= MethodModifiers::ABSTRACT;
        self
    }

    /// Set the method as sealed (final).
    ///
    /// Sealed methods cannot be overridden further.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").sealed();
    /// ```
    #[must_use]
    pub fn sealed(mut self) -> Self {
        self.modifiers |= MethodModifiers::FINAL;
        self
    }

    /// Mark the method as having a special name.
    ///
    /// This is typically used for constructors, property accessors, etc.
    #[must_use]
    pub fn special_name(mut self) -> Self {
        self.modifiers |= MethodModifiers::SPECIAL_NAME;
        self
    }

    /// Mark the method as having a runtime special name.  
    ///
    /// This is typically used for constructors and other runtime-special methods.
    #[must_use]
    pub fn rtspecial_name(mut self) -> Self {
        self.modifiers |= MethodModifiers::RTSPECIAL_NAME;
        self
    }

    /// Set the method to use the default managed calling convention.
    ///
    /// This is the standard calling convention for .NET methods and is enabled by default.
    /// Most managed methods should use this calling convention.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").calling_convention_default();
    /// ```
    #[must_use]
    pub fn calling_convention_default(mut self) -> Self {
        self.clear_calling_conventions();
        self.default_calling_convention = true;
        self
    }

    /// Set the method to use the variable argument calling convention.
    ///
    /// Methods using this calling convention can accept additional arguments
    /// beyond those declared in the signature (similar to C's variadic functions).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Printf").calling_convention_vararg();
    /// ```
    #[must_use]
    pub fn calling_convention_vararg(mut self) -> Self {
        self.clear_calling_conventions();
        self.vararg = true;
        self
    }

    /// Set the method to use the C declaration calling convention (cdecl).
    ///
    /// This calling convention is used for interoperability with native C functions.
    /// Arguments are pushed right-to-left and the caller cleans up the stack.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("CFunction").calling_convention_cdecl();
    /// ```
    #[must_use]
    pub fn calling_convention_cdecl(mut self) -> Self {
        self.clear_calling_conventions();
        self.cdecl = true;
        self
    }

    /// Set the method to use the standard call calling convention (stdcall).
    ///
    /// This calling convention is commonly used for Windows API functions.
    /// Arguments are pushed right-to-left and the callee cleans up the stack.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("WinAPI").calling_convention_stdcall();
    /// ```
    #[must_use]
    pub fn calling_convention_stdcall(mut self) -> Self {
        self.clear_calling_conventions();
        self.stdcall = true;
        self
    }

    /// Set the method to use the this call calling convention (thiscall).
    ///
    /// This calling convention is used for C++ member functions.
    /// The 'this' pointer is passed in a register (typically ECX on x86).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("CppMethod").calling_convention_thiscall();
    /// ```
    #[must_use]
    pub fn calling_convention_thiscall(mut self) -> Self {
        self.clear_calling_conventions();
        self.thiscall = true;
        self
    }

    /// Set the method to use the fast call calling convention (fastcall).
    ///
    /// This calling convention uses registers for parameter passing where possible,
    /// providing better performance for frequently called methods.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("FastMethod").calling_convention_fastcall();
    /// ```
    #[must_use]
    pub fn calling_convention_fastcall(mut self) -> Self {
        self.clear_calling_conventions();
        self.fastcall = true;
        self
    }

    /// Set the method to use explicit 'this' parameter.
    ///
    /// When enabled, the 'this' parameter is explicitly declared in the method signature
    /// rather than being implicit. This is rarely used in managed code.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("ExplicitThis").explicit_this();
    /// ```
    #[must_use]
    pub fn explicit_this(mut self) -> Self {
        self.explicit_this = true;
        self
    }

    /// Set the return type of the method.
    ///
    /// # Arguments
    ///
    /// * `return_type` - Type signature for the return value
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = MethodBuilder::new("GetValue").returns(TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn returns(mut self, return_type: TypeSignature) -> Self {
        self.return_type = return_type;
        self
    }

    /// Add a parameter to the method.
    ///
    /// Parameters are added in order and will be accessible via ldarg instructions
    /// starting from index 0 (or 1 for instance methods, where 0 is 'this').
    ///
    /// # Arguments
    ///
    /// * `name` - Parameter name
    /// * `param_type` - Parameter type signature
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = MethodBuilder::new("Add")
    ///     .parameter("a", TypeSignature::I4)
    ///     .parameter("b", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn parameter(mut self, name: &str, param_type: TypeSignature) -> Self {
        self.parameters.push((name.to_string(), param_type));
        self
    }

    /// Set the method implementation using a method body builder.
    ///
    /// This defines what the method actually does. The closure receives a
    /// `MethodBodyBuilder` that can be configured with locals and implementation.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that configures the method body
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_file("test.dll".as_ref())?;
    /// # let assembly = dotscope::CilAssembly::new(view);
    /// # let mut context = dotscope::BuilderContext::new(assembly);
    /// let method = MethodBuilder::new("Test")
    ///     .implementation(|body| {
    ///         body.local("temp", dotscope::metadata::signatures::TypeSignature::I4)
    ///             .implementation(|asm| {
    ///                 asm.ldc_i4_const(42)?
    ///                    .stloc_0()?
    ///                    .ldloc_0()?
    ///                    .ret()?;
    ///                 Ok(())
    ///             })
    ///     })
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn implementation<F>(mut self, f: F) -> Self
    where
        F: FnOnce(MethodBodyBuilder) -> MethodBodyBuilder,
    {
        let body_builder = f(MethodBodyBuilder::new());
        self.body_builder = Some(body_builder);
        self
    }

    /// Mark this method as extern (no implementation).
    ///
    /// Extern methods are implemented outside of IL (e.g., native code,
    /// runtime-provided, etc.).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("ExternalMethod").extern_method();
    /// ```
    #[must_use]
    pub fn extern_method(mut self) -> Self {
        self.body_builder = None; // No IL implementation
        self
    }

    /// Build the complete method and add it to the assembly.
    ///
    /// This method orchestrates the creation of:
    /// 1. Method signature from return type and parameters
    /// 2. Method body from the body builder (if present)
    /// 3. Parameter table entries
    /// 4. Method definition table entry
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A token representing the newly created method definition.
    ///
    /// # Errors
    ///
    /// Returns an error if method creation fails at any step.
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Extract values needed for both signature and parameter creation
        let return_type = self.return_type.clone();
        let parameters = self.parameters.clone();
        let has_this = self.has_this;

        // Create method signature
        let signature = SignatureMethod {
            has_this,
            explicit_this: self.explicit_this,
            default: self.default_calling_convention,
            vararg: self.vararg,
            cdecl: self.cdecl,
            stdcall: self.stdcall,
            thiscall: self.thiscall,
            fastcall: self.fastcall,
            param_count_generic: 0,
            param_count: u32::try_from(parameters.len())
                .map_err(|_| malformed_error!("Method parameter count exceeds u32 range"))?,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: return_type.clone(),
            },
            params: parameters
                .iter()
                .map(|(_, param_type)| SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: param_type.clone(),
                })
                .collect(),
            varargs: Vec::new(),
        };

        let signature_bytes = encode_method_signature(&signature)?;

        // Create method body if we have an implementation
        let (rva, _local_sig_token) = if let Some(body_builder) = self.body_builder {
            let (body_bytes, local_sig_token) = body_builder.build(context)?;

            // Store method body through BuilderContext and get a placeholder RVA.
            // This placeholder will be resolved to the actual RVA during PE writing
            // when the real code section layout is determined.
            let placeholder_rva = context.store_method_body(body_bytes);

            (placeholder_rva, local_sig_token)
        } else {
            // Abstract or extern method - no implementation
            (0u32, Token::new(0))
        };

        // Combine all flags for the method definition
        let combined_flags = self.access_flags.bits() | self.modifiers.bits();

        // Get the next parameter table index (where our parameters will start)
        let param_start_index = context.next_rid(TableId::Param);

        // Create parameter table entries
        // Always create a return type parameter (sequence 0) for every method,
        // even if it returns void. This is required by ECMA-335 and expected by mono runtime.
        ParamBuilder::new()
            .flags(0) // No special flags for return type
            .sequence(0) // Return type is always sequence 0
            .build(context)?;

        // Create parameter entries for each method parameter
        for (sequence, (name, _param_type)) in parameters.iter().enumerate() {
            let param_sequence = u32::try_from(sequence + 1)
                .map_err(|_| malformed_error!("Parameter sequence exceeds u32 range"))?; // Parameters start at sequence 1

            ParamBuilder::new()
                .name(name)
                .flags(ParamAttributes::IN) // Default to IN parameter
                .sequence(param_sequence)
                .build(context)?;
        }

        // Create the method definition with the correct parameter list index
        let method_token = MethodDefBuilder::new()
            .name(&self.name)
            .flags(combined_flags)
            .impl_flags(self.impl_flags.bits())
            .signature(&signature_bytes)
            .rva(rva)
            .param_list(param_start_index) // Point to our parameter table entries
            .build(context)?;

        Ok(method_token)
    }

    /// Helper method to clear all calling convention flags.
    ///
    /// This ensures only one calling convention is active at a time.
    fn clear_calling_conventions(&mut self) {
        self.default_calling_convention = false;
        self.vararg = false;
        self.cdecl = false;
        self.stdcall = false;
        self.thiscall = false;
        self.fastcall = false;
    }
}

impl Default for MethodBuilder {
    fn default() -> Self {
        Self::new("DefaultMethod")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, signatures::TypeSignature},
    };
    use std::path::PathBuf;

    fn get_test_context() -> Result<BuilderContext> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        let assembly = CilAssembly::new(view);
        Ok(BuilderContext::new(assembly))
    }

    #[test]
    fn test_method_builder_basic() -> Result<()> {
        let mut context = get_test_context()?;

        let method_token = MethodBuilder::new("TestMethod")
            .public()
            .static_method()
            .returns(TypeSignature::Void)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.nop()?;
                    asm.ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        // Should create a valid method token
        assert_eq!(method_token.value() & 0xFF000000, 0x06000000); // MethodDef table

        Ok(())
    }

    #[test]
    fn test_method_builder_with_parameters() -> Result<()> {
        let mut context = get_test_context()?;

        let method_token = MethodBuilder::new("Add")
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(method_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_constructor_builder() -> Result<()> {
        let mut context = get_test_context()?;

        let ctor_token = MethodBuilder::constructor()
            .parameter("name", TypeSignature::String)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // this
                        .call(Token::new(0x0A000001))? // base ctor
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(ctor_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_property_getter() -> Result<()> {
        let mut context = get_test_context()?;

        let getter_token = MethodBuilder::property_getter("Name", TypeSignature::String)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldfld(Token::new(0x04000001))?.ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(getter_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_property_setter() -> Result<()> {
        let mut context = get_test_context()?;

        let setter_token = MethodBuilder::property_setter("Name", TypeSignature::String)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // this
                        .ldarg_1()? // value
                        .stfld(Token::new(0x04000001))?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(setter_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_abstract_method() -> Result<()> {
        let mut context = get_test_context()?;

        let method_token = MethodBuilder::new("AbstractMethod")
            .public()
            .abstract_method()
            .virtual_method()
            .returns(TypeSignature::I4)
            .extern_method() // No implementation
            .build(&mut context)?;

        assert_eq!(method_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_static_constructor() -> Result<()> {
        let mut context = get_test_context()?;

        let static_ctor_token = MethodBuilder::static_constructor()
            .implementation(|body| {
                body.implementation(|asm| {
                    // Initialize static fields
                    asm.ldc_i4_const(42)?
                        .stsfld(Token::new(0x04000001))?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(static_ctor_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_method_with_locals() -> Result<()> {
        let mut context = get_test_context()?;

        let method_token = MethodBuilder::new("ComplexMethod")
            .public()
            .static_method()
            .parameter("input", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.local("temp", TypeSignature::I4)
                    .local("result", TypeSignature::I4)
                    .implementation(|asm| {
                        asm.ldarg_0()? // Load input
                            .stloc_0()? // Store to temp
                            .ldloc_0()? // Load temp
                            .ldc_i4_1()? // Load 1
                            .add()? // Add 1
                            .stloc_1()? // Store to result
                            .ldloc_1()? // Load result
                            .ret()?; // Return result
                        Ok(())
                    })
            })
            .build(&mut context)?;

        assert_eq!(method_token.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_method_builder_calling_conventions() -> Result<()> {
        let mut context = get_test_context()?;

        // Test cdecl calling convention
        let cdecl_method = MethodBuilder::new("CdeclMethod")
            .public()
            .static_method()
            .calling_convention_cdecl()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .extern_method() // No implementation for P/Invoke
            .build(&mut context)?;

        assert_eq!(cdecl_method.value() & 0xFF000000, 0x06000000);

        // Test stdcall calling convention
        let stdcall_method = MethodBuilder::new("StdcallMethod")
            .public()
            .static_method()
            .calling_convention_stdcall()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .extern_method()
            .build(&mut context)?;

        assert_eq!(stdcall_method.value() & 0xFF000000, 0x06000000);

        // Test default calling convention (should work for managed methods)
        let default_method = MethodBuilder::new("DefaultMethod")
            .public()
            .static_method()
            .calling_convention_default()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(default_method.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_method_builder_vararg_calling_convention() -> Result<()> {
        let mut context = get_test_context()?;

        let vararg_method = MethodBuilder::new("VarargMethod")
            .public()
            .static_method()
            .calling_convention_vararg()
            .parameter("format", TypeSignature::String)
            .returns(TypeSignature::Void)
            .extern_method() // Vararg methods are typically extern
            .build(&mut context)?;

        assert_eq!(vararg_method.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_method_builder_explicit_this() -> Result<()> {
        let mut context = get_test_context()?;

        let explicit_this_method = MethodBuilder::new("ExplicitThisMethod")
            .public()
            .explicit_this()
            .parameter("value", TypeSignature::I4)
            .returns(TypeSignature::Void)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // Load explicit 'this'
                        .ldarg_1()? // Load value parameter
                        .stfld(Token::new(0x04000001))? // Store to field
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(explicit_this_method.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_method_builder_calling_convention_switching() -> Result<()> {
        let mut context = get_test_context()?;

        // Test that setting a new calling convention clears the previous one
        let method = MethodBuilder::new("SwitchingMethod")
            .public()
            .static_method()
            .calling_convention_cdecl() // Set cdecl first
            .calling_convention_stdcall() // Switch to stdcall (should clear cdecl)
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .extern_method()
            .build(&mut context)?;

        assert_eq!(method.value() & 0xFF000000, 0x06000000);

        Ok(())
    }

    #[test]
    fn test_event_add_method() -> Result<()> {
        let mut context = get_test_context()?;

        let add_method = MethodBuilder::event_add("OnClick", TypeSignature::Object)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // Load 'this'
                        .ldfld(Token::new(0x04000001))? // Load current delegate
                        .ldarg_1()? // Load new delegate
                        .call(Token::new(0x0A000001))? // Call Delegate.Combine
                        .stfld(Token::new(0x04000001))? // Store combined delegate
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(add_method.value() & 0xFF000000, 0x06000000); // MethodDef table

        Ok(())
    }

    #[test]
    fn test_event_remove_method() -> Result<()> {
        let mut context = get_test_context()?;

        let remove_method = MethodBuilder::event_remove("OnClick", TypeSignature::Object)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // Load 'this'
                        .ldfld(Token::new(0x04000001))? // Load current delegate
                        .ldarg_1()? // Load delegate to remove
                        .call(Token::new(0x0A000002))? // Call Delegate.Remove
                        .stfld(Token::new(0x04000001))? // Store updated delegate
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut context)?;

        assert_eq!(remove_method.value() & 0xFF000000, 0x06000000); // MethodDef table

        Ok(())
    }
}
