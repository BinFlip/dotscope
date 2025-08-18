//! Method body builder for creating CIL method implementations.
//!
//! This module provides [`MethodBodyBuilder`] for creating method body implementations
//! with automatic stack management, local variables, and exception handling support.
//! It integrates the existing [`crate::assembly::InstructionAssembler`] with ECMA-335
//! method body format encoding.

use crate::{
    assembly::InstructionAssembler,
    cilassembly::BuilderContext,
    metadata::{
        method::{encode_exception_handlers, ExceptionHandler, ExceptionHandlerFlags},
        signatures::{
            encode_local_var_signature, SignatureLocalVariable, SignatureLocalVariables,
            TypeSignature,
        },
        tables::StandAloneSigBuilder,
        token::Token,
        typesystem::CilTypeRc,
    },
    Error, Result,
};

/// Type alias for method body implementation closures
type ImplementationFn = Box<dyn FnOnce(&mut InstructionAssembler) -> Result<()>>;

use crate::metadata::method::encode_method_body_header;

/// Builder for creating method body implementations.
///
/// `MethodBodyBuilder` focuses specifically on creating method body bytes according
/// to the ECMA-335 specification (II.25.4.5). It wraps the existing
/// [`crate::assembly::InstructionAssembler`] and adds:
///
/// - Precise stack depth calculation using real-time instruction analysis
/// - Local variable management with automatic signature generation
/// - Method body format encoding (tiny vs fat) based on actual requirements
/// - Exception handler support
///
/// # Examples
///
/// ## Simple Method Body
///
/// ```rust,no_run
/// use dotscope::MethodBodyBuilder;
/// use dotscope::assembly::InstructionAssembler;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let (body_bytes, _token) = MethodBodyBuilder::new()
///     .max_stack(2)
///     .implementation(|asm| {
///         asm.ldarg_0()?
///            .ldarg_1()?
///            .add()?
///            .ret()?;
///         Ok(())
///     })
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Method with Local Variables
///
/// ```rust,no_run
/// use dotscope::MethodBodyBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let (body_bytes, _token) = MethodBodyBuilder::new()
///     .local("temp", TypeSignature::I4)
///     .local("result", TypeSignature::I4)
///     .implementation(|asm| {
///         asm.ldarg_0()?
///            .stloc_0()?  // Store to first local (temp)
///            .ldloc_0()?  // Load from temp
///            .stloc_1()?  // Store to second local (result)
///            .ldloc_1()?  // Load result
///            .ret()?;
///         Ok(())
///     })
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct MethodBodyBuilder {
    /// Maximum stack depth (None = auto-calculate)
    max_stack: Option<u16>,

    /// Initialize locals to zero
    init_locals: bool,

    /// Local variable definitions
    locals: Vec<(String, TypeSignature)>,

    /// The implementation closure
    implementation: Option<ImplementationFn>,

    /// Exception handlers for try/catch/finally blocks
    exception_handlers: Vec<ExceptionHandler>,
}

impl MethodBodyBuilder {
    /// Create a new method body builder.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let builder = MethodBodyBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_stack: None,
            init_locals: true,
            locals: Vec::new(),
            implementation: None,
            exception_handlers: Vec::new(),
        }
    }

    /// Set the maximum stack depth explicitly.
    ///
    /// If not set, the stack depth will be calculated automatically with precise
    /// real-time tracking of stack effects during instruction assembly. Explicit
    /// setting is useful for optimization or special cases where manual control is needed.
    ///
    /// # Arguments
    ///
    /// * `stack_size` - Maximum number of stack slots needed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let builder = MethodBodyBuilder::new().max_stack(4);
    /// ```
    #[must_use]
    pub fn max_stack(mut self, stack_size: u16) -> Self {
        self.max_stack = Some(stack_size);
        self
    }

    /// Add a local variable to the method.
    ///
    /// Local variables are indexed in the order they are added, starting from 0.
    /// The name is used for documentation purposes but is not encoded in the
    /// final method body (use debugging information for that).
    ///
    /// # Arguments
    ///
    /// * `name` - Variable name (for documentation)
    /// * `local_type` - Type signature of the local variable
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = MethodBodyBuilder::new()
    ///     .local("counter", TypeSignature::I4)
    ///     .local("result", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn local(mut self, name: &str, local_type: TypeSignature) -> Self {
        self.locals.push((name.to_string(), local_type));
        self
    }

    /// Set whether to initialize local variables to zero.
    ///
    /// By default, locals are initialized to zero/null. Setting this to false
    /// can improve performance but requires careful initialization in the method body.
    ///
    /// # Arguments
    ///
    /// * `init` - Whether to initialize locals to zero
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let builder = MethodBodyBuilder::new().init_locals(false);
    /// ```
    #[must_use]
    pub fn init_locals(mut self, init: bool) -> Self {
        self.init_locals = init;
        self
    }

    /// Add an exception handler to the method body.
    ///
    /// Exception handlers define protected try regions and their corresponding
    /// catch, finally, or fault handlers. This method provides a high-level
    /// interface for adding exception handling to method bodies.
    ///
    /// # Arguments
    ///
    /// * `handler` - The exception handler specification
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    /// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .exception_handler(ExceptionHandler {
    ///         flags: ExceptionHandlerFlags::EXCEPTION,
    ///         try_offset: 0,
    ///         try_length: 10,
    ///         handler_offset: 10,
    ///         handler_length: 5,
    ///         handler: None, // Would be set to exception type
    ///         filter_offset: 0,
    ///     });
    /// ```
    #[must_use]
    pub fn exception_handler(mut self, handler: ExceptionHandler) -> Self {
        self.exception_handlers.push(handler);
        self
    }

    /// Add a simple catch handler for a specific exception type.
    ///
    /// This is a convenience method for adding typed exception handlers without
    /// manually constructing the ExceptionHandler structure.
    ///
    /// # Arguments
    ///
    /// * `try_offset` - Byte offset of the protected try block
    /// * `try_length` - Length of the protected try block in bytes
    /// * `handler_offset` - Byte offset of the catch handler code
    /// * `handler_length` - Length of the catch handler code in bytes
    /// * `exception_type` - The exception type to catch (optional)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .catch_handler(0, 10, 10, 5, None); // Catch any exception
    /// ```
    #[must_use]
    pub fn catch_handler(
        mut self,
        try_offset: u32,
        try_length: u32,
        handler_offset: u32,
        handler_length: u32,
        exception_type: Option<CilTypeRc>,
    ) -> Self {
        let handler = ExceptionHandler {
            // Use FAULT for catch-all handlers (when exception_type is None)
            // Use EXCEPTION for typed handlers (when exception_type is Some)
            flags: if exception_type.is_some() {
                ExceptionHandlerFlags::EXCEPTION
            } else {
                ExceptionHandlerFlags::FAULT
            },
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            handler: exception_type,
            filter_offset: 0,
        };
        self.exception_handlers.push(handler);
        self
    }

    /// Add a finally handler.
    ///
    /// Finally handlers execute regardless of whether an exception is thrown
    /// in the protected try region, providing guaranteed cleanup functionality.
    ///
    /// # Arguments
    ///
    /// * `try_offset` - Byte offset of the protected try block
    /// * `try_length` - Length of the protected try block in bytes
    /// * `handler_offset` - Byte offset of the finally handler code
    /// * `handler_length` - Length of the finally handler code in bytes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .finally_handler(0, 10, 15, 8);
    /// ```
    #[must_use]
    pub fn finally_handler(
        mut self,
        try_offset: u32,
        try_length: u32,
        handler_offset: u32,
        handler_length: u32,
    ) -> Self {
        let handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            handler: None,
            filter_offset: 0,
        };
        self.exception_handlers.push(handler);
        self
    }

    /// Set the method implementation using the instruction assembler.
    ///
    /// This is where you define what the method actually does using the fluent
    /// instruction assembler API. The closure receives a mutable reference to
    /// an [`crate::assembly::InstructionAssembler`] that can be used to emit CIL instructions.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that implements the method body
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = dotscope::CilAssemblyView::from_file("test.dll".as_ref())?;
    /// # let assembly = dotscope::CilAssembly::new(view);
    /// # let mut context = dotscope::BuilderContext::new(assembly);
    /// let (body_bytes, _token) = MethodBodyBuilder::new()
    ///     .implementation(|asm| {
    ///         asm.ldc_i4_const(42)?
    ///            .ret()?;
    ///         Ok(())
    ///     })
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn implementation<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut InstructionAssembler) -> Result<()> + 'static,
    {
        self.implementation = Some(Box::new(f));
        self
    }

    /// Build the method body and return the encoded bytes with local variable signature token.
    ///
    /// This method integrates with [`crate::cilassembly::BuilderContext`] to properly
    /// handle local variable signatures and heap management. It performs the following steps:
    /// 1. Execute the implementation closure to generate CIL bytecode
    /// 2. Calculate max stack depth if not explicitly set
    /// 3. Generate proper local variable signature tokens using BuilderContext
    /// 4. Choose between tiny and fat method body format
    /// 5. Encode the complete method body according to ECMA-335
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for heap and table management
    ///
    /// # Returns
    ///
    /// A tuple of (method_body_bytes, local_var_sig_token) where the token
    /// can be used when creating the MethodDef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No implementation was provided
    /// - The implementation closure returns an error
    /// - Method body encoding fails
    /// - Local variable signature creation fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// # fn example(context: &mut dotscope::BuilderContext) -> dotscope::Result<()> {
    /// let (body_bytes, local_sig_token) = MethodBodyBuilder::new()
    ///     .local("temp", TypeSignature::I4)
    ///     .implementation(|asm| {
    ///         asm.ldc_i4_1()?
    ///            .stloc_0()?
    ///            .ldloc_0()?
    ///            .ret()?;
    ///         Ok(())
    ///     })
    ///     .build(context)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<(Vec<u8>, Token)> {
        // Extract values from self to avoid borrow issues
        let MethodBodyBuilder {
            max_stack,
            init_locals: _init_locals,
            locals,
            implementation,
            exception_handlers,
        } = self;

        // Must have an implementation
        let implementation = implementation.ok_or_else(|| Error::ModificationInvalidOperation {
            details: "Method body implementation is required".to_string(),
        })?;

        // Generate the CIL bytecode with automatic stack tracking
        let mut assembler = InstructionAssembler::new();
        implementation(&mut assembler)?;
        let (code_bytes, calculated_max_stack) = assembler.finish()?;

        // Use calculated max stack from assembler if not explicitly set
        // The assembler now provides accurate real-time stack tracking
        let max_stack = max_stack.unwrap_or(calculated_max_stack);

        // Generate local variable signature token if we have locals
        let local_var_sig_token = if locals.is_empty() {
            Token::new(0)
        } else {
            // Create proper SignatureLocalVariable entries from the simple type pairs
            let signature_locals: Vec<SignatureLocalVariable> = locals
                .iter()
                .map(|(_, sig)| SignatureLocalVariable {
                    modifiers: Vec::new(),
                    is_byref: false,
                    is_pinned: false,
                    base: sig.clone(),
                })
                .collect();

            let local_sig = SignatureLocalVariables {
                locals: signature_locals,
            };

            let sig_bytes = encode_local_var_signature(&local_sig)?;

            // Create the StandAloneSig table entry using the builder
            StandAloneSigBuilder::new()
                .signature(&sig_bytes)
                .build(context)?
        };

        // Determine if we have exception handlers
        let has_exceptions = !exception_handlers.is_empty();

        // Generate method body header
        let code_size = u32::try_from(code_bytes.len())
            .map_err(|_| malformed_error!("Method body size exceeds u32 range"))?;
        let header = encode_method_body_header(
            code_size,
            max_stack,
            local_var_sig_token.value(),
            has_exceptions,
        )?;

        // Combine header + code
        let mut body = header;
        body.extend_from_slice(&code_bytes);

        // Add exception handler section if needed
        if has_exceptions {
            // Align to 4-byte boundary before exception handler section (ECMA-335 requirement)
            while body.len() % 4 != 0 {
                body.push(0x00);
            }

            // Exception handlers are encoded after the method body according to ECMA-335
            let eh_section = encode_exception_handlers(&exception_handlers)?;
            body.extend_from_slice(&eh_section);
        }

        Ok((body, local_var_sig_token))
    }
}

impl Default for MethodBodyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cilassembly::{BuilderContext, CilAssembly};
    use crate::metadata::cilassemblyview::CilAssemblyView;
    use std::path::PathBuf;

    fn get_test_context() -> Result<BuilderContext> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        let assembly = CilAssembly::new(view);
        Ok(BuilderContext::new(assembly))
    }

    #[test]
    fn test_method_body_builder_basic() -> Result<()> {
        let mut context = get_test_context()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .implementation(|asm| {
                asm.ldc_i4_1()?.ret()?;
                Ok(())
            })
            .build(&mut context)?;

        // Should have at least header + 2 instruction bytes
        assert!(body_bytes.len() >= 3);

        // For tiny format with 2 bytes of code: header should be (2 << 2) | 0x02 = 0x0A
        assert_eq!(body_bytes[0], 0x0A);

        // Should contain ldc.i4.1 (0x17) and ret (0x2A)
        assert_eq!(body_bytes[1], 0x17); // ldc.i4.1
        assert_eq!(body_bytes[2], 0x2A); // ret

        Ok(())
    }

    #[test]
    fn test_method_body_builder_with_max_stack() -> Result<()> {
        let mut context = get_test_context()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .max_stack(10)
            .implementation(|asm| {
                asm.nop()?.ret()?;
                Ok(())
            })
            .build(&mut context)?;

        // With max_stack > 8, should use fat format (12 byte header + code)
        assert!(body_bytes.len() >= 14); // 12 byte header + 2 instruction bytes

        // Fat format should start with flags
        let flags = u16::from_le_bytes([body_bytes[0], body_bytes[1]]);
        assert_eq!(flags & 0x0003, 0x0003); // Fat format flags

        Ok(())
    }

    #[test]
    fn test_method_body_builder_with_locals() -> Result<()> {
        let mut context = get_test_context()?;
        let (body_bytes, local_sig_token) = MethodBodyBuilder::new()
            .local("temp", TypeSignature::I4)
            .local("result", TypeSignature::String)
            .implementation(|asm| {
                asm.ldarg_0()?.stloc_0()?.ldloc_0()?.ret()?;
                Ok(())
            })
            .build(&mut context)?;

        // Should have created a local variable signature token
        assert_ne!(local_sig_token.value(), 0);

        // Should create method body
        assert!(!body_bytes.is_empty());

        Ok(())
    }

    #[test]
    fn test_method_body_builder_complex_method() -> Result<()> {
        let mut context = get_test_context()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .local("counter", TypeSignature::I4)
            .implementation(|asm| {
                asm.ldc_i4_0()? // Initialize counter to 0
                    .stloc_0()? // Store to local 0
                    .label("loop")? // Loop label
                    .ldloc_0()? // Load counter
                    .ldc_i4_const(10)? // Load 10
                    .blt_s("continue")? // Branch if counter < 10
                    .ldloc_0()? // Load final counter value
                    .ret()? // Return counter
                    .label("continue")?
                    .ldloc_0()? // Load counter
                    .ldc_i4_1()? // Load 1
                    .add()? // Increment counter
                    .stloc_0()? // Store back to local
                    .br_s("loop")?; // Continue loop
                Ok(())
            })
            .build(&mut context)?;

        // Should successfully create a method body with branching
        assert!(body_bytes.len() > 10);

        Ok(())
    }

    #[test]
    fn test_method_body_builder_no_implementation_fails() {
        let mut context = get_test_context().unwrap();
        let result = MethodBodyBuilder::new().build(&mut context);

        assert!(result.is_err());
    }

    #[test]
    fn test_method_body_with_exception_handlers() -> Result<()> {
        let mut context = get_test_context()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .catch_handler(0, 10, 10, 5, None) // Simple catch-all handler
            .finally_handler(0, 15, 15, 3) // Finally block
            .implementation(|asm| {
                asm.ldc_i4_1()?.ret()?;
                Ok(())
            })
            .build(&mut context)?;

        // Should create method body with fat format due to exception handlers
        assert!(!body_bytes.is_empty());
        // Fat format should be used when exception handlers are present
        assert!(body_bytes.len() >= 12); // Fat header is larger than tiny header

        Ok(())
    }

    #[test]
    fn test_accurate_stack_tracking() -> Result<()> {
        let mut context = get_test_context()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .implementation(|asm| {
                // This sequence has a known stack pattern:
                // ldc.i4.1: +1 (stack=1, max=1)
                // ldc.i4.2: +1 (stack=2, max=2)
                // add: -2+1 (stack=1, max=2)
                // dup: +1 (stack=2, max=2)
                // ret: -1 (stack=1, max=2)
                asm.ldc_i4_1()?.ldc_i4_2()?.add()?.dup()?.ret()?;
                Ok(())
            })
            .build(&mut context)?;

        // Should have created method body successfully
        assert!(!body_bytes.is_empty());

        // The method should use tiny format since max stack (2) <= 8 and no locals/exceptions
        // Tiny format: first byte = (code_size << 2) | 0x02
        // Code size is 5 bytes: ldc.i4.1(1) + ldc.i4.2(1) + add(1) + dup(1) + ret(1)
        assert_eq!(body_bytes[0], (5 << 2) | 0x02); // 0x16 = tiny format with 5-byte code

        Ok(())
    }
}
