//! Method introspection and instruction access for the emulation context.
//!
//! Provides method metadata lookup, instruction retrieval, parameter/return type
//! inspection, and local variable type resolution.

use std::sync::Arc;

use crate::{
    assembly::Instruction,
    emulation::{
        engine::{context::EmulationContext, error::EmulationError},
        exception::ExceptionClause,
    },
    metadata::{method::Method, signatures::TypeSignature, token::Token, typesystem::CilFlavor},
    prelude::ExceptionHandlerFlags,
    Result,
};

impl EmulationContext {
    /// Gets a method by its token.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method token is not found.
    pub fn get_method(&self, token: Token) -> Result<Arc<Method>> {
        self.assembly
            .methods()
            .get(&token)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| EmulationError::MethodNotFound { token }.into())
    }

    /// Gets the instructions for a method.
    ///
    /// Checks synthetic methods first (from `DynamicMethod`/`ILGenerator`),
    /// then falls through to assembly metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no body.
    pub fn get_instructions(&self, method_token: Token) -> Result<Vec<Instruction>> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.instructions.clone());
        }

        let method = self.get_method(method_token)?;

        // Get instructions from the method's blocks
        let instructions: Vec<Instruction> = method.instructions().cloned().collect();
        if instructions.is_empty() && !method.has_body() {
            return Err(EmulationError::MissingMethodBody {
                token: method_token,
            }
            .into());
        }
        Ok(instructions)
    }

    /// Gets the base RVA (address of the first instruction) of a method.
    ///
    /// This is used to convert between absolute RVAs and method-relative offsets.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or has no instructions.
    pub fn get_method_base_rva(&self, method_token: Token) -> Result<u64> {
        let instructions = self.get_instructions(method_token)?;
        instructions.first().map(|instr| instr.rva).ok_or_else(|| {
            EmulationError::MissingMethodBody {
                token: method_token,
            }
            .into()
        })
    }

    /// Converts an absolute RVA to a method-relative offset.
    ///
    /// Branch targets in CIL are stored as absolute RVAs, but the instruction
    /// pointer uses method-relative offsets. This function converts between them.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found.
    /// Method-relative offsets are bounded by IL method body size (< u32::MAX)
    #[allow(clippy::cast_possible_truncation)]
    pub fn rva_to_method_offset(&self, method_token: Token, rva: u64) -> Result<u32> {
        let base_rva = self.get_method_base_rva(method_token)?;
        let offset = rva.saturating_sub(base_rva);
        Ok(offset as u32)
    }

    /// Gets an instruction at a specific method-relative offset.
    ///
    /// The offset is relative to the start of the method's IL code (0 = first instruction).
    /// This is the offset used by CIL branch instructions and the instruction pointer.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or no instruction exists at the offset.
    pub fn get_instruction_at(&self, method_token: Token, offset: u32) -> Result<Instruction> {
        let instructions = self.get_instructions(method_token)?;

        // Get the base RVA to compute method-relative offsets from RVAs
        // Branch targets are stored as absolute RVAs and converted to method offsets
        // using rva_to_method_offset(target_rva - base_rva), so we need to match
        // instructions by their RVA-based offset, not accumulated instruction sizes
        let base_rva = instructions
            .first()
            .map(|instr| instr.rva)
            .ok_or(EmulationError::InvalidInstructionPointer { offset })?;

        // Find instruction at the given method-relative offset using RVA
        for instr in instructions {
            let instr_offset = instr.rva.saturating_sub(base_rva);
            if instr_offset == u64::from(offset) {
                return Ok(instr);
            }
        }

        Err(EmulationError::InvalidInstructionPointer { offset }.into())
    }

    /// Gets an instruction by index within a method's instruction list.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found or the index is out of bounds.
    pub fn get_instruction_by_index(
        &self,
        method_token: Token,
        index: usize,
    ) -> Result<Instruction> {
        let instructions = self.get_instructions(method_token)?;

        instructions.into_iter().nth(index).ok_or_else(|| {
            EmulationError::InvalidInstructionPointer {
                offset: u32::try_from(index).unwrap_or(u32::MAX),
            }
            .into()
        })
    }

    /// Gets a user string from the #US heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::UserStringNotFound`] if the string is not found.
    pub fn get_user_string(&self, index: u32) -> Result<String> {
        let userstrings = self
            .assembly
            .userstrings()
            .ok_or(EmulationError::UserStringNotFound { index })?;

        let idx =
            usize::try_from(index).map_err(|_| EmulationError::UserStringNotFound { index })?;

        let string_data = userstrings
            .get(idx)
            .map_err(|_| EmulationError::UserStringNotFound { index })?;

        Ok(string_data.to_string_lossy())
    }

    /// Gets the local variable types for a method.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    /// Returns [`EmulationError::TypeNotFound`] if a local variable's type reference is dead.
    pub fn get_local_types(&self, method_token: Token) -> Result<Vec<CilFlavor>> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.local_types.clone());
        }

        let method = self.get_method(method_token)?;

        // Get locals from the method's local_vars field
        // boxcar::Vec iter returns (index, &value) tuples
        let mut locals = Vec::new();
        for (index, local) in method.local_vars.iter() {
            let Ok(idx) = u16::try_from(index) else {
                continue; // Skip locals with index > u16::MAX
            };

            // Resolve the type from the CilTypeRef
            let cil_flavor = match local.base.upgrade() {
                Some(cil_type) => cil_type.flavor().clone(),
                None => {
                    // Type reference is dead - this is an error condition
                    return Err(EmulationError::TypeNotFound {
                        method_token,
                        local_index: idx,
                    }
                    .into());
                }
            };

            locals.push(cil_flavor);
        }

        Ok(locals)
    }

    /// Checks if a method returns a value (non-void).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn method_returns_value(&self, method_token: Token) -> Result<bool> {
        if let Some(body) = self.synthetic_methods.get(&method_token) {
            return Ok(body.returns_value);
        }

        let method = self.get_method(method_token)?;

        // Check the return type from the method signature (it's in .base field)
        Ok(!matches!(
            method.signature.return_type.base,
            TypeSignature::Void
        ))
    }

    /// Gets the return type of a method as a CilFlavor.
    ///
    /// Returns `None` if the method returns void.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_return_type(&self, method_token: Token) -> Result<Option<CilFlavor>> {
        let method = self.get_method(method_token)?;

        if matches!(method.signature.return_type.base, TypeSignature::Void) {
            Ok(None)
        } else {
            Ok(Some(CilFlavor::from(&method.signature.return_type.base)))
        }
    }

    /// Gets the parameter types for a method as CilFlavors.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_parameter_types(&self, method_token: Token) -> Result<Vec<CilFlavor>> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.param_types.clone());
        }

        let method = self.get_method(method_token)?;

        Ok(method
            .signature
            .params
            .iter()
            .map(|param| CilFlavor::from(&param.base))
            .collect())
    }

    /// Gets the maximum stack size for a method.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is not found, has no body, or has invalid metadata.
    pub fn get_max_stack(&self, method_token: Token) -> Result<u16> {
        // Synthetic methods: use a generous default
        if self.synthetic_methods.contains_key(&method_token) {
            return Ok(16);
        }

        let method = self.get_method(method_token)?;

        let body = method.body.get().ok_or(EmulationError::MissingMethodBody {
            token: method_token,
        })?;

        u16::try_from(body.max_stack).map_err(|_| {
            EmulationError::InvalidMethodMetadata {
                token: method_token,
                reason: "max_stack exceeds u16::MAX",
            }
            .into()
        })
    }

    /// Gets the parameter count for a method.
    ///
    /// Uses the method signature blob (authoritative source) rather than the Param
    /// table, which may have fewer entries than the actual parameter count.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn get_parameter_count(&self, method_token: Token) -> Result<usize> {
        let method = self.get_method(method_token)?;
        Ok(method.signature.params.len())
    }

    /// Checks if a method is static.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::MethodNotFound`] if the method is not found.
    pub fn is_static_method(&self, method_token: Token) -> Result<bool> {
        // Check synthetic methods first
        if let Some(synthetic) = self.synthetic_methods.get(&method_token) {
            return Ok(synthetic.is_static);
        }

        let method = self.get_method(method_token)?;
        Ok(method.is_static())
    }

    /// Converts exception handlers from metadata format to emulation format.
    pub(crate) fn convert_exception_handlers(
        &self,
        method_token: Token,
    ) -> Result<Vec<ExceptionClause>> {
        let method = self.get_method(method_token)?;
        let body = method.body.get().ok_or(EmulationError::MissingMethodBody {
            token: method_token,
        })?;

        let mut clauses = Vec::new();
        for handler in &body.exception_handlers {
            let clause = if handler.flags == ExceptionHandlerFlags::EXCEPTION {
                // Catch clause - get the type token from the handler field
                let catch_type = handler
                    .handler
                    .as_ref()
                    .map_or_else(|| Token::new(handler.filter_offset), |t| t.token);

                ExceptionClause::Catch {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                    catch_type,
                }
            } else if handler.flags == ExceptionHandlerFlags::FILTER {
                ExceptionClause::Filter {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                    filter_offset: handler.filter_offset,
                }
            } else if handler.flags == ExceptionHandlerFlags::FINALLY {
                ExceptionClause::Finally {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                }
            } else if handler.flags == ExceptionHandlerFlags::FAULT {
                ExceptionClause::Fault {
                    try_offset: handler.try_offset,
                    try_length: handler.try_length,
                    handler_offset: handler.handler_offset,
                    handler_length: handler.handler_length,
                }
            } else {
                // Unknown handler type - skip it
                continue;
            };
            clauses.push(clause);
        }

        Ok(clauses)
    }
}
