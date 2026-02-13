use std::io::{self, Write};

use dotscope::{
    assembly::{FlowType, Immediate, Instruction, Operand},
    metadata::{
        method::{
            ExceptionHandler, ExceptionHandlerFlags, Method, MethodImplCodeType, MethodModifiers,
        },
        token::Token,
        typesystem::{CilType, CilTypeRc},
    },
    CilObject,
};

/// Display options for CIL disassembly output.
pub struct DisasmOptions {
    pub bytes: bool,
    pub tokens: bool,
    pub offsets: bool,
    pub no_header: bool,
    pub raw: bool,
}

/// Formats CIL assembly output in an ildasm-style text format.
pub struct CilFormatter {
    pub opts: DisasmOptions,
}

impl CilFormatter {
    pub fn new(opts: DisasmOptions) -> Self {
        Self { opts }
    }

    /// Write assembly and module header directives.
    pub fn format_header(w: &mut dyn Write, assembly: &CilObject) -> io::Result<()> {
        if let Some(asm) = assembly.assembly() {
            writeln!(w, ".assembly '{}' {{", asm.name)?;
            writeln!(
                w,
                "  .ver {}:{}:{}:{}",
                asm.major_version, asm.minor_version, asm.build_number, asm.revision_number
            )?;
            writeln!(w, "}}")?;
        }
        if let Some(module) = assembly.module() {
            writeln!(w, ".module {}", module.name)?;
        }
        writeln!(w)?;
        Ok(())
    }

    /// Write opening `.class` directive for a type.
    pub fn format_type_begin(w: &mut dyn Write, cil_type: &CilType) -> io::Result<()> {
        let vis = if cil_type.is_public() {
            "public"
        } else {
            "private"
        };

        let kind = cil_type.flavor().as_str();
        let fullname = cil_type.fullname();

        write!(w, ".class {vis} auto ansi")?;

        // Check for interface/abstract/sealed via flavor
        if kind == "interface" {
            write!(w, " interface abstract")?;
        }

        write!(w, " {fullname}")?;

        if let Some(base) = cil_type.base() {
            if base.name != "Object" || base.namespace != "System" {
                write!(w, " extends {}", base.fullname())?;
            }
        }

        writeln!(w)?;
        writeln!(w, "{{")?;
        Ok(())
    }

    /// Write closing brace for a type.
    pub fn format_type_end(w: &mut dyn Write) -> io::Result<()> {
        writeln!(w, "}} // end of class")?;
        writeln!(w)?;
        Ok(())
    }

    /// Write a complete method: header, body, and exception handlers.
    pub fn format_method(
        &self,
        w: &mut dyn Write,
        method: &Method,
        entry_point_token: u32,
        assembly: &CilObject,
    ) -> io::Result<()> {
        if self.opts.raw {
            return self.format_method_body_raw(w, method, assembly);
        }

        Self::format_method_header(w, method)?;
        writeln!(w, "  {{")?;

        if method.token.value() == entry_point_token {
            writeln!(w, "    .entrypoint")?;
        }

        self.format_method_body(w, method, assembly)?;

        writeln!(w, "  }} // end of method {}", method.name)?;
        writeln!(w)?;
        Ok(())
    }

    /// Write the `.method` directive line with all modifiers.
    fn format_method_header(w: &mut dyn Write, method: &Method) -> io::Result<()> {
        write!(w, "  .method {}", method.flags_access)?;

        if method
            .flags_modifiers
            .contains(MethodModifiers::HIDE_BY_SIG)
        {
            write!(w, " hidebysig")?;
        }
        if method.is_static() {
            write!(w, " static")?;
        }
        if method.is_virtual() {
            write!(w, " virtual")?;
        }
        if method.flags_modifiers.contains(MethodModifiers::FINAL) {
            write!(w, " final")?;
        }
        if method.is_abstract() {
            write!(w, " abstract")?;
        }
        if method
            .flags_modifiers
            .contains(MethodModifiers::SPECIAL_NAME)
        {
            write!(w, " specialname")?;
        }
        if method
            .flags_modifiers
            .contains(MethodModifiers::RTSPECIAL_NAME)
        {
            write!(w, " rtspecialname")?;
        }
        if method
            .flags_modifiers
            .contains(MethodModifiers::PINVOKE_IMPL)
        {
            write!(w, " pinvokeimpl")?;
        }

        // Return type
        write!(w, " {} ", method.signature.return_type)?;

        // Method name and params
        write!(w, "{}(", method.name)?;
        for (i, param) in method.signature.params.iter().enumerate() {
            if i > 0 {
                write!(w, ", ")?;
            }
            write!(w, "{param}")?;
        }
        write!(w, ")")?;

        // Code type
        if method.impl_code_type == MethodImplCodeType::IL {
            write!(w, " cil")?;
        } else if method.impl_code_type == MethodImplCodeType::NATIVE {
            write!(w, " native")?;
        } else if method.impl_code_type == MethodImplCodeType::RUNTIME {
            write!(w, " runtime")?;
        }

        if method.is_code_unmanaged() {
            write!(w, " unmanaged")?;
        } else {
            write!(w, " managed")?;
        }

        writeln!(w)?;
        Ok(())
    }

    /// Write method body: maxstack, locals, instructions, exception handlers.
    fn format_method_body(
        &self,
        w: &mut dyn Write,
        method: &Method,
        assembly: &CilObject,
    ) -> io::Result<()> {
        let header_size = if let Some(body) = method.body.get() {
            writeln!(w, "    .maxstack {}", body.max_stack)?;

            Self::format_locals(w, method)?;

            // Exception handler comments before instructions
            if !body.exception_handlers.is_empty() {
                Self::format_exception_handlers(w, &body.exception_handlers)?;
            }

            body.size_header as u64
        } else {
            0
        };

        let code_start_rva = u64::from(method.rva.unwrap_or(0)) + header_size;

        for instruction in method.instructions() {
            self.format_instruction(w, instruction, code_start_rva, assembly)?;
        }

        Ok(())
    }

    /// Write only raw instructions (for --raw flag).
    fn format_method_body_raw(
        &self,
        w: &mut dyn Write,
        method: &Method,
        assembly: &CilObject,
    ) -> io::Result<()> {
        let header_size = method.body.get().map_or(0, |b| b.size_header as u64);
        let code_start_rva = u64::from(method.rva.unwrap_or(0)) + header_size;
        for instruction in method.instructions() {
            self.format_instruction(w, instruction, code_start_rva, assembly)?;
        }
        Ok(())
    }

    /// Write a `.locals` directive.
    fn format_locals(w: &mut dyn Write, method: &Method) -> io::Result<()> {
        if method.local_vars.is_empty() {
            return Ok(());
        }

        let is_init = method.body.get().is_some_and(|b| b.is_init_local);

        if is_init {
            writeln!(w, "    .locals init (")?;
        } else {
            writeln!(w, "    .locals (")?;
        }

        let count = method.local_vars.count();
        for (i, local) in method.local_vars.iter() {
            let type_name = local.base.upgrade().map_or_else(
                || "???".to_string(),
                |t| {
                    let flavor = t.flavor();
                    let s = flavor.as_str();
                    // For non-primitive types, use fullname
                    match s {
                        "class" | "valuetype" | "interface" | "generic" => t.fullname(),
                        _ => s.to_string(),
                    }
                },
            );

            let pinned = if local.is_pinned { " pinned" } else { "" };
            let byref = if local.is_byref { "&" } else { "" };

            let comma = if i < count - 1 { "," } else { "" };
            writeln!(w, "      [{i}] {type_name}{pinned}{byref} V_{i}{comma}")?;
        }

        writeln!(w, "    )")?;
        Ok(())
    }

    /// Write a single instruction line.
    fn format_instruction(
        &self,
        w: &mut dyn Write,
        instruction: &Instruction,
        code_start_rva: u64,
        assembly: &CilObject,
    ) -> io::Result<()> {
        let offset = instruction.rva.saturating_sub(code_start_rva);

        if self.opts.bytes {
            Self::format_instruction_bytes(w, instruction)?;
        }

        if self.opts.offsets {
            write!(w, "    IL_{offset:04x}: ")?;
        } else {
            write!(w, "    ")?;
        }

        write!(w, "{:<12}", instruction.mnemonic)?;

        let operand_str = self.format_operand(instruction, code_start_rva, assembly);
        if !operand_str.is_empty() {
            write!(w, " {operand_str}")?;
        }

        writeln!(w)?;
        Ok(())
    }

    /// Format operand for display.
    fn format_operand(
        &self,
        instruction: &Instruction,
        code_start_rva: u64,
        assembly: &CilObject,
    ) -> String {
        // For branch/leave instructions with computed targets, show IL labels
        let is_branch = matches!(
            instruction.flow_type,
            FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Leave
        );
        if is_branch && !instruction.branch_targets.is_empty() {
            if let Some(&target) = instruction.branch_targets.first() {
                let offset = target.saturating_sub(code_start_rva);
                return format!("IL_{offset:04x}");
            }
        }

        match &instruction.operand {
            Operand::None => String::new(),
            Operand::Immediate(imm) => Self::format_immediate(imm),
            Operand::Target(addr) => {
                let offset = addr.saturating_sub(code_start_rva);
                format!("IL_{offset:04x}")
            }
            Operand::Token(tok) => {
                let resolved = resolve_token(assembly, *tok);
                match resolved {
                    Some(name) if self.opts.tokens => {
                        format!("{name} /* 0x{:08X} */", tok.value())
                    }
                    Some(name) => name,
                    None => format!("(0x{:08X})", tok.value()),
                }
            }
            Operand::Local(idx) => format!("V_{idx}"),
            Operand::Argument(idx) => format!("{idx}"),
            Operand::Switch(offsets) => {
                let labels: Vec<String> = offsets
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        if let Some(target) = instruction.branch_targets.get(i) {
                            let off = target.saturating_sub(code_start_rva);
                            format!("IL_{off:04x}")
                        } else {
                            "???".to_string()
                        }
                    })
                    .collect();
                format!("({})", labels.join(", "))
            }
        }
    }

    /// Format an immediate value for display.
    fn format_immediate(imm: &Immediate) -> String {
        match imm {
            Immediate::Int8(v) => format!("{v}"),
            Immediate::UInt8(v) => format!("{v}"),
            Immediate::Int16(v) => format!("{v}"),
            Immediate::UInt16(v) => format!("{v}"),
            Immediate::Int32(v) => format!("{v}"),
            Immediate::UInt32(v) => format!("{v}"),
            Immediate::Int64(v) => format!("{v}"),
            Immediate::UInt64(v) => format!("{v}"),
            Immediate::Float32(v) => format!("{v}"),
            Immediate::Float64(v) => format!("{v}"),
        }
    }

    /// Format hex bytes of an instruction (for --bytes flag).
    fn format_instruction_bytes(w: &mut dyn Write, instruction: &Instruction) -> io::Result<()> {
        // Reconstruct bytes from instruction metadata
        let mut bytes = Vec::new();

        if instruction.prefix != 0 {
            bytes.push(instruction.prefix);
        }
        bytes.push(instruction.opcode);

        // Add operand bytes based on operand type
        match &instruction.operand {
            Operand::None => {}
            Operand::Immediate(imm) => match imm {
                Immediate::Int8(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::UInt8(v) => bytes.push(*v),
                Immediate::Int16(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::UInt16(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::Int32(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::UInt32(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::Int64(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::UInt64(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::Float32(v) => bytes.extend_from_slice(&v.to_le_bytes()),
                Immediate::Float64(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            },
            Operand::Target(_) => {
                // Target operand size depends on instruction (short vs long branch)
                // CIL instruction sizes are small (max ~10 bytes), truncation is safe
                #[allow(clippy::cast_possible_truncation)]
                let operand_size =
                    instruction.size as usize - if instruction.prefix != 0 { 2 } else { 1 };
                // We don't have original bytes, just show placeholder
                bytes.extend(std::iter::repeat_n(0x00, operand_size));
            }
            Operand::Token(tok) => {
                bytes.extend_from_slice(&tok.value().to_le_bytes());
            }
            Operand::Local(idx) | Operand::Argument(idx) => {
                if instruction.size <= 2 {
                    // CIL short-form instructions use 1 byte for local/argument indices
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        bytes.push(*idx as u8);
                    }
                } else {
                    bytes.extend_from_slice(&idx.to_le_bytes());
                }
            }
            Operand::Switch(offsets) => {
                // CIL switch instruction: count is encoded as u32
                #[allow(clippy::cast_possible_truncation)]
                let count = offsets.len() as u32;
                bytes.extend_from_slice(&count.to_le_bytes());
                for offset in offsets {
                    bytes.extend_from_slice(&offset.to_le_bytes());
                }
            }
        }

        // Format: "/* XX XX XX */ "
        write!(w, "    /* ")?;
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                write!(w, " ")?;
            }
            write!(w, "{b:02X}")?;
        }
        write!(w, " */")?;
        writeln!(w)?;

        Ok(())
    }

    /// Write exception handler region comments.
    fn format_exception_handlers(
        w: &mut dyn Write,
        handlers: &[ExceptionHandler],
    ) -> io::Result<()> {
        for handler in handlers {
            let try_end = handler.try_offset + handler.try_length;
            let handler_end = handler.handler_offset + handler.handler_length;

            match handler.flags {
                ExceptionHandlerFlags::EXCEPTION => {
                    let type_name = exception_type_name(handler.handler.as_ref());
                    writeln!(
                        w,
                        "    // .try IL_{:04x} to IL_{:04x} catch {type_name} handler IL_{:04x} to IL_{:04x}",
                        handler.try_offset, try_end, handler.handler_offset, handler_end
                    )?;
                }
                ExceptionHandlerFlags::FINALLY => {
                    writeln!(
                        w,
                        "    // .try IL_{:04x} to IL_{:04x} finally handler IL_{:04x} to IL_{:04x}",
                        handler.try_offset, try_end, handler.handler_offset, handler_end
                    )?;
                }
                ExceptionHandlerFlags::FAULT => {
                    writeln!(
                        w,
                        "    // .try IL_{:04x} to IL_{:04x} fault handler IL_{:04x} to IL_{:04x}",
                        handler.try_offset, try_end, handler.handler_offset, handler_end
                    )?;
                }
                ExceptionHandlerFlags::FILTER => {
                    writeln!(
                        w,
                        "    // .try IL_{:04x} to IL_{:04x} filter IL_{:04x} handler IL_{:04x} to IL_{:04x}",
                        handler.try_offset, try_end, handler.filter_offset, handler.handler_offset, handler_end
                    )?;
                }
                _ => {
                    writeln!(
                        w,
                        "    // .try IL_{:04x} to IL_{:04x} unknown handler IL_{:04x} to IL_{:04x}",
                        handler.try_offset, try_end, handler.handler_offset, handler_end
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Get a display name for an exception handler's caught type.
fn exception_type_name(handler: Option<&CilTypeRc>) -> String {
    handler.map_or_else(|| "[?]".to_string(), |t| t.fullname())
}

/// Resolve a metadata token to a human-readable name.
fn resolve_token(assembly: &CilObject, token: Token) -> Option<String> {
    match token.table() {
        0x06 => {
            // MethodDef
            assembly
                .methods()
                .get(&token)
                .map(|entry| entry.value().fullname())
        }
        0x0A => {
            // MemberRef
            assembly.member_ref(&token).map(|mref| {
                let class = mref.declaredby.fullname().unwrap_or_default();
                if class.is_empty() {
                    mref.name.clone()
                } else {
                    format!("{}::{}", class, mref.name)
                }
            })
        }
        0x01 | 0x02 => {
            // TypeRef or TypeDef
            assembly.types().get(&token).map(|t| t.fullname())
        }
        0x70 => {
            // UserString
            assembly
                .userstrings()
                .and_then(|us| us.get(token.row() as usize).ok())
                .map(|s| {
                    let s = s.to_string_lossy();
                    if s.len() > 60 {
                        format!("\"{}...\"", &s[..57])
                    } else {
                        format!("\"{s}\"")
                    }
                })
        }
        _ => None,
    }
}
