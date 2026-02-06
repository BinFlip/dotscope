//! CIL instruction emission helpers.
//!
//! This module provides low-level functions for emitting CIL instructions with
//! proper encoding. These helpers select the most compact instruction encoding
//! based on operand values (e.g., using `ldarg.0` instead of `ldarg 0`).
//!
//! # Instruction Categories
//!
//! The emitters are organized by category:
//!
//! - **Load/Store Arguments**: `emit_ldarg`, `emit_starg`, `emit_ldarga`
//! - **Load/Store Locals**: `emit_ldloc`, `emit_stloc`, `emit_ldloca`
//! - **Constants**: `emit_ldc_i4`
//! - **Conversions**: `emit_conv`
//! - **Array Access**: `emit_ldelem`, `emit_stelem`
//! - **Indirect Access**: `emit_ldind`, `emit_stind`
//!
//! # Encoding Optimization
//!
//! Each emitter selects the most compact instruction encoding:
//!
//! ```text
//! ldarg.0, ldarg.1, ldarg.2, ldarg.3  (1 byte)
//! ldarg.s <uint8>                      (2 bytes)
//! ldarg <uint16>                       (4 bytes)
//! ```

use crate::{
    analysis::SsaType,
    assembly::{Immediate, InstructionEncoder, Operand},
    Result,
};

/// Emits an optimized ldc.i4 instruction for a 32-bit integer value.
///
/// Uses the most compact encoding possible:
/// - ldc.i4.m1 through ldc.i4.8 for values -1 to 8
/// - ldc.i4.s for values in -128..127
/// - ldc.i4 for all other values
///
/// # Examples
///
/// ```rust,ignore
/// // Emits ldc.i4.0 (1 byte)
/// emit_ldc_i4(&mut encoder, 0)?;
///
/// // Emits ldc.i4.s 42 (2 bytes)
/// emit_ldc_i4(&mut encoder, 42)?;
///
/// // Emits ldc.i4 1000000 (5 bytes)
/// emit_ldc_i4(&mut encoder, 1_000_000)?;
/// ```
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for ldc.i4.s encoding
pub fn emit_ldc_i4(encoder: &mut InstructionEncoder, v: i32) -> Result<()> {
    match v {
        -1 => encoder.emit_instruction("ldc.i4.m1", None)?,
        0 => encoder.emit_instruction("ldc.i4.0", None)?,
        1 => encoder.emit_instruction("ldc.i4.1", None)?,
        2 => encoder.emit_instruction("ldc.i4.2", None)?,
        3 => encoder.emit_instruction("ldc.i4.3", None)?,
        4 => encoder.emit_instruction("ldc.i4.4", None)?,
        5 => encoder.emit_instruction("ldc.i4.5", None)?,
        6 => encoder.emit_instruction("ldc.i4.6", None)?,
        7 => encoder.emit_instruction("ldc.i4.7", None)?,
        8 => encoder.emit_instruction("ldc.i4.8", None)?,
        x if (-128..=127).contains(&x) => {
            encoder.emit_instruction(
                "ldc.i4.s",
                Some(Operand::Immediate(Immediate::Int8(x as i8))),
            )?;
        }
        x => {
            encoder.emit_instruction("ldc.i4", Some(Operand::Immediate(Immediate::Int32(x))))?;
        }
    }
    Ok(())
}

/// Emits a ldarg instruction with optimal encoding.
///
/// - ldarg.0 through ldarg.3 for indices 0-3 (1 byte)
/// - ldarg.s for indices 4-255 (2 bytes)
/// - ldarg for indices 256+ (4 bytes)
pub fn emit_ldarg(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    match index {
        0 => encoder.emit_instruction("ldarg.0", None)?,
        1 => encoder.emit_instruction("ldarg.1", None)?,
        2 => encoder.emit_instruction("ldarg.2", None)?,
        3 => encoder.emit_instruction("ldarg.3", None)?,
        x if x <= 255 => {
            #[allow(clippy::cast_possible_truncation)]
            let short_idx = x as u8;
            encoder.emit_instruction(
                "ldarg.s",
                Some(Operand::Immediate(Immediate::UInt8(short_idx))),
            )?;
        }
        x => {
            #[allow(clippy::cast_possible_wrap)]
            let signed_idx = x as i16;
            encoder.emit_instruction(
                "ldarg",
                Some(Operand::Immediate(Immediate::Int16(signed_idx))),
            )?;
        }
    }
    Ok(())
}

/// Emits a ldloc instruction with optimal encoding.
///
/// - ldloc.0 through ldloc.3 for indices 0-3 (1 byte)
/// - ldloc.s for indices 4-255 (2 bytes)
/// - ldloc for indices 256+ (4 bytes)
pub fn emit_ldloc(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    match index {
        0 => encoder.emit_instruction("ldloc.0", None)?,
        1 => encoder.emit_instruction("ldloc.1", None)?,
        2 => encoder.emit_instruction("ldloc.2", None)?,
        3 => encoder.emit_instruction("ldloc.3", None)?,
        x if x <= 255 => {
            #[allow(clippy::cast_possible_truncation)]
            let short_idx = x as u8;
            encoder.emit_instruction(
                "ldloc.s",
                Some(Operand::Immediate(Immediate::UInt8(short_idx))),
            )?;
        }
        x => {
            #[allow(clippy::cast_possible_wrap)]
            let signed_idx = x as i16;
            encoder.emit_instruction(
                "ldloc",
                Some(Operand::Immediate(Immediate::Int16(signed_idx))),
            )?;
        }
    }
    Ok(())
}

/// Emits a starg instruction with optimal encoding.
///
/// - starg.s for indices 0-255 (2 bytes)
/// - starg for indices 256+ (4 bytes)
pub fn emit_starg(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    if index <= 255 {
        #[allow(clippy::cast_possible_truncation)]
        let short_idx = index as u8;
        encoder.emit_instruction(
            "starg.s",
            Some(Operand::Immediate(Immediate::UInt8(short_idx))),
        )?;
    } else {
        #[allow(clippy::cast_possible_wrap)]
        let signed_idx = index as i16;
        encoder.emit_instruction(
            "starg",
            Some(Operand::Immediate(Immediate::Int16(signed_idx))),
        )?;
    }
    Ok(())
}

/// Emits a stloc instruction with optimal encoding.
///
/// - stloc.0 through stloc.3 for indices 0-3 (1 byte)
/// - stloc.s for indices 4-255 (2 bytes)
/// - stloc for indices 256+ (4 bytes)
pub fn emit_stloc(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    match index {
        0 => encoder.emit_instruction("stloc.0", None)?,
        1 => encoder.emit_instruction("stloc.1", None)?,
        2 => encoder.emit_instruction("stloc.2", None)?,
        3 => encoder.emit_instruction("stloc.3", None)?,
        x if x <= 255 => {
            #[allow(clippy::cast_possible_truncation)]
            let short_idx = x as u8;
            encoder.emit_instruction(
                "stloc.s",
                Some(Operand::Immediate(Immediate::UInt8(short_idx))),
            )?;
        }
        x => {
            #[allow(clippy::cast_possible_wrap)]
            let signed_idx = x as i16;
            encoder.emit_instruction(
                "stloc",
                Some(Operand::Immediate(Immediate::Int16(signed_idx))),
            )?;
        }
    }
    Ok(())
}

/// Emits a ldarga instruction with optimal encoding.
///
/// - ldarga.s for indices 0-255 (2 bytes)
/// - ldarga for indices 256+ (4 bytes)
pub fn emit_ldarga(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    if index <= 255 {
        #[allow(clippy::cast_possible_truncation)]
        let short_idx = index as u8;
        encoder.emit_instruction(
            "ldarga.s",
            Some(Operand::Immediate(Immediate::UInt8(short_idx))),
        )?;
    } else {
        #[allow(clippy::cast_possible_wrap)]
        let signed_idx = index as i16;
        encoder.emit_instruction(
            "ldarga",
            Some(Operand::Immediate(Immediate::Int16(signed_idx))),
        )?;
    }
    Ok(())
}

/// Emits a ldloca instruction with optimal encoding.
///
/// - ldloca.s for indices 0-255 (2 bytes)
/// - ldloca for indices 256+ (4 bytes)
pub fn emit_ldloca(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    if index <= 255 {
        #[allow(clippy::cast_possible_truncation)]
        let short_idx = index as u8;
        encoder.emit_instruction(
            "ldloca.s",
            Some(Operand::Immediate(Immediate::UInt8(short_idx))),
        )?;
    } else {
        #[allow(clippy::cast_possible_wrap)]
        let signed_idx = index as i16;
        encoder.emit_instruction(
            "ldloca",
            Some(Operand::Immediate(Immediate::Int16(signed_idx))),
        )?;
    }
    Ok(())
}

/// Emits a conversion instruction based on target type and options.
///
/// # Arguments
///
/// * `target` - The target type to convert to
/// * `overflow_check` - Whether to check for overflow
/// * `unsigned` - Whether the source value is unsigned
///
/// # Instruction Selection
///
/// The function selects from various conv.* instructions:
/// - conv.i1, conv.i2, conv.i4, conv.i8 - signed conversions
/// - conv.u1, conv.u2, conv.u4, conv.u8 - unsigned conversions
/// - conv.r4, conv.r8 - floating point conversions
/// - conv.ovf.* - with overflow checking
/// - conv.ovf.*.un - unsigned source with overflow
pub fn emit_conv(
    encoder: &mut InstructionEncoder,
    target: &SsaType,
    overflow_check: bool,
    unsigned: bool,
) -> Result<()> {
    let instr = match (target, overflow_check, unsigned) {
        (SsaType::I8, false, _) => "conv.i1",
        (SsaType::I16, false, _) => "conv.i2",
        (SsaType::I32, false, _) => "conv.i4",
        (SsaType::I64, false, _) => "conv.i8",
        (SsaType::U8, false, _) => "conv.u1",
        (SsaType::U16, false, _) => "conv.u2",
        (SsaType::U32, false, _) => "conv.u4",
        (SsaType::U64, false, _) => "conv.u8",
        (SsaType::F32, false, _) => "conv.r4",
        (SsaType::F64, false, _) => "conv.r8",
        (SsaType::NativeInt, false, _) => "conv.i",
        (SsaType::NativeUInt, false, _) => "conv.u",
        // With overflow check
        (SsaType::I8, true, false) => "conv.ovf.i1",
        (SsaType::I16, true, false) => "conv.ovf.i2",
        (SsaType::I32, true, false) => "conv.ovf.i4",
        (SsaType::I64, true, false) => "conv.ovf.i8",
        (SsaType::U8, true, false) => "conv.ovf.u1",
        (SsaType::U16, true, false) => "conv.ovf.u2",
        (SsaType::U32, true, false) => "conv.ovf.u4",
        (SsaType::U64, true, false) => "conv.ovf.u8",
        (SsaType::NativeInt, true, false) => "conv.ovf.i",
        (SsaType::NativeUInt, true, false) => "conv.ovf.u",
        // Unsigned with overflow
        (SsaType::I8, true, true) => "conv.ovf.i1.un",
        (SsaType::I16, true, true) => "conv.ovf.i2.un",
        (SsaType::I32, true, true) => "conv.ovf.i4.un",
        (SsaType::I64, true, true) => "conv.ovf.i8.un",
        (SsaType::U8, true, true) => "conv.ovf.u1.un",
        (SsaType::U16, true, true) => "conv.ovf.u2.un",
        (SsaType::U32, true, true) => "conv.ovf.u4.un",
        (SsaType::U64, true, true) => "conv.ovf.u8.un",
        (SsaType::NativeInt, true, true) => "conv.ovf.i.un",
        (SsaType::NativeUInt, true, true) => "conv.ovf.u.un",
        // R.un conversions
        (SsaType::F32 | SsaType::F64, _, true) => "conv.r.un",
        // Other types - no conversion needed or not applicable
        _ => return Ok(()),
    };
    encoder.emit_instruction(instr, None)?;
    Ok(())
}

/// Emits a ldelem instruction based on element type.
///
/// Selects the appropriate ldelem variant:
/// - ldelem.i1, ldelem.i2, ldelem.i4, ldelem.i8 for signed integers
/// - ldelem.u1, ldelem.u2, ldelem.u4 for unsigned integers
/// - ldelem.r4, ldelem.r8 for floats
/// - ldelem.ref for reference types
pub fn emit_ldelem(encoder: &mut InstructionEncoder, elem_type: &SsaType) -> Result<()> {
    let instr = match elem_type {
        SsaType::I8 => "ldelem.i1",
        SsaType::I16 => "ldelem.i2",
        SsaType::I32 => "ldelem.i4",
        SsaType::I64 | SsaType::U64 => "ldelem.i8",
        SsaType::U8 => "ldelem.u1",
        SsaType::U16 => "ldelem.u2",
        SsaType::U32 => "ldelem.u4",
        SsaType::F32 => "ldelem.r4",
        SsaType::F64 => "ldelem.r8",
        SsaType::NativeInt | SsaType::NativeUInt => "ldelem.i",
        _ => "ldelem.ref", // Object, Class, String, and other reference types
    };
    encoder.emit_instruction(instr, None)?;
    Ok(())
}

/// Emits a stelem instruction based on element type.
///
/// Selects the appropriate stelem variant:
/// - stelem.i1, stelem.i2, stelem.i4, stelem.i8 for integers
/// - stelem.r4, stelem.r8 for floats
/// - stelem.ref for reference types
pub fn emit_stelem(encoder: &mut InstructionEncoder, elem_type: &SsaType) -> Result<()> {
    let instr = match elem_type {
        SsaType::I8 | SsaType::U8 => "stelem.i1",
        SsaType::I16 | SsaType::U16 => "stelem.i2",
        SsaType::I32 | SsaType::U32 => "stelem.i4",
        SsaType::I64 | SsaType::U64 => "stelem.i8",
        SsaType::F32 => "stelem.r4",
        SsaType::F64 => "stelem.r8",
        SsaType::NativeInt | SsaType::NativeUInt => "stelem.i",
        _ => "stelem.ref", // Object, Class, String, and other reference types
    };
    encoder.emit_instruction(instr, None)?;
    Ok(())
}

/// Emits a ldind instruction based on value type.
///
/// Selects the appropriate ldind variant for indirect loading:
/// - ldind.i1, ldind.i2, ldind.i4, ldind.i8 for signed integers
/// - ldind.u1, ldind.u2, ldind.u4 for unsigned integers
/// - ldind.r4, ldind.r8 for floats
/// - ldind.ref for reference types
pub fn emit_ldind(encoder: &mut InstructionEncoder, value_type: &SsaType) -> Result<()> {
    let instr = match value_type {
        SsaType::I8 => "ldind.i1",
        SsaType::I16 => "ldind.i2",
        SsaType::I32 => "ldind.i4",
        SsaType::I64 | SsaType::U64 => "ldind.i8",
        SsaType::U8 => "ldind.u1",
        SsaType::U16 => "ldind.u2",
        SsaType::U32 => "ldind.u4",
        SsaType::F32 => "ldind.r4",
        SsaType::F64 => "ldind.r8",
        SsaType::NativeInt | SsaType::NativeUInt => "ldind.i",
        _ => "ldind.ref", // Object, Class, String, and other reference types
    };
    encoder.emit_instruction(instr, None)?;
    Ok(())
}

/// Emits a stind instruction based on value type.
///
/// Selects the appropriate stind variant for indirect storing:
/// - stind.i1, stind.i2, stind.i4, stind.i8 for integers
/// - stind.r4, stind.r8 for floats
/// - stind.ref for reference types
pub fn emit_stind(encoder: &mut InstructionEncoder, value_type: &SsaType) -> Result<()> {
    let instr = match value_type {
        SsaType::I8 | SsaType::U8 => "stind.i1",
        SsaType::I16 | SsaType::U16 => "stind.i2",
        SsaType::I32 | SsaType::U32 => "stind.i4",
        SsaType::I64 | SsaType::U64 => "stind.i8",
        SsaType::F32 => "stind.r4",
        SsaType::F64 => "stind.r8",
        SsaType::NativeInt | SsaType::NativeUInt => "stind.i",
        _ => "stind.ref", // Object, Class, String, and other reference types
    };
    encoder.emit_instruction(instr, None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_ldc_i4_special_values() {
        let mut encoder = InstructionEncoder::new();

        // Test special values -1 to 8
        emit_ldc_i4(&mut encoder, -1).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 1).unwrap();
        emit_ldc_i4(&mut encoder, 8).unwrap();

        // Test short form
        emit_ldc_i4(&mut encoder, 42).unwrap();
        emit_ldc_i4(&mut encoder, -100).unwrap();

        // Test full form
        emit_ldc_i4(&mut encoder, 1000).unwrap();
        emit_ldc_i4(&mut encoder, -1000).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_ldarg_encoding() {
        let mut encoder = InstructionEncoder::new();

        // Short forms
        emit_ldarg(&mut encoder, 0).unwrap();
        emit_ldarg(&mut encoder, 1).unwrap();
        emit_ldarg(&mut encoder, 2).unwrap();
        emit_ldarg(&mut encoder, 3).unwrap();

        // ldarg.s form
        emit_ldarg(&mut encoder, 10).unwrap();

        // Full form
        emit_ldarg(&mut encoder, 300).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_ldloc_encoding() {
        let mut encoder = InstructionEncoder::new();

        // Short forms
        emit_ldloc(&mut encoder, 0).unwrap();
        emit_ldloc(&mut encoder, 3).unwrap();

        // ldloc.s form
        emit_ldloc(&mut encoder, 100).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_stloc_encoding() {
        let mut encoder = InstructionEncoder::new();

        // Push values before storing (stloc pops 1 value)
        emit_ldc_i4(&mut encoder, 1).unwrap();
        emit_stloc(&mut encoder, 0).unwrap();

        emit_ldc_i4(&mut encoder, 2).unwrap();
        emit_stloc(&mut encoder, 3).unwrap();

        // stloc.s form
        emit_ldc_i4(&mut encoder, 3).unwrap();
        emit_stloc(&mut encoder, 100).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_conv_variants() {
        let mut encoder = InstructionEncoder::new();

        // Basic conversions
        emit_conv(&mut encoder, &SsaType::I32, false, false).unwrap();
        emit_conv(&mut encoder, &SsaType::I64, false, false).unwrap();
        emit_conv(&mut encoder, &SsaType::F64, false, false).unwrap();

        // With overflow
        emit_conv(&mut encoder, &SsaType::I32, true, false).unwrap();

        // Unsigned with overflow
        emit_conv(&mut encoder, &SsaType::U32, true, true).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_ldelem_types() {
        let mut encoder = InstructionEncoder::new();

        // ldelem pops 2 (array ref + index), pushes 1
        // Push dummy values (array ref and index) before each ldelem
        emit_ldc_i4(&mut encoder, 0).unwrap(); // dummy array ref
        emit_ldc_i4(&mut encoder, 0).unwrap(); // index
        emit_ldelem(&mut encoder, &SsaType::I8).unwrap();
        encoder.emit_instruction("pop", None).unwrap(); // consume the result

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldelem(&mut encoder, &SsaType::I32).unwrap();
        encoder.emit_instruction("pop", None).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldelem(&mut encoder, &SsaType::F64).unwrap();
        encoder.emit_instruction("pop", None).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldelem(&mut encoder, &SsaType::Object).unwrap();
        encoder.emit_instruction("pop", None).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_stelem_types() {
        let mut encoder = InstructionEncoder::new();

        // stelem pops 3 (array ref + index + value), pushes 0
        emit_ldc_i4(&mut encoder, 0).unwrap(); // array ref
        emit_ldc_i4(&mut encoder, 0).unwrap(); // index
        emit_ldc_i4(&mut encoder, 0).unwrap(); // value
        emit_stelem(&mut encoder, &SsaType::I8).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_stelem(&mut encoder, &SsaType::I32).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_stelem(&mut encoder, &SsaType::Object).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_ldind_types() {
        let mut encoder = InstructionEncoder::new();

        // ldind pops 1 (address), pushes 1
        emit_ldc_i4(&mut encoder, 0).unwrap(); // dummy address
        emit_ldind(&mut encoder, &SsaType::I8).unwrap();
        encoder.emit_instruction("pop", None).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldind(&mut encoder, &SsaType::I32).unwrap();
        encoder.emit_instruction("pop", None).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldind(&mut encoder, &SsaType::Object).unwrap();
        encoder.emit_instruction("pop", None).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_stind_types() {
        let mut encoder = InstructionEncoder::new();

        // stind pops 2 (address + value), pushes 0
        emit_ldc_i4(&mut encoder, 0).unwrap(); // address
        emit_ldc_i4(&mut encoder, 0).unwrap(); // value
        emit_stind(&mut encoder, &SsaType::I8).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_stind(&mut encoder, &SsaType::I32).unwrap();

        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_stind(&mut encoder, &SsaType::Object).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }
}
