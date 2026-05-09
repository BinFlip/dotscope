//! `CilTarget` — the .NET CIL host's concrete impl of `analyssa::Target`.
//!
//! The trait + `MockTarget` live in `analyssa::target`; this file plugs CIL
//! semantics into them and is the only place in dotscope that knows the
//! mapping from `Target` associated types to dotscope's metadata types.
//!
//! Conversion helpers (`cil_convert_const`, `cil_convert_const_checked`,
//! `cil_evaluator_apply_conversion`) live here too so the `Target` impl can
//! delegate without forming an `impl ConstValue<CilTarget>` ↔ `impl Target for
//! CilTarget` cycle.

use analyssa::{ir::value::ConstValue, PointerSize};

#[cfg(feature = "compiler")]
use crate::compiler::CilCapability;
use crate::{
    analysis::ssa::types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef},
    assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior},
    metadata::{method::ExceptionHandlerFlags, signatures::SignatureLocalVariable},
};

// Re-export so existing `crate::analysis::ssa::target::Target` import paths
// in the rest of dotscope continue to resolve. The trait itself lives in
// `analyssa::target`.
pub use analyssa::target::Target;

/// `Target` impl for .NET CIL.
///
/// Instances carry the pointer width chosen at construction (4 for 32-bit
/// hosts, 8 for 64-bit). The associated types alias the existing dotscope
/// metadata types so the rest of the crate continues to compile unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CilTarget {
    ptr_bytes: u32,
}

impl CilTarget {
    /// 64-bit CIL target (8-byte pointers). The default for x86_64 hosts.
    #[must_use]
    pub const fn x64() -> Self {
        Self { ptr_bytes: 8 }
    }

    /// 32-bit CIL target (4-byte pointers).
    #[must_use]
    pub const fn x86() -> Self {
        Self { ptr_bytes: 4 }
    }

    /// Construct a `CilTarget` with an explicit pointer width.
    ///
    /// `ptr_bytes` must be 4 or 8. Other values are accepted but undefined for
    /// pointer-sized type inference downstream.
    #[must_use]
    pub const fn with_ptr_bytes(ptr_bytes: u32) -> Self {
        Self { ptr_bytes }
    }
}

impl Default for CilTarget {
    fn default() -> Self {
        Self::x64()
    }
}

impl Target for CilTarget {
    type TypeRef = TypeRef;
    type MethodRef = MethodRef;
    type FieldRef = FieldRef;
    type SigRef = SigRef;
    type ExceptionKind = ExceptionHandlerFlags;
    type Type = SsaType;
    type OriginalInstruction = Instruction;
    type LocalSignature = SignatureLocalVariable;
    #[cfg(feature = "compiler")]
    type Capability = CilCapability;
    #[cfg(not(feature = "compiler"))]
    type Capability = ();

    fn ptr_bytes(&self) -> u32 {
        self.ptr_bytes
    }

    fn synthetic_instruction() -> Self::OriginalInstruction {
        Instruction {
            rva: 0,
            offset: 0,
            size: 0,
            opcode: 0,
            prefix: 0,
            mnemonic: "synthetic",
            category: InstructionCategory::Misc,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        }
    }

    fn unknown_type() -> Self::Type {
        SsaType::Unknown
    }

    fn is_integer(t: &Self::Type) -> bool {
        t.is_integer()
    }

    fn is_floating(t: &Self::Type) -> bool {
        t.is_float()
    }

    fn is_signed(t: &Self::Type) -> bool {
        matches!(
            t,
            SsaType::I8
                | SsaType::I16
                | SsaType::I32
                | SsaType::I64
                | SsaType::NativeInt
                | SsaType::F32
                | SsaType::F64
        )
    }

    fn is_pointer(t: &Self::Type) -> bool {
        t.is_pointer()
    }

    fn is_reference(t: &Self::Type) -> bool {
        t.is_reference()
    }

    fn is_unknown(t: &Self::Type) -> bool {
        t.is_unknown()
    }

    fn bit_width(t: &Self::Type) -> Option<u32> {
        t.size_bytes().map(|b| b.saturating_mul(8))
    }

    fn instruction_mnemonic(instr: &Self::OriginalInstruction) -> &'static str {
        instr.mnemonic
    }

    fn instruction_rva(instr: &Self::OriginalInstruction) -> u64 {
        instr.rva
    }

    fn is_filter_handler(flags: &Self::ExceptionKind) -> bool {
        *flags == ExceptionHandlerFlags::FILTER
    }

    fn result_type_for_const(value: &ConstValue<Self>) -> Option<Self::Type> {
        Some(match value {
            ConstValue::I8(_) => SsaType::I8,
            ConstValue::I16(_) => SsaType::I16,
            ConstValue::I32(_) => SsaType::I32,
            ConstValue::I64(_) => SsaType::I64,
            ConstValue::U8(_) => SsaType::U8,
            ConstValue::U16(_) => SsaType::U16,
            ConstValue::U32(_) => SsaType::U32,
            ConstValue::U64(_) => SsaType::U64,
            ConstValue::NativeInt(_) => SsaType::NativeInt,
            ConstValue::NativeUInt(_) => SsaType::NativeUInt,
            ConstValue::F32(_) => SsaType::F32,
            ConstValue::F64(_) => SsaType::F64,
            ConstValue::String(_) | ConstValue::DecryptedString(_) => SsaType::String,
            ConstValue::DecryptedArray { .. } => SsaType::Object,
            ConstValue::Null => SsaType::Null,
            ConstValue::True | ConstValue::False => SsaType::Bool,
            ConstValue::Type(_) | ConstValue::MethodHandle(_) | ConstValue::FieldHandle(_) => {
                SsaType::Object
            }
        })
    }

    fn comparison_result_type() -> Option<Self::Type> {
        Some(SsaType::Bool)
    }

    fn arithmetic_result_type() -> Option<Self::Type> {
        Some(SsaType::I32)
    }

    fn native_int_result_type() -> Option<Self::Type> {
        Some(SsaType::NativeInt)
    }

    fn ckfinite_result_type() -> Option<Self::Type> {
        Some(SsaType::F64)
    }

    fn function_ptr_result_type() -> Option<Self::Type> {
        Some(SsaType::NativeInt)
    }

    fn object_result_type() -> Option<Self::Type> {
        Some(SsaType::Object)
    }

    fn value_type_from_ref(r: &Self::TypeRef) -> Option<Self::Type> {
        Some(SsaType::ValueType(*r))
    }

    fn byref_value_type_from_ref(r: &Self::TypeRef) -> Option<Self::Type> {
        Some(SsaType::ByRef(Box::new(SsaType::ValueType(*r))))
    }

    fn byref_class_type_from_ref(r: &Self::TypeRef) -> Option<Self::Type> {
        Some(SsaType::ByRef(Box::new(SsaType::Class(*r))))
    }

    fn convert_const(
        value: &ConstValue<Self>,
        target_type: &Self::Type,
        unsigned_source: bool,
        ptr_bytes: u32,
    ) -> Option<ConstValue<Self>> {
        let ptr_size = if ptr_bytes == 4 {
            PointerSize::Bit32
        } else {
            PointerSize::Bit64
        };
        cil_convert_const(value, target_type, unsigned_source, ptr_size)
    }

    fn convert_const_checked(
        value: &ConstValue<Self>,
        target_type: &Self::Type,
        unsigned_source: bool,
        ptr_bytes: u32,
    ) -> Option<ConstValue<Self>> {
        let ptr_size = if ptr_bytes == 4 {
            PointerSize::Bit32
        } else {
            PointerSize::Bit64
        };
        cil_convert_const_checked(value, target_type, unsigned_source, ptr_size)
    }

    fn evaluate_int_conv(
        value: i64,
        target: &Self::Type,
        unsigned: bool,
        ptr_bytes: u32,
    ) -> Option<ConstValue<Self>> {
        let ptr_size = if ptr_bytes == 4 {
            PointerSize::Bit32
        } else {
            PointerSize::Bit64
        };
        Some(cil_evaluator_apply_conversion(
            value, target, unsigned, ptr_size,
        ))
    }
}

fn cil_convert_const(
    value: &ConstValue<CilTarget>,
    target: &SsaType,
    unsigned_source: bool,
    ptr_size: PointerSize,
) -> Option<ConstValue<CilTarget>> {
    let (signed_val, unsigned_val) = if unsigned_source {
        let u = value.as_u64()?;
        (i64::from_ne_bytes(u.to_ne_bytes()), u)
    } else {
        let s = value.as_i64()?;
        (s, u64::from_ne_bytes(s.to_ne_bytes()))
    };

    #[allow(clippy::cast_possible_truncation)]
    let converted = match target {
        SsaType::I8 => ConstValue::I8(signed_val as i8),
        SsaType::U8 => ConstValue::U8(unsigned_val as u8),
        SsaType::I16 => ConstValue::I16(signed_val as i16),
        SsaType::U16 | SsaType::Char => ConstValue::U16(unsigned_val as u16),
        SsaType::I32 => ConstValue::I32(signed_val as i32),
        SsaType::U32 => ConstValue::U32(unsigned_val as u32),
        SsaType::I64 => ConstValue::I64(signed_val),
        SsaType::U64 => ConstValue::U64(unsigned_val),
        SsaType::NativeInt => ConstValue::NativeInt(signed_val),
        SsaType::NativeUInt => ConstValue::NativeUInt(unsigned_val),
        SsaType::F32 =>
        {
            #[allow(clippy::cast_precision_loss)]
            if unsigned_source {
                ConstValue::F32(unsigned_val as f32)
            } else {
                ConstValue::F32(signed_val as f32)
            }
        }
        SsaType::F64 =>
        {
            #[allow(clippy::cast_precision_loss)]
            if unsigned_source {
                ConstValue::F64(unsigned_val as f64)
            } else {
                ConstValue::F64(signed_val as f64)
            }
        }
        SsaType::Bool => ConstValue::from_bool(signed_val != 0),
        _ => return None,
    };
    Some(converted.mask_native(ptr_size))
}

fn cil_convert_const_checked(
    value: &ConstValue<CilTarget>,
    target: &SsaType,
    unsigned_source: bool,
    ptr_size: PointerSize,
) -> Option<ConstValue<CilTarget>> {
    let (signed_val, unsigned_val) = if unsigned_source {
        let u = value.as_u64()?;
        (i64::from_ne_bytes(u.to_ne_bytes()), u)
    } else {
        let s = value.as_i64()?;
        (s, u64::from_ne_bytes(s.to_ne_bytes()))
    };

    let fits = match target {
        SsaType::I8 => i8::try_from(signed_val).is_ok(),
        SsaType::U8 => u8::try_from(unsigned_val).is_ok() && signed_val >= 0,
        SsaType::I16 => i16::try_from(signed_val).is_ok(),
        SsaType::U16 => u16::try_from(unsigned_val).is_ok() && signed_val >= 0,
        SsaType::I32 => i32::try_from(signed_val).is_ok(),
        SsaType::U32 => u32::try_from(unsigned_val).is_ok() && signed_val >= 0,
        SsaType::I64
        | SsaType::NativeInt
        | SsaType::Bool
        | SsaType::Char
        | SsaType::F32
        | SsaType::F64 => true,
        SsaType::U64 | SsaType::NativeUInt => signed_val >= 0,
        _ => return None,
    };

    if !fits {
        return None;
    }
    cil_convert_const(value, target, unsigned_source, ptr_size)
}

/// CIL-side `evaluate_int_conv` body. Mirrors the legacy
/// `SsaEvaluator::apply_conversion` semantics (raw `as`-casts; `Bool` truncates
/// the low byte rather than booleanizing) so generifying the evaluator does
/// not change behavior.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss
)]
fn cil_evaluator_apply_conversion(
    value: i64,
    target: &SsaType,
    unsigned: bool,
    ptr_size: PointerSize,
) -> ConstValue<CilTarget> {
    match target {
        SsaType::I8 => {
            if unsigned {
                ConstValue::I8((value as u8) as i8)
            } else {
                ConstValue::I8(value as i8)
            }
        }
        SsaType::U8 | SsaType::Bool => ConstValue::U8(value as u8),
        SsaType::I16 => {
            if unsigned {
                ConstValue::I16((value as u16) as i16)
            } else {
                ConstValue::I16(value as i16)
            }
        }
        SsaType::U16 => ConstValue::U16(value as u16),
        SsaType::I32 => {
            if unsigned {
                ConstValue::I32((value as u32) as i32)
            } else {
                ConstValue::I32(value as i32)
            }
        }
        SsaType::U32 => ConstValue::U32(value as u32),
        SsaType::NativeInt => match ptr_size {
            PointerSize::Bit32 => {
                if unsigned {
                    ConstValue::NativeInt(i64::from((value as u32) as i32))
                } else {
                    ConstValue::NativeInt(i64::from(value as i32))
                }
            }
            PointerSize::Bit64 => ConstValue::NativeInt(value),
            PointerSize::Bit8 | PointerSize::Bit16 | PointerSize::Bit128 => {
                ConstValue::NativeInt(value)
            }
        },
        SsaType::NativeUInt => match ptr_size {
            PointerSize::Bit32 => ConstValue::NativeUInt(u64::from(value as u32)),
            PointerSize::Bit64 => ConstValue::NativeUInt(value as u64),
            PointerSize::Bit8 | PointerSize::Bit16 | PointerSize::Bit128 => {
                ConstValue::NativeUInt(value as u64)
            }
        },
        SsaType::U64 => ConstValue::U64(value as u64),
        SsaType::F32 => {
            let float_val = if unsigned {
                (value as u64) as f32
            } else {
                value as f32
            };
            ConstValue::F32(float_val)
        }
        SsaType::F64 => {
            let float_val = if unsigned {
                (value as u64) as f64
            } else {
                value as f64
            };
            ConstValue::F64(float_val)
        }
        _ => ConstValue::I64(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use analyssa::{MockTarget, MockType};

    use crate::analysis::ssa::{
        value::ConstValue, DefSite, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        VariableOrigin,
    };

    #[test]
    fn cil_target_ptr_bytes() {
        assert_eq!(CilTarget::x64().ptr_bytes(), 8);
        assert_eq!(CilTarget::x86().ptr_bytes(), 4);
        assert_eq!(CilTarget::with_ptr_bytes(8).ptr_bytes(), 8);
        assert_eq!(CilTarget::default().ptr_bytes(), 8);
    }

    #[test]
    fn cil_target_type_queries() {
        assert!(CilTarget::is_integer(&SsaType::I32));
        assert!(CilTarget::is_integer(&SsaType::U64));
        assert!(!CilTarget::is_integer(&SsaType::F32));

        assert!(CilTarget::is_floating(&SsaType::F32));
        assert!(CilTarget::is_floating(&SsaType::F64));
        assert!(!CilTarget::is_floating(&SsaType::I32));

        assert!(CilTarget::is_signed(&SsaType::I32));
        assert!(!CilTarget::is_signed(&SsaType::U32));

        assert!(CilTarget::is_pointer(&SsaType::Pointer(Box::new(
            SsaType::I32
        ))));
        assert!(CilTarget::is_pointer(&SsaType::ByRef(Box::new(
            SsaType::I32
        ))));
        assert!(!CilTarget::is_pointer(&SsaType::I32));

        assert!(CilTarget::is_reference(&SsaType::Object));
        assert!(CilTarget::is_reference(&SsaType::String));
        assert!(!CilTarget::is_reference(&SsaType::I32));

        assert!(CilTarget::is_unknown(&SsaType::Unknown));
        assert!(CilTarget::is_unknown(&SsaType::Varying));
        assert!(!CilTarget::is_unknown(&SsaType::I32));

        assert_eq!(CilTarget::bit_width(&SsaType::I32), Some(32));
        assert_eq!(CilTarget::bit_width(&SsaType::I64), Some(64));
        assert_eq!(CilTarget::bit_width(&SsaType::Bool), Some(8));
        assert_eq!(CilTarget::bit_width(&SsaType::NativeInt), None);
    }

    #[test]
    fn cil_target_unknown() {
        assert_eq!(CilTarget::unknown_type(), SsaType::Unknown);
    }

    #[test]
    fn cil_target_synthetic_instruction() {
        let i = CilTarget::synthetic_instruction();
        assert_eq!(i.mnemonic, "synthetic");
        assert_eq!(i.size, 0);
    }

    /// End-to-end IR-core smoke test using `MockTarget`.
    ///
    /// Constructs an `SsaFunction<MockTarget>` end-to-end using the generic
    /// IR API. Lives in dotscope (rather than analyssa) until `SsaFunction`
    /// itself moves to analyssa. Once that happens, this test should migrate
    /// to a analyssa-side integration test.
    #[test]
    fn mock_target_builds_generic_ir() {
        // 1. Empty function with the mock target.
        let mut func = SsaFunction::<MockTarget>::new(1, 1);
        assert_eq!(func.num_args(), 1);
        assert_eq!(func.num_locals(), 1);
        assert!(func.is_empty());

        // 2. Allocate a few variables.
        let arg0 = func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            MockType::I32,
        );
        let const_var = func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            MockType::I32,
        );
        let sum = func.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(0, 1),
            MockType::I32,
        );
        assert_eq!(func.variable_count(), 3);
        assert_eq!(func.variable(arg0).unwrap().var_type(), &MockType::I32);

        // 3. Build a block: const = 42, sum = arg0 + const, return sum.
        let mut block: SsaBlock<MockTarget> = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: const_var,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: sum,
            left: arg0,
            right: const_var,
            flags: None,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(sum),
        }));
        assert_eq!(block.instruction_count(), 3);
        func.add_block(block);

        // 4. Iterate over the function's instructions.
        let instr_dests: Vec<Option<SsaVarId>> = func
            .iter_instructions()
            .map(|(_, _, instr)| instr.def())
            .collect();
        assert_eq!(instr_dests, vec![Some(const_var), Some(sum), None]);

        // 5. Confirm the IR carries `T::Type` values opaquely.
        for var in func.variables() {
            assert!(MockTarget::is_integer(var.var_type()));
        }
    }
}
