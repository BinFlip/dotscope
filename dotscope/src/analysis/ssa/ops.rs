//! Re-export shim — generic SSA ops live in `analyssa::ir::ops`.
//!
//! `referenced_token` is the only CIL-specific method; it lives here as the
//! [`SsaOpCilExt`] extension trait (orphan rule prevents inherent impls on
//! foreign types).

use analyssa::ir::ops::SsaOp as AnalyssaSsaOp;

use crate::{analysis::ssa::target::CilTarget, metadata::token::Token};

// `BinaryOpInfo`/`UnaryOpInfo` aren't re-exported (the original dotscope
// `ops.rs` didn't surface them either; direct callers go through
// `analyssa::ir::ops` if they need them).
pub use analyssa::ir::ops::{BinaryOpKind, CmpKind, UnaryOpKind};

/// CIL-defaulted alias of `analyssa::ir::ops::SsaOp`.
pub type SsaOp<T = CilTarget> = AnalyssaSsaOp<T>;

/// CIL-specific extension methods on `SsaOp<CilTarget>`.
///
/// Import this trait to call `op.referenced_token()` as before.
pub trait SsaOpCilExt {
    /// Returns the metadata token referenced by this operation, if any.
    ///
    /// Extracts the token from operations that reference metadata entities
    /// (methods, fields, types). Used for cleanup operations to identify
    /// which SSA operations reference tokens that are being removed.
    fn referenced_token(&self) -> Option<Token>;
}

impl SsaOpCilExt for AnalyssaSsaOp<CilTarget> {
    fn referenced_token(&self) -> Option<Token> {
        match self {
            AnalyssaSsaOp::Call { method, .. }
            | AnalyssaSsaOp::CallVirt { method, .. }
            | AnalyssaSsaOp::LoadFunctionPtr { method, .. }
            | AnalyssaSsaOp::LoadVirtFunctionPtr { method, .. } => Some(method.token()),
            AnalyssaSsaOp::NewObj { ctor, .. } => Some(ctor.token()),
            AnalyssaSsaOp::LoadField { field, .. }
            | AnalyssaSsaOp::StoreField { field, .. }
            | AnalyssaSsaOp::LoadFieldAddr { field, .. }
            | AnalyssaSsaOp::LoadStaticField { field, .. }
            | AnalyssaSsaOp::StoreStaticField { field, .. }
            | AnalyssaSsaOp::LoadStaticFieldAddr { field, .. } => Some(field.token()),
            AnalyssaSsaOp::Box { value_type, .. }
            | AnalyssaSsaOp::Unbox { value_type, .. }
            | AnalyssaSsaOp::UnboxAny { value_type, .. }
            | AnalyssaSsaOp::InitObj { value_type, .. }
            | AnalyssaSsaOp::SizeOf { value_type, .. }
            | AnalyssaSsaOp::CopyObj { value_type, .. }
            | AnalyssaSsaOp::LoadObj { value_type, .. }
            | AnalyssaSsaOp::StoreObj { value_type, .. } => Some(value_type.token()),
            AnalyssaSsaOp::IsInst { target_type, .. }
            | AnalyssaSsaOp::CastClass { target_type, .. } => Some(target_type.token()),
            AnalyssaSsaOp::NewArr { elem_type, .. }
            | AnalyssaSsaOp::LoadElementAddr { elem_type, .. } => Some(elem_type.token()),
            AnalyssaSsaOp::LoadToken { token, .. } => Some(token.token()),
            AnalyssaSsaOp::Constrained { constraint_type } => Some(constraint_type.token()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::ssa::{
            ops::{BinaryOpKind, UnaryOpKind},
            target::CilTarget,
            types::{FieldRef, MethodRef},
            value::ConstValue as RawConstValue,
            SsaVarId,
        },
        metadata::token::Token,
    };

    // Lock the type parameter to CilTarget for the test module so unit-only
    // variant constructions like `SsaOp::Add { ... }` infer cleanly.
    type SsaOp = super::SsaOp<CilTarget>;
    type ConstValue = RawConstValue<CilTarget>;

    #[test]
    fn test_dest_extraction() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        assert_eq!(op.dest(), Some(dest));

        let op = SsaOp::Jump { target: 1 };
        assert_eq!(op.dest(), None);

        let call_dest = SsaVarId::from_index(3);
        let op = SsaOp::Call {
            dest: Some(call_dest),
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert_eq!(op.dest(), Some(call_dest));

        let op = SsaOp::Call {
            dest: None,
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert_eq!(op.dest(), None);
    }

    #[test]
    fn test_uses_extraction() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        assert_eq!(op.uses(), vec![left, right]);

        let const_dest = SsaVarId::from_index(3);
        let op = SsaOp::Const {
            dest: const_dest,
            value: ConstValue::I32(42),
        };
        assert!(op.uses().is_empty());

        let phi_dest = SsaVarId::from_index(4);
        let phi_op1 = SsaVarId::from_index(5);
        let phi_op2 = SsaVarId::from_index(6);
        let op = SsaOp::Phi {
            dest: phi_dest,
            operands: vec![(0, phi_op1), (1, phi_op2)],
        };
        assert_eq!(op.uses(), vec![phi_op1, phi_op2]);
    }

    #[test]
    fn test_is_terminator() {
        let cond = SsaVarId::from_index(0);
        let exc = SsaVarId::from_index(1);
        let dest = SsaVarId::from_index(2);
        let left = SsaVarId::from_index(3);
        let right = SsaVarId::from_index(4);

        assert!(SsaOp::Jump { target: 1 }.is_terminator());
        assert!(SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2
        }
        .is_terminator());
        assert!(SsaOp::Return { value: None }.is_terminator());
        assert!(SsaOp::Throw { exception: exc }.is_terminator());

        assert!(!SsaOp::Nop.is_terminator());
        assert!(!SsaOp::Add {
            dest,
            left,
            right,
            flags: None
        }
        .is_terminator());
    }

    #[test]
    fn test_is_pure() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        let const_dest = SsaVarId::from_index(3);
        let object = SsaVarId::from_index(4);
        let value = SsaVarId::from_index(5);

        assert!(SsaOp::Add {
            dest,
            left,
            right,
            flags: None
        }
        .is_pure());
        assert!(SsaOp::Const {
            dest: const_dest,
            value: ConstValue::I32(42)
        }
        .is_pure());
        assert!(SsaOp::Nop.is_pure());

        // Not pure: has side effects
        assert!(!SsaOp::StoreField {
            object,
            field: FieldRef::new(Token::new(0x04000001)),
            value
        }
        .is_pure());
        assert!(!SsaOp::Call {
            dest: None,
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![]
        }
        .is_pure());
    }

    #[test]
    fn test_display() {
        let op = SsaOp::Add {
            dest: SsaVarId::from_index(2),
            left: SsaVarId::from_index(0),
            right: SsaVarId::from_index(1),
            flags: None,
        };
        assert_eq!(format!("{op}"), "v2 = add v0, v1");

        let op = SsaOp::Const {
            dest: SsaVarId::from_index(0),
            value: ConstValue::I32(42),
        };
        assert_eq!(format!("{op}"), "v0 = 42");

        let op = SsaOp::Branch {
            condition: SsaVarId::from_index(0),
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(format!("{op}"), "branch v0, B1, B2");

        let op = SsaOp::Phi {
            dest: SsaVarId::from_index(3),
            operands: vec![(0, SsaVarId::from_index(1)), (1, SsaVarId::from_index(2))],
        };
        assert_eq!(format!("{op}"), "v3 = phi(B0: v1, B1: v2)");
    }

    #[test]
    fn test_successors() {
        let cond = SsaVarId::from_index(0);
        let switch_val = SsaVarId::from_index(1);
        let ret_val = SsaVarId::from_index(2);
        let exc = SsaVarId::from_index(3);
        let dest = SsaVarId::from_index(4);
        let left = SsaVarId::from_index(5);
        let right = SsaVarId::from_index(6);

        // Jump has single successor
        let op = SsaOp::Jump { target: 5 };
        assert_eq!(op.successors(), vec![5]);

        // Leave has single successor
        let op = SsaOp::Leave { target: 3 };
        assert_eq!(op.successors(), vec![3]);

        // Branch has two successors
        let op = SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(op.successors(), vec![1, 2]);

        // Switch has multiple successors plus default
        let op = SsaOp::Switch {
            value: switch_val,
            targets: vec![1, 2, 3],
            default: 4,
        };
        assert_eq!(op.successors(), vec![1, 2, 3, 4]);

        // Return has no successors
        let op = SsaOp::Return { value: None };
        assert!(op.successors().is_empty());

        let op = SsaOp::Return {
            value: Some(ret_val),
        };
        assert!(op.successors().is_empty());

        // Throw has no successors
        let op = SsaOp::Throw { exception: exc };
        assert!(op.successors().is_empty());

        // Non-terminators have no successors
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        assert!(op.successors().is_empty());

        let op = SsaOp::Nop;
        assert!(op.successors().is_empty());
    }

    #[test]
    fn test_as_binary_op() {
        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);

        // Add is a binary operation
        let op = SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        let info = op.as_binary_op().expect("Add should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Add);
        assert_eq!(info.dest, dest);
        assert_eq!(info.left, left);
        assert_eq!(info.right, right);
        assert!(!info.unsigned);

        // Div with unsigned
        let op = SsaOp::Div {
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        };
        let info = op.as_binary_op().expect("Div should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Div);
        assert!(info.unsigned);

        // Shl maps value/amount to left/right
        let value = SsaVarId::from_index(3);
        let amount = SsaVarId::from_index(4);
        let op = SsaOp::Shl {
            dest,
            value,
            amount,
            flags: None,
        };
        let info = op.as_binary_op().expect("Shl should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Shl);
        assert_eq!(info.left, value);
        assert_eq!(info.right, amount);

        // Comparison operations
        let op = SsaOp::Clt {
            dest,
            left,
            right,
            unsigned: true,
        };
        let info = op.as_binary_op().expect("Clt should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Clt);
        assert!(info.unsigned);

        // Non-binary operations return None
        assert!(SsaOp::Nop.as_binary_op().is_none());
        assert!(SsaOp::Jump { target: 1 }.as_binary_op().is_none());
        assert!(SsaOp::Neg {
            dest,
            operand: left,
            flags: None,
        }
        .as_binary_op()
        .is_none());
        assert!(SsaOp::Const {
            dest,
            value: ConstValue::I32(42)
        }
        .as_binary_op()
        .is_none());
    }

    #[test]
    fn test_as_unary_op() {
        let dest = SsaVarId::from_index(0);
        let operand = SsaVarId::from_index(1);

        // Neg is a unary operation
        let op = SsaOp::Neg {
            dest,
            operand,
            flags: None,
        };
        let info = op.as_unary_op().expect("Neg should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Neg);
        assert_eq!(info.dest, dest);
        assert_eq!(info.operand, operand);

        // Not is a unary operation
        let op = SsaOp::Not {
            dest,
            operand,
            flags: None,
        };
        let info = op.as_unary_op().expect("Not should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Not);

        // Ckfinite is a unary operation
        let op = SsaOp::Ckfinite { dest, operand };
        let info = op.as_unary_op().expect("Ckfinite should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Ckfinite);

        // Non-unary operations return None
        assert!(SsaOp::Nop.as_unary_op().is_none());
        assert!(SsaOp::Jump { target: 1 }.as_unary_op().is_none());

        let left = SsaVarId::from_index(2);
        let right = SsaVarId::from_index(3);
        assert!(SsaOp::Add {
            dest,
            left,
            right,
            flags: None
        }
        .as_unary_op()
        .is_none());

        assert!(SsaOp::Const {
            dest,
            value: ConstValue::I32(42)
        }
        .as_unary_op()
        .is_none());
    }

    #[test]
    fn test_binary_op_kind_display() {
        assert_eq!(format!("{}", BinaryOpKind::Add), "add");
        assert_eq!(format!("{}", BinaryOpKind::AddOvf), "add.ovf");
        assert_eq!(format!("{}", BinaryOpKind::Ceq), "ceq");
        assert_eq!(format!("{}", BinaryOpKind::Shl), "shl");
    }

    #[test]
    fn test_unary_op_kind_display() {
        assert_eq!(format!("{}", UnaryOpKind::Neg), "neg");
        assert_eq!(format!("{}", UnaryOpKind::Not), "not");
        assert_eq!(format!("{}", UnaryOpKind::Ckfinite), "ckfinite");
    }
}
