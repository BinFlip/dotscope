//! CIL instruction representation, operand types, and decoding metadata.
//!
//! This module defines the comprehensive type system for representing decoded CIL instructions
//! and their associated metadata. It provides strongly-typed representations for operands,
//! stack effects, control flow behavior, and instruction categories, enabling sophisticated
//! static analysis and program understanding capabilities.
//!
//! # Architecture
//!
//! The module is organized around the central [`crate::assembly::instruction::Instruction`] struct,
//! which aggregates all information about a decoded instruction. Supporting enums provide
//! type-safe representations for operands, flow control, and instruction classification.
//! The design emphasizes immutability and comprehensive metadata preservation.
//!
//! # Key Components
//!
//! - [`crate::assembly::instruction::Instruction`] - Complete decoded instruction representation
//! - [`crate::assembly::instruction::Operand`] - Type-safe operand representation
//! - [`crate::assembly::instruction::Immediate`] - Immediate value types with conversions
//! - [`crate::assembly::instruction::FlowType`] - Control flow behavior classification
//! - [`crate::assembly::instruction::InstructionCategory`] - Functional instruction grouping
//! - [`crate::assembly::instruction::StackBehavior`] - Stack effect analysis metadata
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::{Instruction, OperandType, Immediate, Operand, FlowType};
//!
//! // Working with operand types and immediates
//! let op_type = OperandType::Int32;
//! let imm = Immediate::Int32(42);
//! let operand = Operand::Immediate(imm);
//!
//! // Convert immediate to u64 for analysis
//! let value: u64 = imm.into();
//! assert_eq!(value, 42);
//!
//! // Check control flow properties
//! let flow = FlowType::ConditionalBranch;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::assembly::decoder`] - Consumes these types during instruction decoding
//! - [`crate::assembly::block`] - Uses instructions to build basic block sequences
//! - [`crate::metadata::token`] - References metadata tokens in operands

use crate::metadata::token::Token;
use std::fmt::{self, UpperHex};

/// Types of operands for CIL instructions.
///
/// This enum defines the different types of operands that CIL instructions can accept.
/// Each variant corresponds to a specific data type and size used in the .NET instruction set.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::OperandType;
///
/// // Different operand types for different instructions
/// let local_operand = OperandType::UInt8;  // ldloc.s takes a byte
/// let branch_operand = OperandType::Int32; // br takes a 4-byte offset
/// let token_operand = OperandType::Token;  // ldtoken takes a metadata token
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`OperandType`] is [`std::marker::Send`] and [`std::marker::Sync`] as it only contains primitive data.
/// All variants are safe to share across threads without synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    /// No operand present
    None,
    /// Signed 8-bit integer
    Int8,
    /// Unsigned 8-bit integer
    UInt8,
    /// Signed 16-bit integer
    Int16,
    /// Unsigned 16-bit integer
    UInt16,
    /// Signed 32-bit integer
    Int32,
    /// Unsigned 32-bit integer
    UInt32,
    /// Signed 64-bit integer
    Int64,
    /// Unsigned 64-bit integer
    UInt64,
    /// 32-bit floating point
    Float32,
    /// 64-bit floating point
    Float64,
    /// Metadata token reference
    Token,
    /// Switch table operand
    Switch,
}

/// Represents an immediate value type embedded in CIL instructions.
///
/// Immediate values are constant values that are encoded directly in the instruction
/// stream. This enum provides a type-safe representation of all possible immediate
/// value types in the CIL instruction set.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::Immediate;
///
/// // Different immediate value types
/// let byte_val = Immediate::UInt8(42);
/// let int_val = Immediate::Int32(-1);
/// let float_val = Immediate::Float64(3.14159);
///
/// // Convert to u64 for analysis
/// let as_u64: u64 = byte_val.into();
/// assert_eq!(as_u64, 42);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`Immediate`] is [`std::marker::Send`] and [`std::marker::Sync`] as it only contains primitive data.
/// All numeric and floating-point values are safe to share across threads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Immediate {
    /// Signed 8-bit immediate value
    Int8(i8),
    /// Unsigned 8-bit immediate value
    UInt8(u8),
    /// Signed 16-bit immediate value
    Int16(i16),
    /// Unsigned 16-bit immediate value
    UInt16(u16),
    /// Signed 32-bit immediate value
    Int32(i32),
    /// Unsigned 32-bit immediate value
    UInt32(u32),
    /// Signed 64-bit immediate value
    Int64(i64),
    /// Unsigned 64-bit immediate value
    UInt64(u64),
    /// 32-bit floating point immediate value
    Float32(f32),
    /// 64-bit floating point immediate value
    Float64(f64),
}

impl UpperHex for Immediate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Immediate::Int8(value) => write!(f, "{value:02X}"),
            Immediate::UInt8(value) => write!(f, "{value:02X}"),
            Immediate::Int16(value) => write!(f, "{value:04X}"),
            Immediate::UInt16(value) => write!(f, "{value:04X}"),
            Immediate::Int32(value) => write!(f, "{value:08X}"),
            Immediate::UInt32(value) => write!(f, "{value:08X}"),
            Immediate::Int64(value) => write!(f, "{value:016X}"),
            Immediate::UInt64(value) => write!(f, "{value:016X}"),
            Immediate::Float32(value) => write!(f, "{:08X}", value.to_bits()),
            Immediate::Float64(value) => write!(f, "{:016X}", value.to_bits()),
        }
    }
}

impl From<Immediate> for u64 {
    fn from(val: Immediate) -> Self {
        match val {
            // For signed integers, we preserve the bit pattern
            #[allow(clippy::cast_sign_loss)]
            Immediate::Int8(value) => value as u64,
            Immediate::UInt8(value) => u64::from(value),
            #[allow(clippy::cast_sign_loss)]
            Immediate::Int16(value) => value as u64,
            Immediate::UInt16(value) => u64::from(value),
            #[allow(clippy::cast_sign_loss)]
            Immediate::Int32(value) => value as u64,
            Immediate::UInt32(value) => u64::from(value),
            #[allow(clippy::cast_sign_loss)]
            Immediate::Int64(value) => value as u64,
            Immediate::UInt64(value) => value,
            Immediate::Float32(value) => u64::from(value.to_bits()),
            Immediate::Float64(value) => value.to_bits(),
        }
    }
}

/// Represents an operand in a more structured way.
///
/// This enum provides a high-level representation of instruction operands after
/// decoding. It abstracts away the raw byte representation and provides typed
/// access to different kinds of operand data.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::{Operand, Immediate};
/// use dotscope::metadata::token::Token;
///
/// // Different operand types
/// let immediate = Operand::Immediate(Immediate::Int32(42));
/// let branch_target = Operand::Target(0x1000);
/// let metadata_ref = Operand::Token(Token::new(0x06000001));
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`Operand`] is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain thread-safe types.
/// This includes primitives, [`crate::assembly::instruction::Immediate`], [`crate::metadata::token::Token`], and [`std::vec::Vec`].
#[derive(Debug, Clone)]
pub enum Operand {
    /// No operand present
    None,
    /// Immediate value (constant embedded in instruction)
    Immediate(Immediate),
    /// Branch target address
    Target(u64),
    /// Metadata token reference     
    Token(Token),
    /// Local variable index
    Local(u16),
    /// Method argument index
    Argument(u16),
    /// Switch table with multiple target addresses
    Switch(Vec<u32>),
}

/// How an instruction affects control flow.
///
/// This enum categorizes instructions based on their control flow behavior,
/// which is essential for building control flow graphs and performing static analysis.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::FlowType;
///
/// // Different flow types
/// let sequential = FlowType::Sequential;      // Normal instructions like add, ldloc
/// let branch = FlowType::ConditionalBranch;   // brtrue, brfalse, etc.
/// let call = FlowType::Call;                  // call, callvirt
/// let ret = FlowType::Return;                 // ret instruction
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`FlowType`] is [`std::marker::Send`] and [`std::marker::Sync`] as it only contains unit variants.
/// All variants are safe to share across threads without synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    /// Normal execution continues to next instruction
    Sequential,
    /// Conditional branch to another location
    ConditionalBranch,
    /// Always branches to another location (unconditional jump)
    UnconditionalBranch,
    /// Call to another method
    Call,
    /// Returns from current method
    Return,
    /// Multi-way branch (switch statement)
    Switch,
    /// Exception throwing
    Throw,
    /// End of finally block
    EndFinally,
    /// Leave protected region (try/catch/finally)
    Leave,
}

/// Stack effect of an instruction.
///
/// Describes how an instruction modifies the evaluation stack. This information
/// is crucial for stack analysis, type inference, and verification.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::StackBehavior;
///
/// // An instruction that pops 2 values and pushes 1 (like 'add')
/// let add_behavior = StackBehavior {
///     pops: 2,
///     pushes: 1,
///     net_effect: -1,
/// };
///
/// // An instruction that only pushes (like 'ldloc')
/// let load_behavior = StackBehavior {
///     pops: 0,
///     pushes: 1,
///     net_effect: 1,
/// };
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`StackBehavior`] is [`std::marker::Send`] and [`std::marker::Sync`] as it only contains primitive integer fields.
/// All instances can be safely shared across threads without synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackBehavior {
    /// Number of items popped from stack
    pub pops: u8,
    /// Number of items pushed to stack
    pub pushes: u8,
    /// Net effect on stack depth (pushes - pops)
    pub net_effect: i8,
}

/// Categorization of instructions by their primary function.
///
/// This classification helps in understanding the purpose of instructions
/// and is useful for analysis, optimization, and code generation.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::InstructionCategory;
///
/// // Different instruction categories
/// let arithmetic = InstructionCategory::Arithmetic;     // add, sub, mul, div
/// let control_flow = InstructionCategory::ControlFlow;  // br, switch, ret
/// let load_store = InstructionCategory::LoadStore;      // ldloc, stfld
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`InstructionCategory`] is [`std::marker::Send`] and [`std::marker::Sync`] as it only contains unit variants.
/// All variants are safe to share across threads without synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionCategory {
    /// Arithmetic operations (add, sub, mul, div, rem, neg)
    Arithmetic,
    /// Bitwise and logical operations (and, or, xor, not, shl, shr)
    BitwiseLogical,
    /// Comparison operations (ceq, cgt, clt)
    Comparison,
    /// Control flow operations (br, switch, ret, call)
    ControlFlow,
    /// Type conversion operations (conv.i4, conv.r8, box, unbox)
    Conversion,
    /// Load and store operations (ldloc, stfld, ldarg)
    LoadStore,
    /// Object model operations (newobj, ldfld, castclass)
    ObjectModel,
    /// Prefix instructions (unaligned, volatile, tail)
    Prefix,
    /// Miscellaneous operations (nop, break, dup)
    Misc,
}

/// A decoded CIL instruction with all metadata needed for analysis and emulation.
///
/// This struct represents a fully decoded .NET CIL instruction, including its location,
/// semantic meaning, operands, and analysis metadata. It provides all the information
/// needed for static analysis, emulation, and code generation.
///
/// # Key Features
///
/// - **Location Information**: RVA, file offset, and size in bytes
/// - **Instruction Identity**: Opcode, prefix, and mnemonic
/// - **Semantic Analysis**: Category, control flow type, and stack effects
/// - **Operand Data**: Typed operand representation
/// - **Control Flow**: Branch targets and flow analysis
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{assembly::decode_instruction, Parser};
///
/// let bytecode = &[0x2A]; // ret instruction
/// let mut parser = Parser::new(bytecode);
/// let instruction = decode_instruction(&mut parser, 0x1000)?;
///
/// println!("Instruction: {}", instruction.mnemonic);
/// println!("Is terminal: {}", instruction.is_terminal());
/// println!("Stack effect: {:?}", instruction.stack_behavior);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`Instruction`] is [`std::marker::Send`] and [`std::marker::Sync`] as all fields contain thread-safe types.
/// This includes primitives, static string references, and owned collections that can be safely shared across threads.
#[derive(Clone)]
pub struct Instruction {
    // Core fields
    /// Relative virtual address where this instruction is located
    pub rva: u64,
    /// File offset where this instruction is located
    pub offset: u64,
    /// Size of this instruction in bytes
    pub size: u64,
    /// Primary opcode byte
    pub opcode: u8,
    /// Prefix byte (0 if no prefix)
    pub prefix: u8,

    // Semantic information
    /// Human-readable instruction mnemonic (e.g., "add", "ldloc.s", "ret")
    pub mnemonic: &'static str,
    /// Functional categorization of this instruction
    pub category: InstructionCategory,
    /// How this instruction affects control flow
    pub flow_type: FlowType,

    // Operand information
    /// The operand data for this instruction
    pub operand: Operand,

    // Analysis information
    /// How this instruction affects the evaluation stack
    pub stack_behavior: StackBehavior,
    /// Computed branch targets (if any, as absolute addresses)
    pub branch_targets: Vec<u64>,
}

impl Instruction {
    /// Check if this instruction is a branch instruction.
    ///
    /// Returns `true` for any instruction that can alter control flow by jumping
    /// to a different location, including conditional branches, unconditional jumps,
    /// and switch statements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{Instruction, FlowType, InstructionCategory, StackBehavior, Operand};
    ///
    /// let mut instruction = Instruction {
    ///     rva: 0x1000,
    ///     offset: 0,
    ///     size: 2,
    ///     opcode: 0x2B,
    ///     prefix: 0,
    ///     mnemonic: "br.s",
    ///     category: InstructionCategory::ControlFlow,
    ///     flow_type: FlowType::UnconditionalBranch,
    ///     operand: Operand::Target(0x1010),
    ///     stack_behavior: StackBehavior { pops: 0, pushes: 0, net_effect: 0 },
    ///     branch_targets: vec![0x1010],
    /// };
    ///
    /// assert!(instruction.is_branch());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        matches!(
            self.flow_type,
            FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Switch
        )
    }

    /// Check if this instruction is a terminal instruction (ends a basic block).
    ///
    /// Terminal instructions are those that end the current basic block by transferring
    /// control elsewhere or ending execution. This includes branches, returns, throws,
    /// and exception handling instructions.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{Instruction, FlowType, InstructionCategory, StackBehavior, Operand};
    ///
    /// let ret_instruction = Instruction {
    ///     rva: 0x1000,
    ///     offset: 0,
    ///     size: 1,
    ///     opcode: 0x2A,
    ///     prefix: 0,
    ///     mnemonic: "ret",
    ///     category: InstructionCategory::ControlFlow,
    ///     flow_type: FlowType::Return,
    ///     operand: Operand::None,
    ///     stack_behavior: StackBehavior { pops: 1, pushes: 0, net_effect: -1 },
    ///     branch_targets: vec![],
    /// };
    ///
    /// assert!(ret_instruction.is_terminal());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.flow_type,
            FlowType::ConditionalBranch
                | FlowType::UnconditionalBranch
                | FlowType::Return
                | FlowType::Switch
                | FlowType::Throw
                | FlowType::Leave
        )
    }

    /// Get the target addresses of this instruction (for branches).
    ///
    /// Returns a vector of target addresses that this instruction can jump to.
    /// For non-branch instructions, returns an empty vector. For conditional branches,
    /// this only includes the branch target (not the fall-through). For switch
    /// instructions, includes all possible targets.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{Instruction, FlowType, InstructionCategory, StackBehavior, Operand};
    ///
    /// let branch_instruction = Instruction {
    ///     rva: 0x1000,
    ///     offset: 0,
    ///     size: 5,
    ///     opcode: 0x38,
    ///     prefix: 0,
    ///     mnemonic: "br",
    ///     category: InstructionCategory::ControlFlow,
    ///     flow_type: FlowType::UnconditionalBranch,
    ///     operand: Operand::Target(0x2000),
    ///     stack_behavior: StackBehavior { pops: 0, pushes: 0, net_effect: 0 },
    ///     branch_targets: vec![0x2000],
    /// };
    ///
    /// let targets = branch_instruction.get_targets();
    /// assert_eq!(targets, vec![0x2000]);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn get_targets(&self) -> Vec<u64> {
        match self.flow_type {
            FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Switch => {
                match &self.operand {
                    Operand::Switch(values) => {
                        values.iter().map(|entry| u64::from(*entry)).collect()
                    }
                    Operand::Target(target) => vec![*target],
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Main instruction header: RVA - Opcode - Mnemonic
        write!(f, "{:016X} - ", self.rva)?;

        // Include prefix if present
        if self.prefix != 0 {
            write!(f, "{:02X}:", self.prefix)?;
        }

        write!(f, "{:02X} - {:<12}", self.opcode, self.mnemonic)?;

        // Add operand information
        match &self.operand {
            Operand::None => {
                // No operand to display
            }
            Operand::Immediate(imm) => {
                write!(f, " 0x{imm:X}")?;
            }
            Operand::Target(target) => {
                write!(f, " -> 0x{target:08X}")?;
            }
            Operand::Token(token) => {
                write!(f, " token:0x{:08X}", token.value())?;
            }
            Operand::Local(local) => {
                write!(f, " local:{local}")?;
            }
            Operand::Argument(arg) => {
                write!(f, " arg:{arg}")?;
            }
            Operand::Switch(items) => {
                write!(f, " switch[{}]:(", items.len())?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "0x{item:08X}")?;
                    // Limit output for very large switch tables
                    if i >= 5 && items.len() > 6 {
                        write!(f, ", ...{} more", items.len() - 6)?;
                        break;
                    }
                }
                write!(f, ")")?;
            }
        }

        // Add metadata section
        write!(f, " | ")?;
        write!(f, "{:?}", self.category)?;

        if self.flow_type != FlowType::Sequential {
            write!(f, " | {:?}", self.flow_type)?;
        }

        // Add stack effect if non-zero
        if self.stack_behavior.net_effect != 0 {
            write!(f, " | stack:{:+}", self.stack_behavior.net_effect)?;
        }

        // Add size information
        write!(f, " | size:{}", self.size)?;

        // Add branch targets if any
        if !self.branch_targets.is_empty() {
            write!(f, " | targets:[")?;
            for (i, target) in self.branch_targets.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "0x{target:08X}")?;
                // Limit output for instructions with many targets
                if i >= 3 && self.branch_targets.len() > 4 {
                    write!(f, ", ...{} more", self.branch_targets.len() - 4)?;
                    break;
                }
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_type_variants() {
        // Test all OperandType variants exist and can be constructed
        let types = [
            OperandType::None,
            OperandType::Int8,
            OperandType::UInt8,
            OperandType::Int16,
            OperandType::UInt16,
            OperandType::Int32,
            OperandType::UInt32,
            OperandType::Int64,
            OperandType::UInt64,
            OperandType::Float32,
            OperandType::Float64,
            OperandType::Token,
            OperandType::Switch,
        ];

        // Test that they implement expected traits
        for op_type in types.iter() {
            assert_eq!(*op_type, *op_type); // PartialEq
            assert!(!format!("{op_type:?}").is_empty()); // Debug
        }
    }

    #[test]
    fn test_immediate_upper_hex_formatting() {
        // Test different immediate types and their hex formatting using standard UpperHex trait
        assert_eq!(format!("{:X}", Immediate::Int8(-1)), "FF");
        assert_eq!(format!("{:X}", Immediate::UInt8(255)), "FF");
        assert_eq!(format!("{:X}", Immediate::Int16(-1)), "FFFF");
        assert_eq!(format!("{:X}", Immediate::UInt16(65535)), "FFFF");
        assert_eq!(format!("{:X}", Immediate::Int32(42)), "0000002A");
        assert_eq!(format!("{:X}", Immediate::UInt32(0xDEADBEEF)), "DEADBEEF");
        assert_eq!(format!("{:X}", Immediate::Int64(-1)), "FFFFFFFFFFFFFFFF");
        assert_eq!(
            format!("{:X}", Immediate::UInt64(0x123456789ABCDEF0)),
            "123456789ABCDEF0"
        ); // Test floating point formatting (shows bits representation)
        let float32_bits = 42.5f32.to_bits();
        assert_eq!(
            format!("{:X}", Immediate::Float32(42.5f32)),
            format!("{:08X}", float32_bits)
        );

        let float64_bits = 123.456f64.to_bits();
        assert_eq!(
            format!("{:X}", Immediate::Float64(123.456)),
            format!("{:016X}", float64_bits)
        );
    }

    #[test]
    fn test_immediate_variants_and_conversions() {
        // Test all Immediate variants
        let immediates = [
            Immediate::Int8(-42),
            Immediate::UInt8(42),
            Immediate::Int16(-1000),
            Immediate::UInt16(1000),
            Immediate::Int32(-100000),
            Immediate::UInt32(100000),
            Immediate::Int64(-1000000000),
            Immediate::UInt64(1000000000),
            Immediate::Float32(3.04),
            Immediate::Float64(2.0008),
        ];

        for imm in immediates.iter() {
            // Test Debug trait
            assert!(!format!("{imm:?}").is_empty());

            // Test Clone trait
            let cloned = *imm;
            assert_eq!(*imm, cloned);

            // Test conversion to u64
            let as_u64: u64 = (*imm).into();
            assert!(as_u64 < u64::MAX);
        }
    }

    #[test]
    fn test_immediate_to_u64_conversion() {
        // Test specific conversions
        assert_eq!(u64::from(Immediate::UInt8(255)), 255u64);
        assert_eq!(u64::from(Immediate::UInt16(65535)), 65535u64);
        assert_eq!(u64::from(Immediate::UInt32(4294967295)), 4294967295u64);
        assert_eq!(u64::from(Immediate::UInt64(u64::MAX)), u64::MAX);

        // Test signed conversions (they should convert properly)
        assert_eq!(u64::from(Immediate::Int8(-1)), (-1i8) as u64);
        assert_eq!(u64::from(Immediate::Int32(-1)), (-1i32) as u64);

        // Test float conversions
        assert_eq!(u64::from(Immediate::Float32(42.0)), 1109917696u64); // 42.0 as bits
        assert_eq!(u64::from(Immediate::Float64(100.0)), 4636737291354636288u64);
        // 100.0 as bits
    }

    #[test]
    fn test_operand_variants() {
        // Test all Operand variants
        let operands = [
            Operand::None,
            Operand::Immediate(Immediate::Int32(42)),
            Operand::Target(0x1000),
            Operand::Token(Token::new(0x06000001)),
            Operand::Local(5),
            Operand::Argument(3),
            Operand::Switch(vec![0x1000, 0x2000, 0x3000]),
        ];

        for operand in operands.iter() {
            // Test Debug trait
            assert!(!format!("{operand:?}").is_empty());

            // Test Clone trait
            let cloned = operand.clone();
            // Can't use PartialEq because Token doesn't implement it
            match (operand, &cloned) {
                (Operand::None, Operand::None) => {}
                (Operand::Immediate(a), Operand::Immediate(b)) => assert_eq!(a, b),
                (Operand::Target(a), Operand::Target(b)) => assert_eq!(a, b),
                (Operand::Token(a), Operand::Token(b)) => assert_eq!(a.value(), b.value()),
                (Operand::Local(a), Operand::Local(b)) => assert_eq!(a, b),
                (Operand::Argument(a), Operand::Argument(b)) => assert_eq!(a, b),
                (Operand::Switch(a), Operand::Switch(b)) => assert_eq!(a, b),
                _ => panic!("Clone didn't produce same variant"),
            }
        }
    }

    #[test]
    fn test_flow_type_variants() {
        let flow_types = [
            FlowType::Sequential,
            FlowType::ConditionalBranch,
            FlowType::UnconditionalBranch,
            FlowType::Call,
            FlowType::Return,
            FlowType::Switch,
            FlowType::Throw,
            FlowType::EndFinally,
            FlowType::Leave,
        ];

        for flow_type in flow_types.iter() {
            assert_eq!(*flow_type, *flow_type); // PartialEq
            assert!(!format!("{flow_type:?}").is_empty()); // Debug
        }
    }

    #[test]
    fn test_stack_behavior_creation_and_properties() {
        let stack_behavior = StackBehavior {
            pops: 2,
            pushes: 1,
            net_effect: -1,
        };

        assert_eq!(stack_behavior.pops, 2);
        assert_eq!(stack_behavior.pushes, 1);
        assert_eq!(stack_behavior.net_effect, -1);

        // Test traits
        assert_eq!(stack_behavior, stack_behavior); // PartialEq
        assert!(!format!("{stack_behavior:?}").is_empty()); // Debug

        let cloned = stack_behavior;
        assert_eq!(stack_behavior, cloned);
    }

    #[test]
    fn test_instruction_category_variants() {
        let categories = [
            InstructionCategory::Arithmetic,
            InstructionCategory::BitwiseLogical,
            InstructionCategory::Comparison,
            InstructionCategory::ControlFlow,
            InstructionCategory::Conversion,
            InstructionCategory::LoadStore,
            InstructionCategory::ObjectModel,
            InstructionCategory::Prefix,
            InstructionCategory::Misc,
        ];

        for category in categories.iter() {
            assert_eq!(*category, *category); // PartialEq
            assert!(!format!("{category:?}").is_empty()); // Debug
        }
    }

    #[test]
    fn test_instruction_creation() {
        let instruction = Instruction {
            rva: 0x1000,
            offset: 0x500,
            size: 5,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Target(0x2000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x2000],
        };

        assert_eq!(instruction.rva, 0x1000);
        assert_eq!(instruction.offset, 0x500);
        assert_eq!(instruction.size, 5);
        assert_eq!(instruction.opcode, 0x38);
        assert_eq!(instruction.prefix, 0);
        assert_eq!(instruction.mnemonic, "br");
        assert_eq!(instruction.category, InstructionCategory::ControlFlow);
        assert_eq!(instruction.flow_type, FlowType::UnconditionalBranch);
        assert_eq!(instruction.branch_targets, vec![0x2000]);
    }

    #[test]
    fn test_instruction_is_branch() {
        // Test unconditional branch
        let branch_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 5,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Target(0x2000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x2000],
        };
        assert!(branch_instruction.is_branch());

        // Test conditional branch
        let conditional_branch = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 2,
            opcode: 0x2C,
            prefix: 0,
            mnemonic: "brtrue.s",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::ConditionalBranch,
            operand: Operand::Target(0x1010),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![0x1010],
        };
        assert!(conditional_branch.is_branch());

        // Test switch
        let switch_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 10,
            opcode: 0x45,
            prefix: 0,
            mnemonic: "switch",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Switch,
            operand: Operand::Switch(vec![0x1100, 0x1200, 0x1300]),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![0x1100, 0x1200, 0x1300],
        };
        assert!(switch_instruction.is_branch());

        // Test non-branch instruction
        let add_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x58,
            prefix: 0,
            mnemonic: "add",
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 2,
                pushes: 1,
                net_effect: -1,
            },
            branch_targets: vec![],
        };
        assert!(!add_instruction.is_branch());
    }

    #[test]
    fn test_instruction_is_terminal() {
        // Test return instruction
        let ret_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x2A,
            prefix: 0,
            mnemonic: "ret",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Return,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![],
        };
        assert!(ret_instruction.is_terminal());

        // Test throw instruction
        let throw_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x7A,
            prefix: 0,
            mnemonic: "throw",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Throw,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![],
        };
        assert!(throw_instruction.is_terminal());

        // Test branch instruction (also terminal)
        let branch_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 5,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Target(0x2000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x2000],
        };
        assert!(branch_instruction.is_terminal());

        // Test leave instruction
        let leave_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 5,
            opcode: 0xDD,
            prefix: 0,
            mnemonic: "leave",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Leave,
            operand: Operand::Target(0x2000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x2000],
        };
        assert!(leave_instruction.is_terminal());

        // Test non-terminal instruction
        let add_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x58,
            prefix: 0,
            mnemonic: "add",
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 2,
                pushes: 1,
                net_effect: -1,
            },
            branch_targets: vec![],
        };
        assert!(!add_instruction.is_terminal());

        // Test call instruction (not terminal in this implementation)
        let call_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 5,
            opcode: 0x28,
            prefix: 0,
            mnemonic: "call",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Call,
            operand: Operand::Token(Token::new(0x0A000001)),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 1,
                net_effect: 0,
            },
            branch_targets: vec![],
        };
        assert!(!call_instruction.is_terminal());
    }

    #[test]
    fn test_instruction_get_targets() {
        // Test unconditional branch
        let branch_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 5,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Target(0x2000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x2000],
        };
        assert_eq!(branch_instruction.get_targets(), vec![0x2000]);

        // Test conditional branch
        let conditional_branch = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 2,
            opcode: 0x2C,
            prefix: 0,
            mnemonic: "brtrue.s",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::ConditionalBranch,
            operand: Operand::Target(0x1010),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![0x1010],
        };
        assert_eq!(conditional_branch.get_targets(), vec![0x1010]);

        // Test switch instruction
        let switch_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 10,
            opcode: 0x45,
            prefix: 0,
            mnemonic: "switch",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Switch,
            operand: Operand::Switch(vec![0x1100, 0x1200, 0x1300]),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![0x1100, 0x1200, 0x1300],
        };
        let targets = switch_instruction.get_targets();
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&0x1100));
        assert!(targets.contains(&0x1200));
        assert!(targets.contains(&0x1300));

        // Test non-branch instruction
        let add_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x58,
            prefix: 0,
            mnemonic: "add",
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 2,
                pushes: 1,
                net_effect: -1,
            },
            branch_targets: vec![],
        };
        assert_eq!(add_instruction.get_targets(), Vec::<u64>::new());

        // Test branch with non-target operand (should return empty)
        let branch_with_immediate = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 2,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Immediate(Immediate::Int32(42)), // Wrong operand type
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        };
        assert_eq!(branch_with_immediate.get_targets(), Vec::<u64>::new());
    }

    #[test]
    fn test_instruction_debug_format() {
        // Test basic instruction formatting
        let add_instruction = Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x58,
            prefix: 0,
            mnemonic: "add",
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 2,
                pushes: 1,
                net_effect: -1,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{add_instruction:?}");
        assert!(debug_str.contains("0000000000001000"));
        assert!(debug_str.contains("58"));
        assert!(debug_str.contains("add"));
        assert!(debug_str.contains("Arithmetic"));
        assert!(debug_str.contains("stack:-1"));
        assert!(debug_str.contains("size:1"));

        // Test instruction with immediate operand
        let immediate_instruction = Instruction {
            rva: 0x2000,
            offset: 0,
            size: 5,
            opcode: 0x20,
            prefix: 0,
            mnemonic: "ldc.i4",
            category: InstructionCategory::LoadStore,
            flow_type: FlowType::Sequential,
            operand: Operand::Immediate(Immediate::Int32(42)),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 1,
                net_effect: 1,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{immediate_instruction:?}");
        assert!(debug_str.contains("0000000000002000"));
        assert!(debug_str.contains("20"));
        assert!(debug_str.contains("ldc.i4"));
        assert!(debug_str.contains("0x0000002A")); // 42 in hex
        assert!(debug_str.contains("LoadStore"));
        assert!(debug_str.contains("stack:+1"));

        // Test instruction with target operand
        let branch_instruction = Instruction {
            rva: 0x3000,
            offset: 0,
            size: 5,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Target(0x4000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x4000],
        };
        let debug_str = format!("{branch_instruction:?}");
        assert!(debug_str.contains("0000000000003000"));
        assert!(debug_str.contains("38"));
        assert!(debug_str.contains("br"));
        assert!(debug_str.contains("-> 0x00004000"));
        assert!(debug_str.contains("ControlFlow"));
        assert!(debug_str.contains("UnconditionalBranch"));
        assert!(debug_str.contains("targets:[0x00004000]"));

        // Test instruction with token operand
        let token_instruction = Instruction {
            rva: 0x5000,
            offset: 0,
            size: 5,
            opcode: 0x28,
            prefix: 0,
            mnemonic: "call",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Call,
            operand: Operand::Token(Token::new(0x0A000001)),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 1,
                net_effect: 0,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{token_instruction:?}");
        assert!(debug_str.contains("0000000000005000"));
        assert!(debug_str.contains("28"));
        assert!(debug_str.contains("call"));
        assert!(debug_str.contains("token:0x0A000001"));
        assert!(debug_str.contains("ControlFlow"));
        assert!(debug_str.contains("Call"));

        // Test instruction with local operand
        let local_instruction = Instruction {
            rva: 0x6000,
            offset: 0,
            size: 2,
            opcode: 0x11,
            prefix: 0,
            mnemonic: "ldloc.s",
            category: InstructionCategory::LoadStore,
            flow_type: FlowType::Sequential,
            operand: Operand::Local(5),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 1,
                net_effect: 1,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{local_instruction:?}");
        assert!(debug_str.contains("0000000000006000"));
        assert!(debug_str.contains("11"));
        assert!(debug_str.contains("ldloc.s"));
        assert!(debug_str.contains("local:5"));
        assert!(debug_str.contains("LoadStore"));
        assert!(debug_str.contains("stack:+1"));

        // Test instruction with argument operand
        let arg_instruction = Instruction {
            rva: 0x7000,
            offset: 0,
            size: 2,
            opcode: 0x0E,
            prefix: 0,
            mnemonic: "ldarg.s",
            category: InstructionCategory::LoadStore,
            flow_type: FlowType::Sequential,
            operand: Operand::Argument(3),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 1,
                net_effect: 1,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{arg_instruction:?}");
        assert!(debug_str.contains("0000000000007000"));
        assert!(debug_str.contains("0E"));
        assert!(debug_str.contains("ldarg.s"));
        assert!(debug_str.contains("arg:3"));
        assert!(debug_str.contains("LoadStore"));

        // Test instruction with switch operand
        let switch_instruction = Instruction {
            rva: 0x8000,
            offset: 0,
            size: 15,
            opcode: 0x45,
            prefix: 0,
            mnemonic: "switch",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Switch,
            operand: Operand::Switch(vec![0x8100, 0x8200, 0x8300]),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 0,
                net_effect: -1,
            },
            branch_targets: vec![0x8100, 0x8200, 0x8300],
        };
        let debug_str = format!("{switch_instruction:?}");
        assert!(debug_str.contains("0000000000008000"));
        assert!(debug_str.contains("45"));
        assert!(debug_str.contains("switch"));
        assert!(debug_str.contains("switch[3]:(0x00008100, 0x00008200, 0x00008300)"));
        assert!(debug_str.contains("ControlFlow"));
        assert!(debug_str.contains("Switch"));
        assert!(debug_str.contains("stack:-1"));
        assert!(debug_str.contains("targets:[0x00008100, 0x00008200, 0x00008300]"));

        // Test instruction with prefix
        let prefixed_instruction = Instruction {
            rva: 0x9000,
            offset: 0,
            size: 3,
            opcode: 0x6F,
            prefix: 0xFE,
            mnemonic: "callvirt",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::Call,
            operand: Operand::Token(Token::new(0x0A000002)),
            stack_behavior: StackBehavior {
                pops: 1,
                pushes: 1,
                net_effect: 0,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{prefixed_instruction:?}");
        assert!(debug_str.contains("0000000000009000"));
        assert!(debug_str.contains("FE:6F"));
        assert!(debug_str.contains("callvirt"));
        assert!(debug_str.contains("token:0x0A000002"));

        // Test instruction with floating point immediate
        let float_instruction = Instruction {
            rva: 0xA000,
            offset: 0,
            size: 9,
            opcode: 0x23,
            prefix: 0,
            mnemonic: "ldc.r8",
            category: InstructionCategory::LoadStore,
            flow_type: FlowType::Sequential,
            operand: Operand::Immediate(Immediate::Float64(123.456)),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 1,
                net_effect: 1,
            },
            branch_targets: vec![],
        };
        let debug_str = format!("{float_instruction:?}");
        assert!(debug_str.contains("000000000000A000"));
        assert!(debug_str.contains("23"));
        assert!(debug_str.contains("ldc.r8"));
        assert!(debug_str.contains("0x405EDD2F1A9FBE77")); // 123.456 as bits
    }

    #[test]
    fn test_instruction_clone() {
        let original = Instruction {
            rva: 0x1000,
            offset: 0x500,
            size: 5,
            opcode: 0x38,
            prefix: 0,
            mnemonic: "br",
            category: InstructionCategory::ControlFlow,
            flow_type: FlowType::UnconditionalBranch,
            operand: Operand::Target(0x2000),
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![0x2000],
        };

        let cloned = original.clone();

        assert_eq!(original.rva, cloned.rva);
        assert_eq!(original.offset, cloned.offset);
        assert_eq!(original.size, cloned.size);
        assert_eq!(original.opcode, cloned.opcode);
        assert_eq!(original.prefix, cloned.prefix);
        assert_eq!(original.mnemonic, cloned.mnemonic);
        assert_eq!(original.category, cloned.category);
        assert_eq!(original.flow_type, cloned.flow_type);
        assert_eq!(original.stack_behavior, cloned.stack_behavior);
        assert_eq!(original.branch_targets, cloned.branch_targets);

        // Test operand clone (can't use PartialEq because Token doesn't implement it)
        match (&original.operand, &cloned.operand) {
            (Operand::Target(a), Operand::Target(b)) => assert_eq!(a, b),
            _ => panic!("Operand clone failed"),
        }
    }

    #[test]
    fn test_edge_cases_and_boundary_values() {
        // Test maximum values for immediate types
        let max_immediates = [
            Immediate::Int8(i8::MAX),
            Immediate::Int8(i8::MIN),
            Immediate::UInt8(u8::MAX),
            Immediate::Int16(i16::MAX),
            Immediate::Int16(i16::MIN),
            Immediate::UInt16(u16::MAX),
            Immediate::Int32(i32::MAX),
            Immediate::Int32(i32::MIN),
            Immediate::UInt32(u32::MAX),
            Immediate::Int64(i64::MAX),
            Immediate::Int64(i64::MIN),
            Immediate::UInt64(u64::MAX),
            Immediate::Float32(f32::MAX),
            Immediate::Float32(f32::MIN),
            Immediate::Float64(f64::MAX),
            Immediate::Float64(f64::MIN),
        ];

        for imm in max_immediates.iter() {
            let _: u64 = (*imm).into(); // Should not panic
            assert!(!format!("{imm:?}").is_empty());
        }

        // Test empty switch
        let empty_switch = Operand::Switch(vec![]);
        assert!(!format!("{empty_switch:?}").is_empty());

        // Test large switch - Note: Operand::Switch Debug just uses Vec's Debug format
        let large_switch = Operand::Switch((0..10).collect());
        let debug_str = format!("{large_switch:?}");
        assert!(debug_str.contains("Switch"));
        assert!(debug_str.contains("["));
        assert!(debug_str.contains("]"));

        // Test zero values
        let zero_stack = StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        };
        assert_eq!(zero_stack.pops, 0);
        assert_eq!(zero_stack.pushes, 0);
        assert_eq!(zero_stack.net_effect, 0);
    }

    #[test]
    fn test_stack_behavior_calculations() {
        // Test various stack behavior scenarios
        let scenarios = [
            // (pops, pushes, expected_net_effect)
            (0, 1, 1),  // Load operations
            (1, 0, -1), // Store operations
            (2, 1, -1), // Binary operations (add, sub, etc.)
            (1, 1, 0),  // Unary operations (neg, not, etc.)
            (0, 0, 0),  // No-op operations
            (3, 2, -1), // Complex operations
        ];

        for (pops, pushes, expected_net) in scenarios.iter() {
            let stack_behavior = StackBehavior {
                pops: *pops,
                pushes: *pushes,
                net_effect: *expected_net,
            };

            assert_eq!(stack_behavior.pops, *pops);
            assert_eq!(stack_behavior.pushes, *pushes);
            assert_eq!(stack_behavior.net_effect, *expected_net);
            assert_eq!(stack_behavior.net_effect, (*pushes as i8) - (*pops as i8));
        }
    }
}
