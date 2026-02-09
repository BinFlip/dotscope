//! Handler methods for the CIL interpreter.
//!
//! This module contains the implementation of instruction handlers used by
//! the main interpreter dispatch loop. These are private helper methods that
//! perform specific operations like loading/storing variables, arithmetic,
//! branching, array access, and field operations.

use std::sync::Arc;

use crate::{
    assembly::Instruction,
    emulation::{
        engine::{error::EmulationError, interpreter::Interpreter, result::StepResult},
        memory::AddressSpace,
        thread::EmulationThread,
        BinaryOp, CompareOp, ConversionType, EmValue, HeapObject, HeapRef, ManagedPointer,
        PointerTarget, SymbolicValue, TaintSource, UnaryOp,
    },
    metadata::{
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
    Error, Result,
};

/// Implementation of instruction handler methods for the interpreter.
///
/// These methods are called from the main `step()` function to handle
/// specific instruction types. They are organized by category:
///
/// - **Error helpers**: `invalid_operand`
/// - **Local variables**: `load_local`, `store_local`, `load_local_address`
/// - **Arguments**: `load_argument`, `store_argument`, `load_argument_address`
/// - **Arithmetic**: `binary_op`, `unary_op`, `compare`, `convert`
/// - **Branches**: `branch_if_true`, `branch_if_false`, `branch_compare`, etc.
/// - **Arrays**: `new_array`, `load_element`, `store_element`, etc.
/// - **Fields**: `load_field`, `store_field`, `load_static_field`, etc.
/// - **Indirect**: `load_indirect_sized`, `store_indirect_sized`, `load_object`, `store_object`
impl Interpreter {
    /// Creates an error for an invalid operand.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The instruction with the invalid operand.
    /// * `expected` - Description of the expected operand type.
    ///
    /// # Returns
    ///
    /// An error indicating the operand type mismatch.
    pub(super) fn invalid_operand(instruction: &Instruction, expected: &'static str) -> Error {
        EmulationError::InvalidOperand {
            instruction: instruction.mnemonic,
            expected,
        }
        .into()
    }

    /// Loads a local variable onto the evaluation stack.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `index` - The local variable index.
    ///
    /// # Errors
    ///
    /// Returns an error if the local index is out of bounds.
    pub(super) fn load_local(thread: &mut EmulationThread, index: u16) -> Result<StepResult> {
        let value = thread.get_local(usize::from(index))?.clone();
        thread.push(value)?;
        Ok(StepResult::Continue)
    }

    /// Loads the address of a local variable onto the evaluation stack.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `index` - The local variable index.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    pub(super) fn load_local_address(
        thread: &mut EmulationThread,
        index: u16,
    ) -> Result<StepResult> {
        let ptr = EmValue::ManagedPtr(ManagedPointer::to_local(index));
        thread.push(ptr)?;
        Ok(StepResult::Continue)
    }

    /// Stores a value from the evaluation stack into a local variable.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `index` - The local variable index.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty or the local index is out of bounds.
    pub(super) fn store_local(thread: &mut EmulationThread, index: u16) -> Result<StepResult> {
        let value = thread.pop()?;
        thread.set_local(usize::from(index), value)?;
        Ok(StepResult::Continue)
    }

    /// Loads an argument onto the evaluation stack.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `index` - The argument index.
    ///
    /// # Errors
    ///
    /// Returns an error if the argument index is out of bounds.
    pub(super) fn load_argument(thread: &mut EmulationThread, index: u16) -> Result<StepResult> {
        let value = thread.get_arg(usize::from(index))?.clone();
        thread.push(value)?;
        Ok(StepResult::Continue)
    }

    /// Loads the address of an argument onto the evaluation stack.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `index` - The argument index.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    pub(super) fn load_argument_address(
        thread: &mut EmulationThread,
        index: u16,
    ) -> Result<StepResult> {
        let ptr = EmValue::ManagedPtr(ManagedPointer::to_argument(index));
        thread.push(ptr)?;
        Ok(StepResult::Continue)
    }

    /// Stores a value from the evaluation stack into an argument slot.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `index` - The argument index.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty or the argument index is out of bounds.
    pub(super) fn store_argument(thread: &mut EmulationThread, index: u16) -> Result<StepResult> {
        let value = thread.pop()?;
        thread.set_arg(usize::from(index), value)?;
        Ok(StepResult::Continue)
    }

    /// Executes a binary arithmetic or bitwise operation.
    ///
    /// Pops two values from the stack, applies the operation, and pushes the result.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `op` - The binary operation to perform.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than two values or type mismatch occurs.
    pub(super) fn binary_op(
        thread: &mut EmulationThread,
        op: BinaryOp,
        ptr_size: PointerSize,
    ) -> Result<StepResult> {
        let right = thread.pop()?;
        let left = thread.pop()?;
        let result = left.binary_op(right, op, ptr_size)?;
        thread.push(result)?;
        Ok(StepResult::Continue)
    }

    /// Executes a unary operation (negation or bitwise NOT).
    ///
    /// Pops one value from the stack, applies the operation, and pushes the result.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `op` - The unary operation to perform.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty or type mismatch occurs.
    pub(super) fn unary_op(
        thread: &mut EmulationThread,
        op: UnaryOp,
        ptr_size: PointerSize,
    ) -> Result<StepResult> {
        let value = thread.pop()?;
        let result = value.unary_op(op, ptr_size)?;
        thread.push(result)?;
        Ok(StepResult::Continue)
    }

    /// Executes a comparison operation.
    ///
    /// Pops two values from the stack, compares them, and pushes 1 (true) or 0 (false).
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `op` - The comparison operation to perform.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than two values or type mismatch occurs.
    pub(super) fn compare(thread: &mut EmulationThread, op: CompareOp) -> Result<StepResult> {
        let right = thread.pop()?;
        let left = thread.pop()?;
        let result = left.compare(&right, op)?;
        thread.push(result)?;
        Ok(StepResult::Continue)
    }

    /// Converts a value to a different type.
    ///
    /// Pops a value from the stack, converts it, and pushes the result.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `conv_type` - The target conversion type.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty, conversion fails, or overflow occurs
    /// (for overflow-checked conversions).
    pub(super) fn convert(
        thread: &mut EmulationThread,
        conv_type: ConversionType,
        ptr_size: PointerSize,
    ) -> Result<StepResult> {
        let value = thread.pop()?;
        let result = value.convert(conv_type, ptr_size)?;
        thread.push(result)?;
        Ok(StepResult::Continue)
    }

    /// Branches if the top of the stack is true (non-zero or non-null).
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `target` - The branch target offset.
    ///
    /// # Returns
    ///
    /// `StepResult::Branch { target }` if the value is true, otherwise `StepResult::Continue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty or contains an unsupported type.
    pub(super) fn branch_if_true(thread: &mut EmulationThread, target: u64) -> Result<StepResult> {
        let value = thread.pop()?;
        let is_true = match value {
            EmValue::I32(v) => v != 0,
            EmValue::I64(v) | EmValue::NativeInt(v) => v != 0,
            EmValue::NativeUInt(v) => v != 0,
            EmValue::Bool(v) => v,
            EmValue::ObjectRef(_) => true,
            EmValue::Null => false,
            // Handle symbolic values - default to "false" (don't take branch)
            // This allows emulation to continue through unknown branches.
            // The result may be incorrect if the symbolic would have been true.
            EmValue::Symbolic(_) => false,
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "brtrue",
                    expected: "integer or object",
                    found: value.cil_flavor().as_str(),
                }
                .into())
            }
        };

        if is_true {
            Ok(StepResult::Branch { target })
        } else {
            Ok(StepResult::Continue)
        }
    }

    /// Branches if the top of the stack is false (zero or null).
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `target` - The branch target offset.
    ///
    /// # Returns
    ///
    /// `StepResult::Branch { target }` if the value is false, otherwise `StepResult::Continue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty or contains an unsupported type.
    pub(super) fn branch_if_false(thread: &mut EmulationThread, target: u64) -> Result<StepResult> {
        let value = thread.pop()?;
        let is_false = match value {
            EmValue::I32(v) => v == 0,
            EmValue::I64(v) | EmValue::NativeInt(v) => v == 0,
            EmValue::NativeUInt(v) => v == 0,
            EmValue::Bool(v) => !v,
            EmValue::ObjectRef(_) => false,
            EmValue::Null => true,
            // Handle symbolic values - default to "false" (don't take branch)
            // This allows emulation to continue through unknown branches.
            // The result may be incorrect if the symbolic would have been false/null.
            EmValue::Symbolic(_) => false,
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "brfalse",
                    expected: "integer or object",
                    found: value.cil_flavor().as_str(),
                }
                .into())
            }
        };

        if is_false {
            Ok(StepResult::Branch { target })
        } else {
            Ok(StepResult::Continue)
        }
    }

    /// Branches based on comparing two values from the stack.
    ///
    /// Pops two values, compares them using the specified operation,
    /// and branches if the comparison is true.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `target` - The branch target offset.
    /// * `op` - The comparison operation to perform.
    ///
    /// # Returns
    ///
    /// `StepResult::Branch { target }` if the comparison is true, otherwise `StepResult::Continue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than two values or type mismatch occurs.
    pub(super) fn branch_compare(
        thread: &mut EmulationThread,
        target: u64,
        op: CompareOp,
    ) -> Result<StepResult> {
        let right = thread.pop()?;
        let left = thread.pop()?;
        let result = left.compare(&right, op)?;

        // Compare returns EmValue::I32(0) or EmValue::I32(1), extract the boolean
        let is_true = match result {
            EmValue::I32(v) => v != 0,
            _ => false, // Symbolic or other types default to false
        };

        if is_true {
            Ok(StepResult::Branch { target })
        } else {
            Ok(StepResult::Continue)
        }
    }

    /// Branches based on unsigned comparison of two values from the stack.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `target` - The branch target offset.
    /// * `op` - The comparison operation to perform.
    ///
    /// # Returns
    ///
    /// `StepResult::Branch { target }` if the comparison is true, otherwise `StepResult::Continue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than two values or type mismatch occurs.
    pub(super) fn branch_compare_unsigned(
        thread: &mut EmulationThread,
        target: u64,
        op: CompareOp,
    ) -> Result<StepResult> {
        // For unsigned comparisons, we use the unsigned comparison ops
        Self::branch_compare(thread, target, op)
    }

    /// Executes a switch instruction.
    ///
    /// Pops an integer index from the stack and branches to the corresponding
    /// target. If the index is out of range, execution continues to the next instruction.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `instruction` - The switch instruction containing the jump table.
    ///
    /// # Returns
    ///
    /// `StepResult::Branch { target }` if the index is within the table,
    /// otherwise `StepResult::Continue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty or contains an unsupported type.
    pub(super) fn execute_switch(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let value = thread.pop()?;
        let index = match value {
            EmValue::I32(v) => match usize::try_from(v) {
                Ok(idx) => idx,
                Err(_) => return Ok(StepResult::Continue), // Negative - fall through
            },
            EmValue::NativeInt(v) => match usize::try_from(v) {
                Ok(idx) => idx,
                Err(_) => return Ok(StepResult::Continue), // Negative or overflow - fall through
            },
            // Handle symbolic values - fall through (default case)
            // This allows emulation to continue through unknown switch indices.
            EmValue::Symbolic(_) => return Ok(StepResult::Continue),
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "switch",
                    expected: "integer",
                    found: value.cil_flavor().as_str(),
                }
                .into())
            }
        };

        // Get switch targets from computed branch_targets (RVAs)
        // NOT from get_switch_targets() which are raw operand offsets
        let branch_targets = &instruction.branch_targets;

        if branch_targets.is_empty() {
            return Err(Self::invalid_operand(instruction, "switch branch targets"));
        }

        if index < branch_targets.len() {
            Ok(StepResult::Branch {
                target: branch_targets[index],
            })
        } else {
            // Fall through if index is out of range
            Ok(StepResult::Continue)
        }
    }

    /// Loads a string from the metadata string heap.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The ldstr instruction containing the string token.
    ///
    /// # Returns
    ///
    /// `StepResult::LoadString { token }` for the controller to resolve.
    ///
    /// # Errors
    ///
    /// Returns an error if the token operand is missing.
    pub(super) fn load_string(instruction: &Instruction) -> Result<StepResult> {
        let token = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;

        // Return LoadString result for the controller to handle string resolution
        Ok(StepResult::LoadString { token })
    }

    /// Creates a new array instance.
    ///
    /// Pops the length from the stack and returns a result for the controller
    /// to allocate the array with the specified element type.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `instruction` - The newarr instruction containing the element type token.
    ///
    /// # Returns
    ///
    /// `StepResult::NewArray { element_type, length }` for the controller to handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is negative or the operand is missing.
    pub(super) fn new_array(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let element_type = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
        let length_value = thread.pop()?;

        let length = match length_value {
            EmValue::I32(v) => usize::try_from(v).map_err(|_| {
                Error::from(EmulationError::ArrayIndexOutOfBounds {
                    index: i64::from(v),
                    length: 0,
                })
            })?,
            EmValue::NativeInt(v) => usize::try_from(v).map_err(|_| {
                Error::from(EmulationError::ArrayIndexOutOfBounds {
                    index: v,
                    length: 0,
                })
            })?,
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "newarr",
                    expected: "integer",
                    found: length_value.cil_flavor().as_str(),
                }
                .into())
            }
        };

        // Return NewArray result for the controller to handle type resolution and allocation
        Ok(StepResult::NewArray {
            element_type,
            length,
        })
    }

    /// Loads the length of an array onto the stack.
    ///
    /// Pops an array reference from the stack and pushes its length as a native unsigned integer.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is null or not an array reference.
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn load_array_length(thread: &mut EmulationThread) -> Result<StepResult> {
        let array_ref = thread.pop()?;

        match array_ref {
            EmValue::ObjectRef(href) => {
                let obj = thread.get_heap_object(href)?;
                let length = match obj {
                    HeapObject::Array { elements, .. } => elements.len(),
                    HeapObject::MultiArray { dimensions, .. } => dimensions.iter().product(),
                    HeapObject::String(s) => s.len(),
                    _ => {
                        return Err(EmulationError::TypeMismatch {
                            operation: "ldlen",
                            expected: "array",
                            found: "non-array object",
                        }
                        .into())
                    }
                };
                thread.push(EmValue::NativeUInt(length as u64))?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldlen",
                expected: "array reference",
                found: array_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Extracts an integer value from a heap object reference.
    ///
    /// This helper function tries to extract an integer index from an ObjectRef
    /// by examining the heap object. It supports:
    /// - Object with integer fields (common in obfuscated code with struct wrappers)
    /// - Object with nested ObjectRef fields (recursively checks up to 2 levels)
    /// - Single-element arrays containing integers
    /// - Multi-dimensional arrays with a single element
    fn extract_integer_from_object(thread: &EmulationThread, href: HeapRef) -> Option<i64> {
        if let Ok(obj) = thread.get_heap_object(href) {
            match obj {
                HeapObject::BoxedValue { value, .. } => {
                    // This shouldn't happen (get_boxed_value should have caught it)
                    // but handle it anyway
                    return value.try_to_i64();
                }
                HeapObject::Object { fields, .. } => {
                    // Try to find any integer-like value in the fields
                    for (_, field_value) in fields.iter() {
                        if let Some(int_val) = field_value.try_to_i64() {
                            return Some(int_val);
                        }
                        // Check nested ObjectRef (one level of indirection)
                        if let EmValue::ObjectRef(nested_href) = field_value {
                            if let Ok(boxed) = thread.heap().get_boxed_value(*nested_href) {
                                if let Some(int_val) = boxed.try_to_i64() {
                                    return Some(int_val);
                                }
                            }
                            // Also try recursively extracting from nested object
                            if let Some(int_val) =
                                Self::extract_integer_from_object(thread, *nested_href)
                            {
                                return Some(int_val);
                            }
                        }
                    }
                }
                HeapObject::Array { elements, .. } => {
                    // Check if it's a single-element array containing an integer
                    if elements.len() == 1 {
                        if let Some(int_val) = elements[0].try_to_i64() {
                            return Some(int_val);
                        }
                    }
                }
                HeapObject::MultiArray { elements, .. } => {
                    // Check if it's a single-element multi-array
                    if elements.len() == 1 {
                        if let Some(int_val) = elements[0].try_to_i64() {
                            return Some(int_val);
                        }
                    }
                }
                HeapObject::String(s) => {
                    // Try to parse the string as an integer (some obfuscators do this)
                    if let Ok(v) = s.parse::<i64>() {
                        return Some(v);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Extracts an integer index from an EmValue for array operations.
    ///
    /// This function handles various ways an index might be represented:
    /// - Direct integer types (I32, I64, NativeInt, NativeUInt)
    /// - Boxed integers (ObjectRef -> BoxedValue)
    /// - Object wrappers with integer fields
    /// - Single-element arrays containing integers
    fn extract_array_index(
        thread: &EmulationThread,
        index: &EmValue,
        operation: &'static str,
    ) -> Result<i64> {
        // First, try direct conversion for all integer-like types
        if let Some(v) = index.try_to_i64() {
            return Ok(v);
        }

        // Handle ObjectRef - could be boxed value or wrapper object
        if let EmValue::ObjectRef(href) = index {
            // Try boxed value first
            if let Ok(boxed_value) = thread.heap().get_boxed_value(*href) {
                if let Some(v) = boxed_value.try_to_i64() {
                    return Ok(v);
                }
            }

            // Try extracting from object/array structure
            if let Some(v) = Self::extract_integer_from_object(thread, *href) {
                return Ok(v);
            }
        }

        Err(EmulationError::TypeMismatch {
            operation,
            expected: "integer index",
            found: index.cil_flavor().as_str(),
        }
        .into())
    }

    /// Loads an element from an array onto the stack.
    ///
    /// Pops an index and array reference from the stack, retrieves the element,
    /// and pushes it onto the stack.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `_element_type` - The expected element type (used for type checking).
    ///
    /// # Errors
    ///
    /// Returns an error if the array is null, the index is out of bounds,
    /// or the value is not an array reference.
    pub(super) fn load_element(
        thread: &mut EmulationThread,
        expected_type: &CilFlavor,
    ) -> Result<StepResult> {
        let index = thread.pop()?;
        let array_ref = thread.pop()?;

        let idx = Self::extract_array_index(thread, &index, "ldelem")?;

        match array_ref {
            EmValue::ObjectRef(href) => {
                let obj = thread.get_heap_object(href)?;
                let element = match obj {
                    HeapObject::Array {
                        element_type,
                        elements,
                    } => {
                        // Verify the instruction's expected type matches the array's element type
                        if !expected_type.is_compatible_with(&element_type) {
                            return Err(EmulationError::TypeMismatch {
                                operation: "ldelem",
                                expected: expected_type.as_str(),
                                found: element_type.as_str(),
                            }
                            .into());
                        }

                        let array_idx = usize::try_from(idx).ok().filter(|&i| i < elements.len());
                        match array_idx {
                            Some(i) => elements[i].clone(),
                            None => {
                                return Err(EmulationError::ArrayIndexOutOfBounds {
                                    index: idx,
                                    length: elements.len(),
                                }
                                .into());
                            }
                        }
                    }
                    _ => {
                        return Err(EmulationError::TypeMismatch {
                            operation: "ldelem",
                            expected: "array",
                            found: "non-array object",
                        }
                        .into())
                    }
                };
                thread.push(element)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldelem",
                expected: "array reference",
                found: array_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Stores a value into an array element.
    ///
    /// Pops a value, index, and array reference from the stack and stores
    /// the value at the specified index.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `expected_type` - The expected element type (used for type checking).
    ///
    /// # Errors
    ///
    /// Returns an error if the array is null, the index is out of bounds,
    /// or the value is not an array reference.
    pub(super) fn store_element(
        thread: &mut EmulationThread,
        expected_type: &CilFlavor,
    ) -> Result<StepResult> {
        let value = thread.pop()?;
        let index = thread.pop()?;
        let array_ref = thread.pop()?;

        let idx = Self::extract_array_index(thread, &index, "stelem")?;

        let array_idx = usize::try_from(idx).map_err(|_| {
            Error::from(EmulationError::ArrayIndexOutOfBounds {
                index: idx,
                length: 0,
            })
        })?;

        // Verify the value's type is compatible with the expected element type
        let value_type = value.cil_flavor();
        if !value_type.is_compatible_with(expected_type) {
            return Err(EmulationError::TypeMismatch {
                operation: "stelem",
                expected: expected_type.as_str(),
                found: value_type.as_str(),
            }
            .into());
        }

        match array_ref {
            EmValue::ObjectRef(href) => {
                // Also verify against the array's declared element type
                let array_element_type = {
                    let obj = thread.get_heap_object(href)?;
                    match obj {
                        HeapObject::Array { element_type, .. } => element_type,
                        _ => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "stelem",
                                expected: "array",
                                found: "non-array object",
                            }
                            .into())
                        }
                    }
                };

                // Check type compatibility
                // Note: We allow flexible type checking for reference types because:
                // 1. Object can be stored into any reference type array (runtime checks actual type)
                // 2. The value might be a boxed value type that gets unboxed
                // 3. In deobfuscation context, decryptors often use Object arrays/boxing
                // 4. We prioritize functionality over strict type checking here
                let is_compatible = value_type.is_compatible_with(&array_element_type)
                    // Object -> any reference type (runtime type checking)
                    || (matches!(value_type, CilFlavor::Object)
                        && array_element_type.is_reference_type())
                    // Any reference type -> Object array
                    || (value_type.is_reference_type()
                        && matches!(array_element_type, CilFlavor::Object))
                    // Object -> value type (boxed value being stored)
                    || (matches!(value_type, CilFlavor::Object)
                        && array_element_type.is_value_type())
                    // Value type -> Object array (auto-boxing)
                    || (value_type.is_value_type()
                        && matches!(array_element_type, CilFlavor::Object));

                if !is_compatible {
                    return Err(EmulationError::TypeMismatch {
                        operation: "stelem",
                        expected: array_element_type.as_str(),
                        found: value_type.as_str(),
                    }
                    .into());
                }

                let heap = thread.heap_mut();
                heap.set_array_element(href, array_idx, value)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "stelem",
                expected: "array reference",
                found: array_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Loads the address of an array element onto the stack.
    ///
    /// Pops an index and array reference from the stack and pushes a managed
    /// pointer to the element.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    ///
    /// # Errors
    ///
    /// Returns an error if the array is null, the index is negative,
    /// or the value is not an array reference.
    pub(super) fn load_element_address(thread: &mut EmulationThread) -> Result<StepResult> {
        let index = thread.pop()?;
        let array_ref = thread.pop()?;

        let idx_i64 = match index {
            EmValue::I32(v) => i64::from(v),
            EmValue::NativeInt(v) => v,
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "ldelema",
                    expected: "integer index",
                    found: index.cil_flavor().as_str(),
                }
                .into())
            }
        };

        let idx = usize::try_from(idx_i64).map_err(|_| {
            Error::from(EmulationError::ArrayIndexOutOfBounds {
                index: idx_i64,
                length: 0,
            })
        })?;

        match array_ref {
            EmValue::ObjectRef(href) => {
                let ptr = EmValue::ManagedPtr(ManagedPointer::to_array_element(href, idx));
                thread.push(ptr)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldelema",
                expected: "array reference",
                found: array_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Loads an array element with an explicit type token.
    ///
    /// This is the generic ldelem instruction that takes a type token operand.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    ///
    /// # Errors
    ///
    /// Returns an error if the array is null or the index is out of bounds.
    pub(super) fn load_element_typed(thread: &mut EmulationThread) -> Result<StepResult> {
        // ldelem <type> - same as ldelem.* but with explicit type token
        Self::load_element(thread, &CilFlavor::Object)
    }

    /// Stores an array element with an explicit type token.
    ///
    /// This is the generic stelem instruction that takes a type token operand.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    ///
    /// # Errors
    ///
    /// Returns an error if the array is null or the index is out of bounds.
    pub(super) fn store_element_typed(thread: &mut EmulationThread) -> Result<StepResult> {
        // stelem <type> - same as stelem.* but with explicit type token
        Self::store_element(thread, &CilFlavor::Object)
    }

    /// Loads an instance field value onto the stack.
    ///
    /// Pops an object reference from the stack and pushes the field value.
    /// If the field was not initialized in the object's field map, a symbolic
    /// value with [`TaintSource::Field`] is returned to track the unknown origin.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread.
    /// * `instruction` - The ldfld instruction containing the field token.
    ///
    /// # Errors
    ///
    /// Returns an error if the object is null or not an object reference.
    ///
    /// [`TaintSource::Field`]: crate::emulation::TaintSource::Field
    pub(super) fn load_field(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let field_token = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
        let obj_ref = thread.pop()?;

        // Helper to load field from heap reference
        let load_from_href = |thread: &mut EmulationThread, href: HeapRef| -> Result<StepResult> {
            let obj = thread.get_heap_object(href)?;
            match obj {
                HeapObject::Object { fields, .. } => {
                    let value = fields.get(&field_token).cloned().unwrap_or_else(|| {
                        // Return symbolic for uninitialized instance fields.
                        // Using Object flavor since we don't know the actual type.
                        EmValue::Symbolic(SymbolicValue::new(
                            CilFlavor::Object,
                            TaintSource::Field(field_token.value()),
                        ))
                    });
                    thread.push(value)?;
                    Ok(StepResult::Continue)
                }
                _ => Err(EmulationError::TypeMismatch {
                    operation: "ldfld",
                    expected: "object",
                    found: "non-object",
                }
                .into()),
            }
        };

        // Helper to extract a field from a ValueType
        // Uses the assembly metadata to calculate the field index
        let load_from_valuetype =
            |thread: &mut EmulationThread, value: EmValue| -> Result<StepResult> {
                if let EmValue::ValueType { type_token, fields } = value {
                    // Calculate field index within the type
                    // Field index = field_token.row - type's field_list start
                    if let Some(assembly) = thread.assembly() {
                        if let Some(field_idx) = assembly
                            .types()
                            .get_field_index_in_type(&type_token, &field_token)
                        {
                            if let Some(field_value) = fields.get(field_idx) {
                                thread.push(field_value.clone())?;
                                return Ok(StepResult::Continue);
                            }
                        }
                    }
                    // Field not found in ValueType - return default value (0)
                    // This handles the case where a struct field was never initialized
                    thread.push(EmValue::I32(0))?;
                    Ok(StepResult::Continue)
                } else if matches!(value, EmValue::Void) {
                    // Void is the default for uninitialized ValueType locals
                    // Return default value (0) for struct fields
                    thread.push(EmValue::I32(0))?;
                    Ok(StepResult::Continue)
                } else {
                    // Not a ValueType - return symbolic
                    thread.push(EmValue::Symbolic(SymbolicValue::new(
                        CilFlavor::Object,
                        TaintSource::Field(field_token.value()),
                    )))?;
                    Ok(StepResult::Continue)
                }
            };

        match obj_ref {
            EmValue::ObjectRef(href) => load_from_href(thread, href),
            // Handle ValueType directly (e.g., from ldloc of a struct)
            EmValue::ValueType { .. } => load_from_valuetype(thread, obj_ref),
            // CIL allows ldfld with a managed pointer to the object
            EmValue::ManagedPtr(ptr) => {
                match &ptr.target {
                    PointerTarget::ObjectField { object, .. } => {
                        // Pointer to an object's field - use that object
                        load_from_href(thread, *object)
                    }
                    PointerTarget::Local(idx) => {
                        let local_value = thread.get_local(usize::from(*idx))?;
                        match &local_value {
                            EmValue::ObjectRef(href) => load_from_href(thread, *href),
                            EmValue::ValueType { .. } | EmValue::Void => {
                                // ValueType or Void (default-initialized ValueType)
                                load_from_valuetype(thread, local_value.clone())
                            }
                            _ => {
                                // Dereference pointer for other value types
                                let value = thread.deref_pointer(&ptr)?;
                                if matches!(value, EmValue::ValueType { .. } | EmValue::Void) {
                                    load_from_valuetype(thread, value)
                                } else {
                                    thread.push(value)?;
                                    Ok(StepResult::Continue)
                                }
                            }
                        }
                    }
                    PointerTarget::Argument(idx) => {
                        let arg_value = thread.get_arg(usize::from(*idx))?;
                        match &arg_value {
                            EmValue::ObjectRef(href) => load_from_href(thread, *href),
                            EmValue::ValueType { .. } | EmValue::Void => {
                                // ValueType or Void (default-initialized ValueType)
                                load_from_valuetype(thread, arg_value.clone())
                            }
                            _ => {
                                let value = thread.deref_pointer(&ptr)?;
                                if matches!(value, EmValue::ValueType { .. } | EmValue::Void) {
                                    load_from_valuetype(thread, value)
                                } else {
                                    thread.push(value)?;
                                    Ok(StepResult::Continue)
                                }
                            }
                        }
                    }
                    _ => {
                        // Dereference pointer for other cases
                        let value = thread.deref_pointer(&ptr)?;
                        if matches!(value, EmValue::ValueType { .. } | EmValue::Void) {
                            load_from_valuetype(thread, value)
                        } else {
                            thread.push(value)?;
                            Ok(StepResult::Continue)
                        }
                    }
                }
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldfld",
                expected: "object reference",
                found: obj_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Loads the address of an instance field onto the stack.
    ///
    /// Pops an object reference from the stack and pushes a managed pointer
    /// to the field.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `instruction` - The ldflda instruction containing the field token.
    ///
    /// # Errors
    ///
    /// Returns an error if the object is null or not an object reference.
    pub(super) fn load_field_address(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let field_token = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
        let obj_ref = thread.pop()?;

        match obj_ref {
            EmValue::ObjectRef(href) => {
                let ptr = EmValue::ManagedPtr(ManagedPointer::to_object_field(href, field_token));
                thread.push(ptr)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldflda",
                expected: "object reference",
                found: obj_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Stores a value into an instance field.
    ///
    /// Pops a value and object reference from the stack and stores the value
    /// in the specified field.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `instruction` - The stfld instruction containing the field token.
    ///
    /// # Errors
    ///
    /// Returns an error if the object is null or not an object reference.
    pub(super) fn store_field(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let field_token = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
        let value = thread.pop()?;
        let obj_ref = thread.pop()?;

        // Helper to store field into a ValueType and return the updated ValueType
        let store_into_valuetype = |thread: &EmulationThread,
                                    vt: EmValue,
                                    field_token: Token,
                                    value: EmValue|
         -> Option<EmValue> {
            if let EmValue::ValueType {
                type_token,
                mut fields,
            } = vt
            {
                // Get the field index
                if let Some(assembly) = thread.assembly() {
                    if let Some(field_idx) = assembly
                        .types()
                        .get_field_index_in_type(&type_token, &field_token)
                    {
                        // Ensure the fields vector is large enough
                        while fields.len() <= field_idx {
                            fields.push(EmValue::I32(0)); // Default to 0
                        }
                        fields[field_idx] = value;
                        return Some(EmValue::ValueType { type_token, fields });
                    }
                }
            }
            None
        };

        match obj_ref {
            EmValue::ObjectRef(href) => {
                let heap = thread.heap_mut();
                heap.set_field(href, field_token, value)?;
                Ok(StepResult::Continue)
            }
            // CIL allows stfld with a managed pointer to the object
            // The pointer can point to the start of the object (from ldloca etc.)
            // or can be a pointer to a nested object within a value type
            EmValue::ManagedPtr(ptr) => {
                // If pointing to an object, use the object's heap reference
                // Otherwise store through the pointer (for value types)
                match &ptr.target {
                    PointerTarget::ObjectField { object, .. } => {
                        // Pointer to an object's field - use the object ref to set the field
                        let heap = thread.heap_mut();
                        heap.set_field(*object, field_token, value)?;
                        Ok(StepResult::Continue)
                    }
                    PointerTarget::Local(idx) => {
                        // Pointer to a local variable
                        let local_idx = usize::from(*idx);
                        let local_value = thread.get_local(local_idx)?;
                        match &local_value {
                            EmValue::ObjectRef(href) => {
                                let heap = thread.heap_mut();
                                heap.set_field(*href, field_token, value)?;
                                Ok(StepResult::Continue)
                            }
                            EmValue::ValueType { .. } => {
                                // Update the field in the ValueType and store back
                                if let Some(updated) = store_into_valuetype(
                                    thread,
                                    local_value.clone(),
                                    field_token,
                                    value.clone(),
                                ) {
                                    thread.set_local(local_idx, updated)?;
                                    Ok(StepResult::Continue)
                                } else {
                                    // Fallback: store through pointer
                                    thread.store_through_pointer(&ptr, value)?;
                                    Ok(StepResult::Continue)
                                }
                            }
                            _ => {
                                // Store through pointer for other types
                                thread.store_through_pointer(&ptr, value)?;
                                Ok(StepResult::Continue)
                            }
                        }
                    }
                    PointerTarget::Argument(idx) => {
                        // Pointer to an argument
                        let arg_idx = usize::from(*idx);
                        let arg_value = thread.get_arg(arg_idx)?;
                        match &arg_value {
                            EmValue::ObjectRef(href) => {
                                let heap = thread.heap_mut();
                                heap.set_field(*href, field_token, value)?;
                                Ok(StepResult::Continue)
                            }
                            EmValue::ValueType { .. } => {
                                // Update the field in the ValueType and store back
                                if let Some(updated) = store_into_valuetype(
                                    thread,
                                    arg_value.clone(),
                                    field_token,
                                    value.clone(),
                                ) {
                                    thread.set_arg(arg_idx, updated)?;
                                    Ok(StepResult::Continue)
                                } else {
                                    thread.store_through_pointer(&ptr, value)?;
                                    Ok(StepResult::Continue)
                                }
                            }
                            _ => {
                                thread.store_through_pointer(&ptr, value)?;
                                Ok(StepResult::Continue)
                            }
                        }
                    }
                    _ => {
                        // For other pointer targets, store through the pointer
                        thread.store_through_pointer(&ptr, value)?;
                        Ok(StepResult::Continue)
                    }
                }
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "stfld",
                expected: "object reference",
                found: obj_ref.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Loads a static field value.
    ///
    /// Returns a result for the controller to resolve and push the static field value.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The ldsfld instruction containing the field token.
    ///
    /// # Returns
    ///
    /// `StepResult::LoadStaticField { field }` for the controller to handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the field token operand is missing.
    pub(super) fn load_static_field(instruction: &Instruction) -> Result<StepResult> {
        let field = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;

        // Return LoadStaticField result for the controller to handle
        Ok(StepResult::LoadStaticField { field })
    }

    /// Loads the address of a static field onto the stack.
    ///
    /// Pushes a managed pointer to the static field.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `instruction` - The ldsflda instruction containing the field token.
    ///
    /// # Errors
    ///
    /// Returns an error if the field token operand is missing.
    pub(super) fn load_static_field_address(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let field_token = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
        let ptr = EmValue::ManagedPtr(ManagedPointer::to_static_field(field_token));
        thread.push(ptr)?;
        Ok(StepResult::Continue)
    }

    /// Stores a value into a static field.
    ///
    /// Pops a value from the stack and returns a result for the controller
    /// to store it in the static field.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `instruction` - The stsfld instruction containing the field token.
    ///
    /// # Returns
    ///
    /// `StepResult::StoreStaticField { field, value }` for the controller to handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the field token operand is missing.
    pub(super) fn store_static_field(
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        let field = instruction
            .get_token_operand()
            .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
        let value = thread.pop()?;

        // Return StoreStaticField result for the controller to handle
        Ok(StepResult::StoreStaticField { field, value })
    }

    /// Loads a value indirectly through a pointer.
    ///
    /// Pops a pointer from the stack, dereferences it, and pushes the value.
    /// Verifies that the loaded value's type matches the expected type.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `expected_type` - The expected stack type of the loaded value.
    /// * `read_size` - The number of bytes to read from memory (1, 2, 4, 8).
    /// * `signed` - Whether to sign-extend the value.
    ///
    /// # Errors
    ///
    /// Returns an error if the pointer is null, unmanaged (not supported),
    /// or not a pointer type.
    pub(super) fn load_indirect_sized(
        thread: &mut EmulationThread,
        address_space: &Arc<AddressSpace>,
        expected_type: &CilFlavor,
        read_size: usize,
        signed: bool,
    ) -> Result<StepResult> {
        let addr = thread.pop()?;

        match addr {
            EmValue::ManagedPtr(ptr) => {
                // Dereference the managed pointer
                let value = thread.deref_pointer(&ptr)?;

                // Verify the loaded value's type matches the expected type
                let value_type = value.cil_flavor();
                if !value_type.is_compatible_with(expected_type) {
                    return Err(EmulationError::TypeMismatch {
                        operation: "ldind",
                        expected: expected_type.as_str(),
                        found: value_type.as_str(),
                    }
                    .into());
                }

                thread.push(value)?;
                Ok(StepResult::Continue)
            }
            EmValue::UnmanagedPtr(_) | EmValue::NativeInt(_) | EmValue::NativeUInt(_) => {
                // For unmanaged pointers (or native integers used as pointers),
                // read from the shared address space (PE images, mapped data, etc.)
                #[allow(clippy::cast_sign_loss)]
                let ptr_addr = match &addr {
                    EmValue::UnmanagedPtr(p) | EmValue::NativeUInt(p) => *p,
                    EmValue::NativeInt(p) => *p as u64,
                    _ => unreachable!(),
                };

                // Read from address space based on read_size and expected_type
                let value = match (expected_type, read_size) {
                    // Small integer reads (1 or 2 bytes) that widen to I32
                    (&CilFlavor::I4, 1) => {
                        let bytes = address_space.read(ptr_addr, 1)?;
                        let val = if signed {
                            i32::from(bytes[0] as i8)
                        } else {
                            i32::from(bytes[0])
                        };
                        EmValue::I32(val)
                    }
                    (&CilFlavor::I4, 2) => {
                        let bytes = address_space.read(ptr_addr, 2)?;
                        let val = if signed {
                            i32::from(i16::from_le_bytes([bytes[0], bytes[1]]))
                        } else {
                            i32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
                        };
                        EmValue::I32(val)
                    }
                    (&CilFlavor::I4, _) => {
                        let bytes = address_space.read(ptr_addr, 4)?;
                        let val = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        EmValue::I32(val)
                    }
                    (&CilFlavor::I8, _) => {
                        let bytes = address_space.read(ptr_addr, 8)?;
                        let val = i64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        EmValue::I64(val)
                    }
                    (&CilFlavor::I, _) => {
                        // Native int is pointer-sized: 4 bytes on PE32, 8 bytes on PE32+
                        let bytes = address_space.read(ptr_addr, read_size)?;
                        let val = if read_size == 4 {
                            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64
                        } else {
                            i64::from_le_bytes([
                                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                                bytes[6], bytes[7],
                            ])
                        };
                        EmValue::NativeInt(val)
                    }
                    (&CilFlavor::R4, _) => {
                        let bytes = address_space.read(ptr_addr, 4)?;
                        let val = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        EmValue::F32(val)
                    }
                    (&CilFlavor::R8, _) => {
                        let bytes = address_space.read(ptr_addr, 8)?;
                        let val = f64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        EmValue::F64(val)
                    }
                    (&CilFlavor::Object, _) => {
                        // For object references, treat as pointer-sized value
                        let bytes = address_space.read(ptr_addr, read_size)?;
                        let val = if read_size == 4 {
                            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                        } else {
                            u64::from_le_bytes([
                                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                                bytes[6], bytes[7],
                            ])
                        };
                        EmValue::UnmanagedPtr(val)
                    }
                    (_, _) => {
                        return Err(EmulationError::TypeMismatch {
                            operation: "ldind (address space)",
                            expected: expected_type.as_str(),
                            found: "unsupported type",
                        }
                        .into())
                    }
                };

                thread.push(value)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            EmValue::Symbolic(sym) => {
                // Symbolic pointer - return symbolic result
                // Check if the symbolic value has a pointer-like type
                match sym.cil_flavor {
                    CilFlavor::I | CilFlavor::Pointer | CilFlavor::ByRef => {
                        // Return a symbolic value with the expected type derived from this one
                        let mut result =
                            SymbolicValue::derived_from(expected_type.clone(), vec![sym.id]);
                        // Update name to indicate this is a dereference
                        if let Some(ref name) = sym.name {
                            result.name = Some(format!("*{name}"));
                        }
                        thread.push(EmValue::Symbolic(result))?;
                        Ok(StepResult::Continue)
                    }
                    _ => Err(EmulationError::TypeMismatch {
                        operation: "ldind (symbolic)",
                        expected: "pointer",
                        found: sym.cil_flavor.as_str(),
                    }
                    .into()),
                }
            }
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldind",
                expected: "pointer",
                found: addr.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Stores a value indirectly through a pointer.
    ///
    /// Pops a value and pointer from the stack and stores the value at the
    /// pointed-to location. Verifies that the value's type matches the expected type.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `address_space` - The shared address space for memory writes.
    /// * `expected_type` - The expected stack type of the value being stored.
    /// * `write_size` - The number of bytes to write.
    ///
    /// # Errors
    ///
    /// Returns an error if the pointer is null or not a pointer type.
    pub(super) fn store_indirect_sized(
        thread: &mut EmulationThread,
        address_space: &Arc<AddressSpace>,
        expected_type: &CilFlavor,
        write_size: usize,
    ) -> Result<StepResult> {
        let value = thread.pop()?;
        let addr = thread.pop()?;

        // Verify the value's type matches the expected type
        let value_type = value.cil_flavor();
        if !value_type.is_compatible_with(expected_type) {
            return Err(EmulationError::TypeMismatch {
                operation: "stind",
                expected: expected_type.as_str(),
                found: value_type.as_str(),
            }
            .into());
        }

        match addr {
            EmValue::ManagedPtr(ptr) => {
                // Store through the managed pointer
                thread.store_through_pointer(&ptr, value)?;
                Ok(StepResult::Continue)
            }
            EmValue::UnmanagedPtr(_) | EmValue::NativeInt(_) | EmValue::NativeUInt(_) => {
                // Store to address space (PE images, mapped data, etc.)
                #[allow(clippy::cast_sign_loss)]
                let ptr_addr = match &addr {
                    EmValue::UnmanagedPtr(p) | EmValue::NativeUInt(p) => *p,
                    EmValue::NativeInt(p) => *p as u64,
                    _ => unreachable!(),
                };

                // Convert value to bytes based on write_size and expected_type
                let bytes: Vec<u8> = match (expected_type, write_size) {
                    // Small integer writes (1 or 2 bytes) from I32
                    (&CilFlavor::I4, 1) => {
                        let v = match &value {
                            EmValue::I32(v) => *v as u8,
                            _ => {
                                return Err(EmulationError::TypeMismatch {
                                    operation: "stind.i1",
                                    expected: "int32",
                                    found: value.cil_flavor().as_str(),
                                }
                                .into());
                            }
                        };
                        vec![v]
                    }
                    (&CilFlavor::I4, 2) => {
                        let v = match &value {
                            EmValue::I32(v) => *v as u16,
                            _ => {
                                return Err(EmulationError::TypeMismatch {
                                    operation: "stind.i2",
                                    expected: "int32",
                                    found: value.cil_flavor().as_str(),
                                }
                                .into());
                            }
                        };
                        v.to_le_bytes().to_vec()
                    }
                    (&CilFlavor::I4, _) => {
                        let v = match &value {
                            EmValue::I32(v) => *v,
                            _ => {
                                return Err(EmulationError::TypeMismatch {
                                    operation: "stind.i4",
                                    expected: "int32",
                                    found: value.cil_flavor().as_str(),
                                }
                                .into());
                            }
                        };
                        v.to_le_bytes().to_vec()
                    }
                    (&CilFlavor::I8, _) => match &value {
                        EmValue::I64(v) => v.to_le_bytes().to_vec(),
                        _ => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "stind.i8",
                                expected: "int64",
                                found: value.cil_flavor().as_str(),
                            }
                            .into());
                        }
                    },
                    (&CilFlavor::I, _) => match &value {
                        EmValue::NativeInt(v) => match write_size {
                            4 => (*v as i32).to_le_bytes().to_vec(),
                            _ => v.to_le_bytes().to_vec(),
                        },
                        EmValue::NativeUInt(v) => match write_size {
                            4 => (*v as u32).to_le_bytes().to_vec(),
                            _ => v.to_le_bytes().to_vec(),
                        },
                        _ => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "stind.i",
                                expected: "native int",
                                found: value.cil_flavor().as_str(),
                            }
                            .into());
                        }
                    },
                    (&CilFlavor::R4, _) => match &value {
                        EmValue::F32(v) => v.to_le_bytes().to_vec(),
                        _ => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "stind.r4",
                                expected: "float32",
                                found: value.cil_flavor().as_str(),
                            }
                            .into());
                        }
                    },
                    (&CilFlavor::R8, _) => match &value {
                        EmValue::F64(v) => v.to_le_bytes().to_vec(),
                        _ => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "stind.r8",
                                expected: "float64",
                                found: value.cil_flavor().as_str(),
                            }
                            .into());
                        }
                    },
                    #[allow(clippy::match_same_arms)]
                    (&CilFlavor::Object, _) => match &value {
                        EmValue::UnmanagedPtr(v) | EmValue::NativeUInt(v) => match write_size {
                            4 => (*v as u32).to_le_bytes().to_vec(),
                            _ => v.to_le_bytes().to_vec(),
                        },
                        EmValue::NativeInt(v) => match write_size {
                            4 => (*v as i32).to_le_bytes().to_vec(),
                            _ => v.to_le_bytes().to_vec(),
                        },
                        _ => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "stind.ref",
                                expected: "object reference",
                                found: value.cil_flavor().as_str(),
                            }
                            .into());
                        }
                    },
                    (_, _) => {
                        return Err(EmulationError::TypeMismatch {
                            operation: "stind (address space)",
                            expected: "primitive value",
                            found: value.cil_flavor().as_str(),
                        }
                        .into());
                    }
                };

                address_space.write(ptr_addr, &bytes)?;
                Ok(StepResult::Continue)
            }
            EmValue::Symbolic(sym) => {
                // Symbolic pointer - silently succeed but don't actually write
                // This allows emulation to continue even with symbolic addresses
                match sym.cil_flavor {
                    CilFlavor::I | CilFlavor::Pointer | CilFlavor::ByRef => {
                        // Just succeed without writing - we can't write to a symbolic address
                        Ok(StepResult::Continue)
                    }
                    _ => Err(EmulationError::TypeMismatch {
                        operation: "stind (symbolic)",
                        expected: "pointer",
                        found: sym.cil_flavor.as_str(),
                    }
                    .into()),
                }
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "stind",
                expected: "pointer",
                found: addr.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Loads a value type from an address onto the stack.
    ///
    /// Pops a pointer from the stack, loads the value type at that address,
    /// and pushes it onto the stack. The type token is used for validation
    /// but full token resolution requires assembly context.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `type_token` - The type token of the value type (used for logging/debugging).
    ///
    /// # Errors
    ///
    /// Returns an error if the pointer is null or not a pointer type.
    pub(super) fn load_object(
        thread: &mut EmulationThread,
        type_token: Token,
    ) -> Result<StepResult> {
        let addr = thread.pop()?;

        match addr {
            EmValue::ManagedPtr(ptr) => {
                // Load the value type from the address
                let value = thread.deref_pointer(&ptr)?;

                // Verify this is a value type operation (ldobj is for value types)
                let value_type = value.cil_flavor();
                let is_value_type = value_type == CilFlavor::ValueType
                    || value_type == CilFlavor::I4
                    || value_type == CilFlavor::I8
                    || value_type == CilFlavor::R4
                    || value_type == CilFlavor::R8
                    || value_type == CilFlavor::I;
                if !is_value_type {
                    let _ = type_token; // Token available for future type resolution
                    return Err(EmulationError::TypeMismatch {
                        operation: "ldobj",
                        expected: "value type",
                        found: value_type.as_str(),
                    }
                    .into());
                }

                thread.push(value)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "ldobj",
                expected: "pointer",
                found: addr.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Stores a value type to an address.
    ///
    /// Pops a value and pointer from the stack and stores the value at the
    /// pointed-to location. The type token is used for validation but full
    /// token resolution requires assembly context.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    /// * `type_token` - The type token of the value type (used for logging/debugging).
    ///
    /// # Errors
    ///
    /// Returns an error if the pointer is null or not a pointer type.
    pub(super) fn store_object(
        thread: &mut EmulationThread,
        type_token: Token,
    ) -> Result<StepResult> {
        let value = thread.pop()?;
        let addr = thread.pop()?;

        // Verify this is a value type operation (stobj is for value types)
        let value_type = value.cil_flavor();
        let is_value_type = value_type == CilFlavor::ValueType
            || value_type == CilFlavor::I4
            || value_type == CilFlavor::I8
            || value_type == CilFlavor::R4
            || value_type == CilFlavor::R8
            || value_type == CilFlavor::I;
        if !is_value_type {
            let _ = type_token; // Token available for future type resolution
            return Err(EmulationError::TypeMismatch {
                operation: "stobj",
                expected: "value type",
                found: value_type.as_str(),
            }
            .into());
        }

        match addr {
            EmValue::ManagedPtr(ptr) => {
                thread.store_through_pointer(&ptr, value)?;
                Ok(StepResult::Continue)
            }
            EmValue::Null => Err(EmulationError::NullReference.into()),
            _ => Err(EmulationError::TypeMismatch {
                operation: "stobj",
                expected: "pointer",
                found: addr.cil_flavor().as_str(),
            }
            .into()),
        }
    }

    /// Checks that a floating-point value is finite.
    ///
    /// Pops a float from the stack. If it's finite (not NaN or infinity),
    /// pushes it back. Otherwise, throws an arithmetic exception.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is NaN, infinity, or not a float type.
    pub(super) fn check_finite(thread: &mut EmulationThread) -> Result<StepResult> {
        let value = thread.pop()?;

        match value {
            EmValue::F32(v) => {
                if v.is_finite() {
                    thread.push(EmValue::F32(v))?;
                    Ok(StepResult::Continue)
                } else {
                    Err(EmulationError::ArithmeticOverflow.into())
                }
            }
            EmValue::F64(v) => {
                if v.is_finite() {
                    thread.push(EmValue::F64(v))?;
                    Ok(StepResult::Continue)
                } else {
                    Err(EmulationError::ArithmeticOverflow.into())
                }
            }
            _ => Err(EmulationError::TypeMismatch {
                operation: "ckfinite",
                expected: "float",
                found: value.cil_flavor().as_str(),
            }
            .into()),
        }
    }
}
