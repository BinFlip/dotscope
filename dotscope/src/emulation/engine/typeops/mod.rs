//! Type-related instruction handlers for the emulation engine.
//!
//! This module contains handlers for CIL instructions that operate on types
//! or the managed heap. These are extracted from the
//! [`EmulationController`](super::controller::EmulationController) to keep
//! the orchestration layer focused on execution flow.
//!
//! # Instruction Coverage
//!
//! | Instruction | Handler | Description |
//! |-------------|---------|-------------|
//! | `newarr` | [`handle_newarr`] | Allocate a zero-based single-dimension array |
//! | `ldstr` | [`handle_ldstr`] | Load a string literal from the `#US` heap |
//! | `box` | [`handle_box`] | Box a value type into an `ObjectRef` |
//! | `unbox` / `unbox.any` | [`handle_unbox`] | Extract the value from a boxed object |
//! | `castclass` | [`handle_castclass`] | Cast with `InvalidCastException` on failure |
//! | `isinst` | [`handle_isinst`] | Type-test returning null on failure |
//! | `sizeof` | [`handle_sizeof`] | Push the byte size of a value type |
//! | `initobj` | [`handle_initobj`] | Zero-initialize a value type at an address |
//! | `cpobj` | [`handle_cpobj`] | Copy a value type between addresses |
//! | `cpblk` | [`handle_cpblk`] | Copy a block of unmanaged memory |
//! | `initblk` | [`handle_initblk`] | Fill a block of unmanaged memory |
//! | `ldsfld` | [`handle_ldsfld`] | Load a static field value |
//! | `newobj` | [`resolve_newobj`] | Allocate an object and resolve its constructor |
//!
//! # Object Allocation
//!
//! [`resolve_newobj`] handles the full `newobj` lifecycle: allocating the
//! object on the managed heap, checking for constructor hooks, detecting
//! delegate constructors (`.ctor(object, IntPtr)`), and returning a
//! [`NewObjResolution`](super::resolution::NewObjResolution) that tells the
//! controller whether to enter the constructor body, bypass via hook, or
//! handle the object as a delegate.

mod boxing;
mod memory;
mod newobj;

pub use boxing::{handle_box, handle_castclass, handle_isinst, handle_unbox};
pub use memory::{deref_managed_ptr, handle_cpblk, handle_cpobj, handle_initblk, handle_initobj};
pub use newobj::resolve_newobj;

use crate::{
    emulation::{
        engine::context::EmulationContext, memory::AddressSpace, runtime::get_bcl_static_field,
        thread::EmulationThread, EmValue,
    },
    metadata::{
        tables::TableId,
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
    Result,
};

/// Handles `newarr` instruction — creates a new array.
///
/// Allocates a single-dimension zero-based array on the managed heap
/// with the specified element type and length.
///
/// # Arguments
///
/// * `thread` - The emulation thread (for heap access and stack push)
/// * `context` - The emulation context (for type resolution)
/// * `element_type` - Token of the array element type
/// * `length` - Number of elements in the array
///
/// # Errors
///
/// Returns an error if type resolution or heap allocation fails.
pub fn handle_newarr(
    thread: &mut EmulationThread,
    context: &EmulationContext,
    element_type: Token,
    length: usize,
) -> Result<()> {
    let cil_flavor = context.type_token_to_cil_flavor(element_type)?;
    let array_ref = thread.heap_mut().alloc_array(cil_flavor, length)?;
    thread.push(EmValue::ObjectRef(array_ref))?;
    Ok(())
}

/// Handles `ldstr` instruction — loads a string literal.
///
/// Retrieves a string from the assembly's user string heap and allocates
/// it on the managed heap. The string reference is pushed onto the stack.
///
/// # Arguments
///
/// * `thread` - The emulation thread (for heap and stack access)
/// * `context` - The emulation context (for user string lookup)
/// * `token` - User string token (0x70XXXXXX format)
///
/// # Errors
///
/// Returns an error if the string is not found or heap allocation fails.
pub fn handle_ldstr(
    thread: &mut EmulationThread,
    context: &EmulationContext,
    token: Token,
) -> Result<()> {
    let index = token.value() & 0x00FF_FFFF;
    let string = context.get_user_string(index)?;
    let str_ref = thread.heap_mut().alloc_string(&string)?;
    thread.push(EmValue::ObjectRef(str_ref))?;
    Ok(())
}

/// Handles `sizeof` instruction — gets the size of a value type.
///
/// Uses the context's type system to look up the size of the type
/// and pushes it as an `I32` value onto the evaluation stack.
///
/// # Arguments
///
/// * `thread` - The emulation thread (for stack push)
/// * `context` - The emulation context (for type size lookup)
/// * `type_token` - Token of the type to get the size of
/// * `pointer_size` - Target platform pointer size
///
/// # Errors
///
/// Returns an error if the stack is full.
pub fn handle_sizeof(
    thread: &mut EmulationThread,
    context: &EmulationContext,
    type_token: Token,
    pointer_size: PointerSize,
) -> Result<()> {
    let size = context.get_type_size(type_token, pointer_size);

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    thread.push(EmValue::I32(size as i32))?;
    Ok(())
}

/// Handles `ldsfld` instruction — loads a static field value.
///
/// Retrieves the value of a static field from the address space's static
/// field storage. For known BCL static fields accessed via MemberRef (external
/// assemblies), returns appropriate concrete values. If the owning type has been
/// initialized but the field wasn't stored, returns the .NET zero-default per
/// ECMA-335. Unknown fields return a symbolic value for tracking.
///
/// # Arguments
///
/// * `address_space` - The shared address space for static field storage
/// * `thread` - The emulation thread (for stack push)
/// * `context` - The emulation context for MemberRef lookup
/// * `field` - Token of the static field to load
///
/// # Errors
///
/// Returns an error if the stack is full.
pub fn handle_ldsfld(
    address_space: &AddressSpace,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    field: Token,
) -> Result<()> {
    if let Some(value) = address_space.get_static(field)? {
        thread.push(value)?;
        return Ok(());
    }

    if field.is_table(TableId::MemberRef) {
        if let Some(member_ref) = context.get_member_ref(field) {
            if let Some((namespace, type_name)) =
                EmulationContext::get_member_ref_type_info(&member_ref)
            {
                if let Some(value) =
                    get_bcl_static_field(&namespace, &type_name, &member_ref.name, thread.heap())
                {
                    thread.push(value)?;
                    return Ok(());
                }
            }
        }
    }

    if let Some((type_token, flavor)) = context.get_field_type_info(field) {
        if address_space.statics().is_type_initialized(type_token)? {
            let default_value = match flavor {
                CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4 => EmValue::I32(0),
                CilFlavor::I8 | CilFlavor::U8 => EmValue::I64(0),
                CilFlavor::R4 => EmValue::F32(0.0),
                CilFlavor::R8 => EmValue::F64(0.0),
                CilFlavor::I | CilFlavor::U => EmValue::NativeInt(0),
                _ => EmValue::Null,
            };
            thread.push(default_value)?;
            return Ok(());
        }
    }

    // .NET zero-initializes all static fields before any code runs.
    // If we have type info, use the type-appropriate default; otherwise use Null
    // (correct for reference types, the common case for unknown-type fields).
    if let Some((_type_token, flavor)) = context.get_field_type_info(field) {
        let default_value = match flavor {
            CilFlavor::Boolean
            | CilFlavor::Char
            | CilFlavor::I1
            | CilFlavor::U1
            | CilFlavor::I2
            | CilFlavor::U2
            | CilFlavor::I4
            | CilFlavor::U4 => EmValue::I32(0),
            CilFlavor::I8 | CilFlavor::U8 => EmValue::I64(0),
            CilFlavor::R4 => EmValue::F32(0.0),
            CilFlavor::R8 => EmValue::F64(0.0),
            CilFlavor::I | CilFlavor::U => EmValue::NativeInt(0),
            _ => EmValue::Null,
        };
        thread.push(default_value)?;
    } else {
        thread.push(EmValue::Null)?;
    }
    Ok(())
}
