//! Memory and pointer operations for CIL emulation.
//!
//! Handles `initobj`, `cpobj`, `cpblk`, `initblk` instructions and managed pointer
//! dereferencing.

use log::trace;

use crate::{
    emulation::{
        engine::{context::EmulationContext, EmulationError},
        memory::AddressSpace,
        thread::EmulationThread,
        EmValue, ManagedPointer, PointerTarget,
    },
    metadata::{signatures::TypeSignature, tables::TableId, token::Token},
    Result,
};

/// Dereferences a managed pointer to read the value it points to.
///
/// Reads from the target location (local, argument, array element, object field,
/// or static field) and returns the value. Used by constrained callvirt boxing
/// to read the value type before boxing it.
///
/// # Arguments
///
/// * `address_space` - Address space for static field access
/// * `thread` - The emulation thread for frame/heap access
/// * `ptr` - The managed pointer to dereference
pub fn deref_managed_ptr(
    address_space: &AddressSpace,
    thread: &EmulationThread,
    ptr: &ManagedPointer,
) -> Result<EmValue> {
    match &ptr.target {
        PointerTarget::Local(idx) => {
            let frame = thread
                .get_frame_at(ptr.frame_depth)
                .or_else(|| thread.current_frame())
                .ok_or_else(|| EmulationError::InternalError {
                    description: "empty call stack".into(),
                })?;
            Ok(frame.locals().get(usize::from(*idx))?.clone())
        }
        PointerTarget::Argument(idx) => {
            let frame = thread
                .get_frame_at(ptr.frame_depth)
                .or_else(|| thread.current_frame())
                .ok_or_else(|| EmulationError::InternalError {
                    description: "empty call stack".into(),
                })?;
            Ok(frame.arguments().get(usize::from(*idx))?.clone())
        }
        PointerTarget::ArrayElement { array, index } => {
            Ok(thread.heap().get_array_element(*array, *index)?.clone())
        }
        PointerTarget::ObjectField { object, field } => {
            Ok(thread.heap().get_field(*object, *field)?.clone())
        }
        PointerTarget::StaticField(field) => {
            Ok(address_space.get_static(*field)?.unwrap_or_else(|| {
                trace!(
                    "Static field {:?} not initialized, defaulting to Null",
                    field
                );
                EmValue::Null
            }))
        }
    }
}

/// Handles `initobj` instruction — initializes value type at address to default.
///
/// Writes a default-initialized value type to the address on the stack.
/// Supports managed pointers to locals, arguments, array elements, and object fields.
///
/// For TypeSpec tokens representing generic type parameters (like `!!0` in a generic
/// method), this function attempts to determine the appropriate default value based
/// on the type signature. Reference types default to null, while value types get
/// an empty `ValueType` placeholder.
///
/// # Arguments
///
/// * `thread` - The emulation thread for stack and memory access
/// * `context` - Optional emulation context for resolving TypeSpec signatures
/// * `type_token` - Token of the value type to initialize
///
/// # Errors
///
/// Returns an error if:
/// - Stack underflow occurs
/// - Null reference is passed
/// - Address is not a valid managed pointer
pub fn handle_initobj(
    thread: &mut EmulationThread,
    context: Option<&EmulationContext>,
    type_token: Token,
) -> Result<()> {
    let addr = thread.pop()?;

    match addr {
        EmValue::ManagedPtr(ptr) => {
            let default_value = get_initobj_default_value(context, type_token);

            match &ptr.target {
                PointerTarget::Local(idx) => {
                    thread
                        .resolve_frame_mut(ptr.frame_depth)
                        .ok_or_else(|| EmulationError::InternalError {
                            description: "empty call stack".into(),
                        })?
                        .locals_mut()
                        .set(usize::from(*idx), default_value)?;
                }
                PointerTarget::Argument(idx) => {
                    thread
                        .resolve_frame_mut(ptr.frame_depth)
                        .ok_or_else(|| EmulationError::InternalError {
                            description: "empty call stack".into(),
                        })?
                        .arguments_mut()
                        .set(usize::from(*idx), default_value)?;
                }
                PointerTarget::ArrayElement { array, index } => {
                    thread
                        .heap_mut()
                        .set_array_element(*array, *index, default_value)?;
                }
                PointerTarget::ObjectField { object, field } => {
                    thread
                        .heap_mut()
                        .set_field(*object, *field, default_value)?;
                }
                PointerTarget::StaticField(_) => {}
            }
        }
        EmValue::UnmanagedPtr(_) => {}
        EmValue::Null => {
            return Err(EmulationError::NullReference.into());
        }
        _ => {
            return Err(EmulationError::TypeMismatch {
                operation: "initobj",
                expected: "managed pointer",
                found: addr.cil_flavor().as_str(),
            }
            .into());
        }
    }

    Ok(())
}

/// Gets the appropriate default value for an `initobj` instruction based on the type.
///
/// For TypeSpec tokens (table 0x1B), this resolves the signature to determine
/// if the type is a reference type (defaults to null) or a value type (defaults
/// to a `ValueType` with empty fields).
///
/// Generic type parameters (`!!0`, `!0`) are treated as reference types since
/// without knowing the actual instantiation, we can't determine the correct
/// default. This is safe because reference type default (null) will work for
/// most deobfuscation scenarios where the actual value gets assigned later.
///
/// # Arguments
///
/// * `context` — Optional emulation context for resolving TypeSpec signatures.
///   When `None`, all types default to `ValueType` with empty fields.
/// * `type_token` — Token of the type to get the default value for.
///
/// # Returns
///
/// The default-initialized `EmValue` for the type: `Null` for reference types,
/// zero-initialized primitives for value types, or `ValueType { fields: [] }`
/// for unresolvable value types.
pub fn get_initobj_default_value(context: Option<&EmulationContext>, type_token: Token) -> EmValue {
    if type_token.is_table(TableId::TypeSpec) {
        if let Some(ctx) = context {
            if let Some(typespec_sig) = ctx.get_typespec_signature(type_token) {
                return match &typespec_sig.base {
                    TypeSignature::Boolean => EmValue::Bool(false),
                    TypeSignature::Char => EmValue::Char('\0'),
                    TypeSignature::I1
                    | TypeSignature::U1
                    | TypeSignature::I2
                    | TypeSignature::U2
                    | TypeSignature::I4
                    | TypeSignature::U4 => EmValue::I32(0),
                    TypeSignature::I8 | TypeSignature::U8 => EmValue::I64(0),
                    TypeSignature::R4 => EmValue::F32(0.0),
                    TypeSignature::R8 => EmValue::F64(0.0),
                    TypeSignature::I | TypeSignature::U => EmValue::NativeInt(0),

                    TypeSignature::Ptr(_) => EmValue::UnmanagedPtr(0),

                    TypeSignature::GenericParamType(_)
                    | TypeSignature::GenericParamMethod(_)
                    | TypeSignature::String
                    | TypeSignature::Object
                    | TypeSignature::Class(_)
                    | TypeSignature::SzArray(_)
                    | TypeSignature::Array(_)
                    | TypeSignature::ByRef(_) => EmValue::Null,

                    TypeSignature::GenericInst(base_type, _) => {
                        if matches!(base_type.as_ref(), TypeSignature::ValueType(_)) {
                            EmValue::ValueType {
                                type_token,
                                fields: Vec::new(),
                            }
                        } else {
                            EmValue::Null
                        }
                    }

                    _ => EmValue::ValueType {
                        type_token,
                        fields: Vec::new(),
                    },
                };
            }
        }
    }

    EmValue::ValueType {
        type_token,
        fields: Vec::new(),
    }
}

/// Handles `cpobj` instruction — copies a value type from source to destination.
///
/// Reads a value type from the source address and writes it to the destination
/// address. Both addresses must be managed pointers pointing to value types.
///
/// # Arguments
///
/// * `address_space` - The shared address space for static field access
/// * `thread` - The emulation thread for stack and memory access
/// * `context` - Optional emulation context for type verification
/// * `type_token` - Token of the value type being copied
///
/// # Errors
///
/// Returns an error if:
/// - Stack underflow occurs
/// - Either address is null
/// - Source value is not a value type
/// - Destination is not a valid managed pointer
pub fn handle_cpobj(
    address_space: &AddressSpace,
    thread: &mut EmulationThread,
    context: Option<&EmulationContext>,
    type_token: Token,
) -> Result<()> {
    let src_addr = thread.pop()?;
    let dest_addr = thread.pop()?;

    // Read value from source
    let value = match src_addr {
        EmValue::ManagedPtr(ptr) => match &ptr.target {
            PointerTarget::Local(idx) => thread
                .get_frame_at(ptr.frame_depth)
                .or_else(|| thread.current_frame())
                .ok_or_else(|| EmulationError::InternalError {
                    description: "empty call stack".into(),
                })?
                .locals()
                .get(usize::from(*idx))?
                .clone(),
            PointerTarget::Argument(idx) => thread
                .get_frame_at(ptr.frame_depth)
                .or_else(|| thread.current_frame())
                .ok_or_else(|| EmulationError::InternalError {
                    description: "empty call stack".into(),
                })?
                .arguments()
                .get(usize::from(*idx))?
                .clone(),
            PointerTarget::ArrayElement { array, index } => {
                thread.heap().get_array_element(*array, *index)?.clone()
            }
            PointerTarget::ObjectField { object, field } => {
                thread.heap().get_field(*object, *field)?.clone()
            }
            PointerTarget::StaticField(field) => {
                address_space.get_static(*field)?.unwrap_or_else(|| {
                    trace!(
                        "Static field {:?} not initialized, defaulting to Null",
                        field
                    );
                    EmValue::Null
                })
            }
        },
        EmValue::Null => {
            return Err(EmulationError::NullReference.into());
        }
        other => other,
    };

    // Verify value type
    let _ = (context, type_token);
    let value_flavor = value.cil_flavor();
    let is_value_type = value_flavor.is_value_type();
    if !is_value_type {
        return Err(EmulationError::TypeMismatch {
            operation: "cpobj",
            expected: "value type",
            found: format!("{value_flavor:?}").leak(),
        }
        .into());
    }

    // Write value to destination
    match dest_addr {
        EmValue::ManagedPtr(ptr) => match &ptr.target {
            PointerTarget::Local(idx) => {
                thread
                    .resolve_frame_mut(ptr.frame_depth)
                    .ok_or_else(|| EmulationError::InternalError {
                        description: "empty call stack".into(),
                    })?
                    .locals_mut()
                    .set(usize::from(*idx), value)?;
            }
            PointerTarget::Argument(idx) => {
                thread
                    .resolve_frame_mut(ptr.frame_depth)
                    .ok_or_else(|| EmulationError::InternalError {
                        description: "empty call stack".into(),
                    })?
                    .arguments_mut()
                    .set(usize::from(*idx), value)?;
            }
            PointerTarget::ArrayElement { array, index } => {
                thread.heap_mut().set_array_element(*array, *index, value)?;
            }
            PointerTarget::ObjectField { object, field } => {
                thread.heap_mut().set_field(*object, *field, value)?;
            }
            PointerTarget::StaticField(_) => {}
        },
        EmValue::Null => {
            return Err(EmulationError::NullReference.into());
        }
        _ => {
            return Err(EmulationError::TypeMismatch {
                operation: "cpobj",
                expected: "managed pointer",
                found: dest_addr.cil_flavor().as_str(),
            }
            .into());
        }
    }

    Ok(())
}

/// Handles `cpblk` instruction — copies a block of memory.
///
/// Copies `size` bytes from the source address to the destination address.
/// Operates on unmanaged memory through the address space.
///
/// Stack: ..., dest, src, size -> ...
///
/// # Arguments
///
/// * `thread` - The emulation thread for address space access
/// * `dest` - Destination pointer value
/// * `src` - Source pointer value
/// * `size` - Number of bytes to copy
///
/// # Errors
///
/// Returns an error if pointer extraction, size extraction, or memory copy fails.
pub fn handle_cpblk(
    thread: &mut EmulationThread,
    dest: &EmValue,
    src: &EmValue,
    size: &EmValue,
) -> Result<()> {
    let dest_addr = dest.as_pointer_address()?;
    let src_addr = src.as_pointer_address()?;
    let size_bytes = size.as_size()?;
    thread
        .address_space()
        .copy_block(dest_addr, src_addr, size_bytes)
}

/// Handles `initblk` instruction — initializes a block of memory.
///
/// Sets `size` bytes at the target address to the specified byte value.
/// Operates on unmanaged memory through the address space.
///
/// Stack: ..., addr, value, size -> ...
///
/// # Arguments
///
/// * `thread` - The emulation thread for address space access
/// * `addr` - Target pointer value
/// * `value` - Byte value to fill with (only low 8 bits used)
/// * `size` - Number of bytes to initialize
///
/// # Errors
///
/// Returns an error if pointer extraction, value type, size extraction, or memory init fails.
#[allow(clippy::cast_sign_loss)]
pub fn handle_initblk(
    thread: &mut EmulationThread,
    addr: &EmValue,
    value: &EmValue,
    size: &EmValue,
) -> Result<()> {
    let address = addr.as_pointer_address()?;

    #[allow(clippy::match_same_arms)]
    let byte_value = match *value {
        EmValue::I32(n) => (n & 0xFF) as u8,
        EmValue::I64(n) => (n & 0xFF) as u8,
        EmValue::NativeInt(n) => (n & 0xFF) as u8,
        EmValue::NativeUInt(n) => (n & 0xFF) as u8,
        _ => {
            return Err(EmulationError::TypeMismatch {
                operation: "initblk",
                expected: "integer value",
                found: value.type_name(),
            }
            .into());
        }
    };

    let size_bytes = size.as_size()?;
    thread
        .address_space()
        .init_block(address, byte_value, size_bytes)
}
