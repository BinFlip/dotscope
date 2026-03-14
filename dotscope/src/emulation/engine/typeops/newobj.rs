//! Object construction and delegate detection for CIL emulation.
//!
//! Handles `newobj` instruction resolution: allocating objects, checking constructor
//! hooks, detecting delegate constructors, and returning resolution outcomes.

use log::debug;

use crate::{
    emulation::{
        engine::{context::EmulationContext, resolution::NewObjResolution, EmulationError},
        memory::{DelegateEntry, HeapObject},
        runtime::{HookContext, HookManager, HookOutcome},
        thread::EmulationThread,
        EmValue,
    },
    metadata::{
        tables::{MemberRefSignature, TableId},
        token::Token,
        typesystem::{CilFlavor, CilType, PointerSize},
    },
    Result,
};

/// Resolves a `newobj` instruction — allocates an object and dispatches its constructor.
///
/// Handles MethodDef, MemberRef, and MethodSpec constructor tokens. Allocates the
/// object on the managed heap, tries constructor hooks, detects delegate constructors,
/// and determines whether to enter the constructor body or bypass it.
///
/// # Arguments
///
/// * `hooks` - The hook manager for constructor interception
/// * `context` - The emulation context for method/type metadata
/// * `constructor_token` - Token of the constructor method
/// * `thread` - The emulation thread for heap/stack access
/// * `pointer_size` - Target platform pointer size
///
/// # Returns
///
/// A [`NewObjResolution`] indicating how the caller should proceed (enter constructor,
/// bypass via hook, redirect to underlying token, etc.).
///
/// # Errors
///
/// Returns an error if method lookup, argument popping, or heap allocation fails.
pub fn resolve_newobj(
    hooks: &HookManager,
    context: &EmulationContext,
    constructor_token: Token,
    thread: &mut EmulationThread,
    pointer_size: PointerSize,
) -> Result<NewObjResolution> {
    // Handle MethodSpec tokens (generic constructor instantiations)
    if constructor_token.is_table(TableId::MethodSpec) {
        if let Some(method_spec) = context.get_method_spec(constructor_token) {
            if let Some(underlying_token) =
                EmulationContext::resolve_method_spec_to_token(&method_spec)
            {
                return Ok(NewObjResolution::Redirect { underlying_token });
            }
        }

        return Err(EmulationError::MethodNotFound {
            token: constructor_token,
        }
        .into());
    }

    // Handle MemberRef tokens (external constructors)
    if constructor_token.is_table(TableId::MemberRef) {
        return resolve_newobj_memberref(hooks, context, constructor_token, thread, pointer_size);
    }

    // Get constructor info for MethodDef tokens
    let method = context.get_method(constructor_token)?;
    let param_count = method.signature.params.len();

    let arg_values = thread.pop_args(param_count)?;

    let declaring_type = context
        .assembly()
        .resolver()
        .declaring_type(constructor_token);
    let type_token = declaring_type.as_ref().map_or_else(
        || Token::new(constructor_token.value() & 0x00FF_FFFF),
        |t| t.token,
    );

    let field_types: Vec<(Token, CilFlavor)> = declaring_type
        .as_ref()
        .map(|t| {
            t.fields
                .iter()
                .filter(|(_, f)| !f.flags.is_static())
                .map(|(_, f)| (f.token, CilFlavor::from(&f.signature.base)))
                .collect()
        })
        .unwrap_or_default();

    let obj_ref = thread
        .heap_mut()
        .alloc_object_with_fields(type_token, &field_types)?;

    // Try to find a constructor hook
    let mut hook_handled = false;
    if let Some(ref decl_type) = declaring_type {
        let this_value = EmValue::ObjectRef(obj_ref);
        let hook_context = HookContext::new(
            constructor_token,
            &decl_type.namespace,
            &decl_type.name,
            ".ctor",
            pointer_size,
        )
        .with_this(Some(&this_value))
        .with_args(&arg_values)
        .with_internal(constructor_token.is_table(TableId::MethodDef));

        match hooks.execute(&hook_context, thread, |_| None)? {
            HookOutcome::NoMatch => {}
            HookOutcome::Handled(_) | HookOutcome::ReflectionInvoke { .. } => {
                hook_handled = true;
            }
            HookOutcome::ThrewException {
                exception_type,
                message,
            } => {
                return Ok(NewObjResolution::ThrowException {
                    exception_type,
                    message,
                });
            }
        }
    }

    // Check that the method has a body AND has decoded instructions
    let has_instructions = method.instructions().next().is_some();
    if !hook_handled && method.has_body() && has_instructions {
        let mut full_args = vec![EmValue::ObjectRef(obj_ref)];
        full_args.extend(arg_values);

        return Ok(NewObjResolution::EnterConstructor {
            constructor_token,
            obj_ref,
            arguments: full_args,
        });
    }

    // Delegate constructor detection
    if !hook_handled && method.is_code_runtime() && arg_values.len() == 2 {
        if let Some(ref decl_type) = declaring_type {
            if is_delegate_type(decl_type) {
                let target = match &arg_values[0] {
                    EmValue::ObjectRef(href) => Some(*href),
                    EmValue::Null => None,
                    _ => None,
                };

                let method_token_value = match &arg_values[1] {
                    EmValue::UnmanagedPtr(ptr) => Some(Token::new(*ptr as u32)),
                    EmValue::I32(v) => Some(Token::new(*v as u32)),
                    EmValue::I64(v) => Some(Token::new(*v as u32)),
                    EmValue::NativeInt(v) => Some(Token::new(*v as u32)),
                    _ => None,
                };

                if let Some(delegate_method) = method_token_value {
                    debug!(
                        "Delegate .ctor: upgrading 0x{:08X} to HeapObject::Delegate \
                         (type=0x{:08X}, target={:?}, method=0x{:08X})",
                        obj_ref.id(),
                        type_token.value(),
                        target,
                        delegate_method.value(),
                    );

                    thread.heap().replace_object(
                        obj_ref,
                        HeapObject::Delegate {
                            type_token,
                            invocation_list: vec![DelegateEntry {
                                target,
                                method_token: delegate_method,
                            }],
                        },
                    )?;
                }
            }
        }
    }

    if hook_handled {
        Ok(NewObjResolution::HookedBypass { obj_ref })
    } else {
        Ok(NewObjResolution::DefaultObject { obj_ref })
    }
}

/// Resolves a `newobj` instruction for MemberRef tokens (external constructors).
///
/// Handles constructor calls through MemberRef tokens, which reference constructors
/// in external assemblies. Allocates the object, checks for constructor hooks, and
/// detects delegate constructor patterns.
fn resolve_newobj_memberref(
    hooks: &HookManager,
    context: &EmulationContext,
    constructor_token: Token,
    thread: &mut EmulationThread,
    pointer_size: PointerSize,
) -> Result<NewObjResolution> {
    let member_ref =
        context
            .get_member_ref(constructor_token)
            .ok_or(EmulationError::MethodNotFound {
                token: constructor_token,
            })?;

    let param_count = if let MemberRefSignature::Method(method_sig) = &member_ref.signature {
        method_sig.param_count as usize
    } else {
        return Err(EmulationError::InvalidOperand {
            instruction: "newobj",
            expected: "method signature in MemberRef",
        }
        .into());
    };

    let args = thread.pop_args(param_count)?;

    let (namespace, type_name_only) = EmulationContext::get_member_ref_type_info(&member_ref)
        .unwrap_or_else(|| (String::new(), String::from("Unknown")));

    let type_token = EmulationContext::get_member_ref_type_token(&member_ref)
        .unwrap_or_else(|| Token::new(constructor_token.value() & 0x00FF_FFFF));

    let field_types: Vec<(Token, CilFlavor)> = context
        .get_type(type_token)
        .map(|t| {
            t.fields
                .iter()
                .filter(|(_, f)| !f.flags.is_static())
                .map(|(_, f)| (f.token, CilFlavor::from(&f.signature.base)))
                .collect()
        })
        .unwrap_or_default();

    let obj_ref = if type_name_only == "DynamicMethod" && namespace == "System.Reflection.Emit" {
        thread.heap_mut().alloc_dynamic_method()?
    } else {
        thread
            .heap_mut()
            .alloc_object_with_fields(type_token, &field_types)?
    };

    let this_value = EmValue::ObjectRef(obj_ref);
    let hook_context = HookContext::new(
        constructor_token,
        &namespace,
        &type_name_only,
        ".ctor",
        pointer_size,
    )
    .with_this(Some(&this_value))
    .with_args(&args)
    .with_internal(false);

    match hooks.execute(&hook_context, thread, |_| None)? {
        HookOutcome::NoMatch => {}
        HookOutcome::Handled(_) | HookOutcome::ReflectionInvoke { .. } => {
            return Ok(NewObjResolution::HookedBypass { obj_ref });
        }
        HookOutcome::ThrewException {
            exception_type,
            message,
        } => {
            return Ok(NewObjResolution::ThrowException {
                exception_type,
                message,
            });
        }
    }

    // Delegate constructor detection for MemberRef path
    if args.len() == 2 {
        if let Some(cil_type) = context.get_type(type_token) {
            if is_delegate_type(&cil_type) {
                let target = match &args[0] {
                    EmValue::ObjectRef(href) => Some(*href),
                    EmValue::Null => None,
                    _ => None,
                };

                let method_token_value = match &args[1] {
                    EmValue::UnmanagedPtr(ptr) => Some(Token::new(*ptr as u32)),
                    EmValue::I32(v) => Some(Token::new(*v as u32)),
                    EmValue::I64(v) => Some(Token::new(*v as u32)),
                    EmValue::NativeInt(v) => Some(Token::new(*v as u32)),
                    _ => None,
                };

                if let Some(delegate_method) = method_token_value {
                    debug!(
                        "Delegate .ctor (MemberRef): upgrading 0x{:08X} to HeapObject::Delegate \
                         (type=0x{:08X}, target={:?}, method=0x{:08X})",
                        obj_ref.id(),
                        type_token.value(),
                        target,
                        delegate_method.value(),
                    );

                    thread.heap().replace_object(
                        obj_ref,
                        HeapObject::Delegate {
                            type_token,
                            invocation_list: vec![DelegateEntry {
                                target,
                                method_token: delegate_method,
                            }],
                        },
                    )?;
                }
            }
        }
    }

    Ok(NewObjResolution::DefaultObject { obj_ref })
}

/// Checks whether a type is a delegate type.
///
/// Walks the base type chain up to 3 levels looking for either `MulticastDelegate` or
/// `Delegate` in the `System` namespace. This detects both standard delegates and
/// custom delegate types generated by obfuscators.
///
/// # Arguments
///
/// * `cil_type` — The type to check.
///
/// # Returns
///
/// `true` if the type (or any of its bases within 3 levels) is `System.Delegate`
/// or `System.MulticastDelegate`.
pub fn is_delegate_type(cil_type: &CilType) -> bool {
    let mut current = cil_type.base();
    for _ in 0..3 {
        match current {
            Some(base) => {
                if base.namespace == "System"
                    && (base.name == "MulticastDelegate" || base.name == "Delegate")
                {
                    return true;
                }
                current = base.base();
            }
            None => break,
        }
    }
    false
}
