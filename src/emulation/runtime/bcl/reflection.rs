//! `System.Reflection` method hooks.
//!
//! This module provides hook implementations for reflection methods commonly used in
//! obfuscated assemblies for runtime type inspection, member lookup, and dynamic
//! method invocation.
//!
//! # Overview
//!
//! Reflection is a powerful .NET feature that allows code to inspect and invoke types
//! at runtime. Obfuscators use reflection to:
//! - Resolve method tokens dynamically
//! - Invoke decryption routines through reflection
//! - Access private/internal members
//!
//! # Emulated .NET Methods
//!
//! ## Type Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Type.GetTypeFromHandle(RuntimeTypeHandle)` | Get `Type` from handle |
//! | `Type.GetMethod(string)` | Lookup method by name |
//! | `Type.GetField(string)` | Lookup field by name |
//! | `Type.GetProperty(string)` | Lookup property by name |
//! | `Type.GetConstructor(Type[])` | Lookup constructor |
//! | `Type.Module` | Get containing module |
//!
//! ## Module Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Module.Assembly` | Get containing assembly |
//! | `Module.ResolveMethod(int)` | Resolve method by token |
//! | `Module.ResolveType(int)` | Resolve type by token |
//! | `Module.FullyQualifiedName` | Get module path |
//!
//! ## Assembly Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Assembly.GlobalAssemblyCache` | Check if in GAC (returns false) |
//!
//! ## Member Invocation
//!
//! | Method | Description |
//! |--------|-------------|
//! | `MethodBase.Invoke(object, object[])` | Invoke method dynamically |
//! | `MethodInfo.Invoke(object, object[])` | Invoke method dynamically |
//! | `ConstructorInfo.Invoke(object[])` | Create instance |
//! | `FieldInfo.GetValue(object)` | Read field value |
//! | `FieldInfo.SetValue(object, object)` | Write field value |
//!
//! # Deobfuscation Use Cases
//!
//! ## Dynamic Method Resolution
//!
//! ```csharp
//! // Common obfuscation pattern
//! Module mod = typeof(Program).Module;
//! MethodBase method = mod.ResolveMethod(encryptedToken ^ key);
//! method.Invoke(null, new object[] { args });
//! ```
//!
//! ## Type-Based Dispatch
//!
//! ```csharp
//! Type t = Type.GetTypeFromHandle(handle);
//! MethodInfo decrypt = t.GetMethod("Decrypt");
//! string result = (string)decrypt.Invoke(null, new object[] { data });
//! ```
//!
//! # Limitations
//!
//! - All returned reflection objects are **symbolic** (fake tokens)
//! - `Invoke` returns `null` or generic objects (no actual execution)
//! - Field values are unknown (`GetValue` returns `null`)
//! - Method resolution does not validate tokens

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::{EmulationThread, ReflectionInvokeRequest},
        EmValue, HeapObject,
    },
    metadata::token::Token,
};

/// Registers all reflection method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - **Type**: `GetTypeFromHandle`, `GetMethod`, `GetField`, `GetProperty`, `GetConstructor`, `Module`
/// - **Module**: `Assembly`, `ResolveMethod`, `ResolveType`, `FullyQualifiedName`
/// - **Assembly**: `GlobalAssemblyCache`
/// - **Invocation**: `MethodBase.Invoke`, `MethodInfo.Invoke`, `ConstructorInfo.Invoke`
/// - **Fields**: `FieldInfo.GetValue`, `FieldInfo.SetValue`
pub fn register(manager: &mut HookManager) {
    // Type methods
    manager.register(
        Hook::new("System.Type.get_Module")
            .match_name("System", "Type", "get_Module")
            .pre(type_get_module_pre),
    );

    manager.register(
        Hook::new("System.Type.GetTypeFromHandle")
            .match_name("System", "Type", "GetTypeFromHandle")
            .pre(type_get_type_from_handle_pre),
    );

    manager.register(
        Hook::new("System.Type.GetMethod")
            .match_name("System", "Type", "GetMethod")
            .pre(type_get_method_pre),
    );

    manager.register(
        Hook::new("System.Type.GetField")
            .match_name("System", "Type", "GetField")
            .pre(type_get_field_pre),
    );

    manager.register(
        Hook::new("System.Type.GetProperty")
            .match_name("System", "Type", "GetProperty")
            .pre(type_get_property_pre),
    );

    manager.register(
        Hook::new("System.Type.GetConstructor")
            .match_name("System", "Type", "GetConstructor")
            .pre(type_get_constructor_pre),
    );

    // MethodBase methods
    manager.register(
        Hook::new("System.Reflection.MethodBase.Invoke")
            .match_name("System.Reflection", "MethodBase", "Invoke")
            .pre(method_invoke_pre),
    );

    manager.register(
        Hook::new("System.Reflection.MethodInfo.Invoke")
            .match_name("System.Reflection", "MethodInfo", "Invoke")
            .pre(method_invoke_pre),
    );

    manager.register(
        Hook::new("System.Reflection.ConstructorInfo.Invoke")
            .match_name("System.Reflection", "ConstructorInfo", "Invoke")
            .pre(constructor_invoke_pre),
    );

    // Module methods
    manager.register(
        Hook::new("System.Reflection.Module.get_FullyQualifiedName")
            .match_name("System.Reflection", "Module", "get_FullyQualifiedName")
            .pre(module_get_fully_qualified_name_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Module.get_Assembly")
            .match_name("System.Reflection", "Module", "get_Assembly")
            .pre(module_get_assembly_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Module.ResolveMethod")
            .match_name("System.Reflection", "Module", "ResolveMethod")
            .pre(module_resolve_method_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Module.ResolveType")
            .match_name("System.Reflection", "Module", "ResolveType")
            .pre(module_resolve_type_pre),
    );

    // Assembly properties - used in anti-tamper initialization checks
    manager.register(
        Hook::new("System.Reflection.Assembly.get_GlobalAssemblyCache")
            .match_name("System.Reflection", "Assembly", "get_GlobalAssemblyCache")
            .pre(|_ctx, _thread| {
                // Local assemblies are not in the GAC, return false (0)
                PreHookResult::Bypass(Some(EmValue::I32(0)))
            }),
    );

    // FieldInfo methods
    manager.register(
        Hook::new("System.Reflection.FieldInfo.GetValue")
            .match_name("System.Reflection", "FieldInfo", "GetValue")
            .pre(field_get_value_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.SetValue")
            .match_name("System.Reflection", "FieldInfo", "SetValue")
            .pre(field_set_value_pre),
    );
}

/// Hook for `System.Type.get_Module` property.
///
/// Gets the module (the DLL) in which the current Type is defined.
///
/// # Handled Overloads
///
/// - `Type.Module { get; } -> Module`
///
/// # Parameters
///
/// - `this`: The Type instance
fn type_get_module_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0003)) {
        Ok(module_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(module_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetTypeFromHandle` method.
///
/// Gets the type referenced by the specified type handle.
///
/// # Handled Overloads
///
/// - `Type.GetTypeFromHandle(RuntimeTypeHandle) -> Type`
///
/// # Parameters
///
/// - `handle`: The object that refers to the type
fn type_get_type_from_handle_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0001)) {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetMethod` method.
///
/// Searches for the specified method, using the specified binding constraints.
///
/// # Handled Overloads
///
/// - `Type.GetMethod(String) -> MethodInfo`
/// - `Type.GetMethod(String, BindingFlags) -> MethodInfo`
/// - `Type.GetMethod(String, Type[]) -> MethodInfo`
/// - `Type.GetMethod(String, BindingFlags, Binder, Type[], ParameterModifier[]) -> MethodInfo`
/// - `Type.GetMethod(String, BindingFlags, Type[]) -> MethodInfo`
/// - `Type.GetMethod(String, Int32, Type[]) -> MethodInfo`
/// - `Type.GetMethod(String, Int32, BindingFlags, Binder, Type[], ParameterModifier[]) -> MethodInfo`
///
/// # Parameters
///
/// - `name`: The string containing the name of the method to get
/// - `bindingAttr`: Binding flags that control the search (optional)
/// - `types`: An array of Type objects representing the parameter types (optional)
fn type_get_method_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0002)) {
        Ok(method_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(method_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetField` method.
///
/// Searches for the specified field, using the specified binding constraints.
///
/// # Handled Overloads
///
/// - `Type.GetField(String) -> FieldInfo`
/// - `Type.GetField(String, BindingFlags) -> FieldInfo`
///
/// # Parameters
///
/// - `name`: The string containing the name of the field to get
/// - `bindingAttr`: Binding flags that control the search (optional)
fn type_get_field_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0004)) {
        Ok(field_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(field_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetProperty` method.
///
/// Searches for the specified property, using the specified binding constraints.
///
/// # Handled Overloads
///
/// - `Type.GetProperty(String) -> PropertyInfo`
/// - `Type.GetProperty(String, BindingFlags) -> PropertyInfo`
/// - `Type.GetProperty(String, Type) -> PropertyInfo`
/// - `Type.GetProperty(String, Type[]) -> PropertyInfo`
/// - `Type.GetProperty(String, Type, Type[]) -> PropertyInfo`
/// - `Type.GetProperty(String, BindingFlags, Binder, Type, Type[], ParameterModifier[]) -> PropertyInfo`
///
/// # Parameters
///
/// - `name`: The string containing the name of the property to get
/// - `bindingAttr`: Binding flags that control the search (optional)
/// - `returnType`: The return type of the property (optional)
/// - `types`: An array of Type objects representing the indexer parameter types (optional)
fn type_get_property_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0005)) {
        Ok(prop_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(prop_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetConstructor` method.
///
/// Searches for a constructor whose parameters match the specified argument types.
///
/// # Handled Overloads
///
/// - `Type.GetConstructor(Type[]) -> ConstructorInfo`
/// - `Type.GetConstructor(BindingFlags, Binder, Type[], ParameterModifier[]) -> ConstructorInfo`
/// - `Type.GetConstructor(BindingFlags, Type[]) -> ConstructorInfo`
/// - `Type.GetConstructor(BindingFlags, Binder, CallingConventions, Type[], ParameterModifier[]) -> ConstructorInfo`
///
/// # Parameters
///
/// - `types`: An array of Type objects representing the parameter types
/// - `bindingAttr`: Binding flags that control the search (optional)
fn type_get_constructor_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0006)) {
        Ok(ctor_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(ctor_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.MethodBase.Invoke` and `System.Reflection.MethodInfo.Invoke` methods.
///
/// Invokes the method or constructor represented by the current instance.
///
/// # Handled Overloads
///
/// - `MethodBase.Invoke(Object, Object[]) -> Object`
/// - `MethodBase.Invoke(Object, BindingFlags, Binder, Object[], CultureInfo) -> Object`
/// - `MethodInfo.Invoke(Object, Object[]) -> Object`
/// - `MethodInfo.Invoke(Object, BindingFlags, Binder, Object[], CultureInfo) -> Object`
///
/// # Parameters
///
/// - `obj`: The object on which to invoke the method (null for static methods)
/// - `parameters`: An argument list for the invoked method
/// - `invokeAttr`: Invocation flags (optional)
/// - `binder`: An object that enables binding (optional)
/// - `culture`: Culture information (optional)
fn method_invoke_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to get the method token from the 'this' parameter (the MethodBase object)
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            // Extract the target object (first argument to Invoke)
            let this_ref = ctx.args.first().cloned();

            // Extract the method arguments from the object[] array (second argument)
            let method_args = if let Some(EmValue::ObjectRef(arr_ref)) = ctx.args.get(1) {
                if let Ok(HeapObject::Array { elements, .. }) = thread.heap().get(*arr_ref) {
                    elements
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            // Set up the pending reflection invoke request
            thread.set_pending_reflection_invoke(ReflectionInvokeRequest {
                method_token,
                this_ref,
                args: method_args,
            });

            // Return null for now - the controller will replace this with the actual
            // return value after invoking the method
            return PreHookResult::Bypass(Some(EmValue::Null));
        }
    }

    // Fallback: no valid method token found
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Reflection.ConstructorInfo.Invoke` method.
///
/// Invokes the constructor represented by the current instance.
///
/// # Handled Overloads
///
/// - `ConstructorInfo.Invoke(Object[]) -> Object`
/// - `ConstructorInfo.Invoke(BindingFlags, Binder, Object[], CultureInfo) -> Object`
/// - `ConstructorInfo.Invoke(Object, Object[]) -> void`
/// - `ConstructorInfo.Invoke(Object, BindingFlags, Binder, Object[], CultureInfo) -> void`
///
/// # Parameters
///
/// - `parameters`: An argument list for the invoked constructor
/// - `invokeAttr`: Invocation flags (optional)
/// - `binder`: An object that enables binding (optional)
/// - `culture`: Culture information (optional)
/// - `obj`: The object to invoke the constructor on (for reinitialization, optional)
fn constructor_invoke_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Return a generic object instance
    match thread.heap_mut().alloc_object(Token::new(0x0100_0007)) {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Module.get_FullyQualifiedName` property.
///
/// Gets a string representing the fully qualified name and path to this module.
///
/// # Handled Overloads
///
/// - `Module.FullyQualifiedName { get; } -> String`
///
/// # Parameters
///
/// - `this`: The Module instance
fn module_get_fully_qualified_name_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread
        .heap_mut()
        .alloc_string("C:\\Program Files\\App\\module.exe")
    {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Module.get_Assembly` property.
///
/// Gets the assembly for this module.
///
/// # Handled Overloads
///
/// - `Module.Assembly { get; } -> Assembly`
///
/// # Parameters
///
/// - `this`: The Module instance
///
/// # Returns
///
/// Returns the pre-allocated fake Assembly object from [`FakeObjects`], ensuring
/// that multiple calls return the same reference. This is critical for anti-tamper
/// checks that compare assembly references.
fn module_get_assembly_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Return the pre-allocated fake assembly from FakeObjects.
    // This ensures Assembly.GetExecutingAssembly() == module.Assembly passes.
    if let Some(asm_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref)));
    }

    // Fallback: allocate a new fake assembly if FakeObjects not initialized
    match thread.heap_mut().alloc_object(Token::new(0x0100_0008)) {
        Ok(asm_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Module.ResolveMethod` method.
///
/// Returns the method identified by the specified metadata token.
///
/// # Handled Overloads
///
/// - `Module.ResolveMethod(Int32) -> MethodBase`
/// - `Module.ResolveMethod(Int32, Type[], Type[]) -> MethodBase`
///
/// # Parameters
///
/// - `metadataToken`: A metadata token that identifies a method in the module
/// - `genericTypeArguments`: An array of Type objects for generic type arguments (optional)
/// - `genericMethodArguments`: An array of Type objects for generic method arguments (optional)
fn module_resolve_method_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the metadata token from the first argument (int32)
    #[allow(clippy::cast_sign_loss)]
    let method_token = if let Some(token_value) = ctx.args.first().and_then(|v| v.as_i32()) {
        // The argument is the raw metadata token value (e.g., 0x06000001 for MethodDef)
        Token::new(token_value as u32)
    } else {
        // Fallback to generic MethodBase type if no token provided
        Token::new(0x0100_0002)
    };

    // Create a ReflectionMethod object that stores the resolved token
    match thread.heap_mut().alloc_reflection_method(method_token) {
        Ok(method_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(method_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Module.ResolveType` method.
///
/// Returns the type identified by the specified metadata token.
///
/// # Handled Overloads
///
/// - `Module.ResolveType(Int32) -> Type`
/// - `Module.ResolveType(Int32, Type[], Type[]) -> Type`
///
/// # Parameters
///
/// - `metadataToken`: A metadata token that identifies a type in the module
/// - `genericTypeArguments`: An array of Type objects for generic type arguments (optional)
/// - `genericMethodArguments`: An array of Type objects for generic method arguments (optional)
fn module_resolve_type_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0001)) {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.FieldInfo.GetValue` method.
///
/// Returns the value of a field supported by a given object.
///
/// # Handled Overloads
///
/// - `FieldInfo.GetValue(Object) -> Object`
///
/// # Parameters
///
/// - `obj`: The object whose field value will be returned (null for static fields)
fn field_get_value_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Reflection.FieldInfo.SetValue` method.
///
/// Sets the value of the field supported by the given object.
///
/// # Handled Overloads
///
/// - `FieldInfo.SetValue(Object, Object) -> void`
/// - `FieldInfo.SetValue(Object, Object, BindingFlags, Binder, CultureInfo) -> void`
///
/// # Parameters
///
/// - `obj`: The object whose field value will be set (null for static fields)
/// - `value`: The value to assign to the field
/// - `invokeAttr`: Invocation flags (optional)
/// - `binder`: An object that enables binding (optional)
/// - `culture`: Culture information (optional)
fn field_set_value_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager, metadata::typesystem::PointerSize,
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 16);
    }

    #[test]
    fn test_get_module_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Type",
            "get_Module",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = type_get_module_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef"),
        }
    }

    #[test]
    fn test_get_type_from_handle_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Type",
            "GetTypeFromHandle",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = type_get_type_from_handle_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef"),
        }
    }

    #[test]
    fn test_method_invoke_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Reflection",
            "MethodBase",
            "Invoke",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = method_invoke_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::Null)) => {}
            _ => panic!("Expected Bypass with Null"),
        }
    }

    #[test]
    fn test_field_get_value_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Reflection",
            "FieldInfo",
            "GetValue",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = field_get_value_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::Null)) => {}
            _ => panic!("Expected Bypass with Null"),
        }
    }
}
