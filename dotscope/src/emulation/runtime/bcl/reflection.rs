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
//! | `Type.Assembly` | Get containing assembly |
//! | `Type.Module` | Get containing module |
//! | `Type.get_IsByRef` | Check if type is by-reference |
//! | `Type.get_IsPointer` | Check if type is an unmanaged pointer |
//!
//! ## Object Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Object.GetType()` | Get runtime type of an object |
//!
//! ## Module Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Module.Assembly` | Get containing assembly |
//! | `Module.ResolveMethod(int)` | Resolve method by token |
//! | `Module.ResolveType(int)` | Resolve type by token |
//! | `Module.ResolveField(int)` | Resolve field by token |
//! | `Module.FullyQualifiedName` | Get module path |
//!
//! ## Assembly Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Assembly.GlobalAssemblyCache` | Check if in GAC (returns false) |
//! | `Assembly.Location` | Get assembly path (returns null in emulation) |
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

use std::sync::Arc;

use log::debug;

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::{EmulationThread, ReflectionInvokeRequest},
        EmValue, HeapObject,
    },
    metadata::{
        method::Method,
        signatures::TypeSignature,
        tables::{FieldAttributes, ModuleRaw, TableId},
        token::Token,
        typesystem::{CilFlavor, CilPrimitiveData, CilType},
    },
    CilObject,
};

/// Registers all reflection method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - **Type**: `GetTypeFromHandle`, `GetMethod`, `GetField`, `GetProperty`, `GetConstructor`, `Module`, `Assembly`
/// - **Module**: `Assembly`, `ResolveMethod`, `ResolveType`, `ResolveField`, `FullyQualifiedName`
/// - **Assembly**: `GlobalAssemblyCache`, `Location`
/// - **Invocation**: `MethodBase.Invoke`, `MethodInfo.Invoke`, `ConstructorInfo.Invoke`
/// - **Fields**: `FieldInfo.GetValue`, `FieldInfo.SetValue`
pub fn register(manager: &HookManager) {
    // Type comparison operators
    manager.register(
        Hook::new("System.Type.op_Equality")
            .match_name("System", "Type", "op_Equality")
            .pre(type_op_equality_pre),
    );

    manager.register(
        Hook::new("System.Type.op_Inequality")
            .match_name("System", "Type", "op_Inequality")
            .pre(type_op_inequality_pre),
    );

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
        Hook::new("System.Type.GetFields")
            .match_name("System", "Type", "GetFields")
            .pre(type_get_fields_pre),
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

    manager.register(
        Hook::new("System.Reflection.Module.ResolveField")
            .match_name("System.Reflection", "Module", "ResolveField")
            .pre(module_resolve_field_pre),
    );

    // Type.get_Assembly — used in anti-tamper checks that do
    // typeof(X).Assembly.Location to verify the assembly file
    manager.register(
        Hook::new("System.Type.get_Assembly")
            .match_name("System", "Type", "get_Assembly")
            .pre(type_get_assembly_pre),
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

    // Debugger.get_IsAttached — returns false so anti-debug checks
    // that throw when a debugger is detected are bypassed
    manager.register(
        Hook::new("System.Diagnostics.Debugger.get_IsAttached")
            .match_name("System.Diagnostics", "Debugger", "get_IsAttached")
            .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(0)))),
    );

    // Assembly.get_Location — returns a plausible path using module name from
    // metadata and configured base path. Used by anti-tamper and licensing checks.
    manager.register(
        Hook::new("System.Reflection.Assembly.get_Location")
            .match_name("System.Reflection", "Assembly", "get_Location")
            .pre(assembly_get_location_pre),
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

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_FieldType")
            .match_name("System.Reflection", "FieldInfo", "get_FieldType")
            .pre(field_get_field_type_pre),
    );

    // MemberInfo.get_MetadataToken — return the real metadata token from Reflection objects
    manager.register(
        Hook::new("System.Reflection.MemberInfo.get_MetadataToken")
            .match_name("System.Reflection", "MemberInfo", "get_MetadataToken")
            .pre(member_get_metadata_token_pre),
    );

    // MethodBase.get_IsStatic — check method flags in assembly metadata
    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsStatic")
            .match_name("System.Reflection", "MethodBase", "get_IsStatic")
            .pre(method_get_is_static_pre),
    );

    // Delegate.CreateDelegate(Type, MethodInfo) — static method to create delegates
    manager.register(
        Hook::new("System.Delegate.CreateDelegate")
            .match_name("System", "Delegate", "CreateDelegate")
            .pre(delegate_create_delegate_pre),
    );

    // Type.GetGenericArguments() — return empty Type[] for non-generic types
    manager.register(
        Hook::new("System.Type.GetGenericArguments")
            .match_name("System", "Type", "GetGenericArguments")
            .pre(
                |_ctx, thread| match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
                    Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                },
            ),
    );

    // Type.get_IsValueType — check if the type is a value type
    manager.register(
        Hook::new("System.Type.get_IsValueType")
            .match_name("System", "Type", "get_IsValueType")
            .pre(type_get_is_value_type_pre),
    );

    // MemberInfo.get_DeclaringType — return the declaring type of a member
    manager.register(
        Hook::new("System.Reflection.MemberInfo.get_DeclaringType")
            .match_name("System.Reflection", "MemberInfo", "get_DeclaringType")
            .pre(member_get_declaring_type_pre),
    );

    // Type.MakeByRefType() — return a Type object representing byref
    manager.register(
        Hook::new("System.Type.MakeByRefType")
            .match_name("System", "Type", "MakeByRefType")
            .pre(|ctx, _thread| {
                // Return the same type object (byref distinction doesn't matter for emulation)
                if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(*type_ref)));
                }
                PreHookResult::Bypass(Some(EmValue::Null))
            }),
    );

    // MethodInfo.get_ReturnType — return the method's return type
    manager.register(
        Hook::new("System.Reflection.MethodInfo.get_ReturnType")
            .match_name("System.Reflection", "MethodInfo", "get_ReturnType")
            .pre(method_get_return_type_pre),
    );

    // MethodBase.GetParameters() — return ParameterInfo array
    manager.register(
        Hook::new("System.Reflection.MethodBase.GetParameters")
            .match_name("System.Reflection", "MethodBase", "GetParameters")
            .pre(method_get_parameters_pre),
    );

    // ParameterInfo.get_ParameterType — return real parameter type from ReflectionParameter
    manager.register(
        Hook::new("System.Reflection.ParameterInfo.get_ParameterType")
            .match_name("System.Reflection", "ParameterInfo", "get_ParameterType")
            .pre(parameter_get_parameter_type_pre),
    );

    // Obfuscators use DynamicMethod to build wrapper delegates at runtime:
    //   1. new DynamicMethod(name, returnType, paramTypes, module, skipVisibility)
    //   2. dm.GetILGenerator() → ILGenerator
    //   3. ilGen.Emit(Ldarg_0/1/2/...) — load arguments
    //   4. ilGen.Emit(Call/Callvirt, targetMethodInfo) — call the real method
    //   5. ilGen.Emit(Ret) — return
    //   6. dm.CreateDelegate(delegateType) → functional delegate
    //
    // We track the target method through ILGenerator.Emit(OpCode, MethodInfo)
    // and use it in CreateDelegate to produce a proper HeapObject::Delegate.

    manager.register(
        Hook::new("System.Reflection.Emit.DynamicMethod.GetILGenerator")
            .match_name("System.Reflection.Emit", "DynamicMethod", "GetILGenerator")
            .pre(dynamic_method_get_il_generator_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.Emit")
            .match_name("System.Reflection.Emit", "ILGenerator", "Emit")
            .pre(il_generator_emit_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.DeclareLocal")
            .match_name("System.Reflection.Emit", "ILGenerator", "DeclareLocal")
            .pre(|_ctx, thread| {
                // Return a stub LocalBuilder object
                match thread.heap_mut().alloc_object(Token::new(0x7F00_000B)) {
                    Ok(lb_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(lb_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }),
    );

    manager.register(
        Hook::new("System.Reflection.Emit.DynamicMethod.CreateDelegate")
            .match_name("System.Reflection.Emit", "DynamicMethod", "CreateDelegate")
            .pre(dynamic_method_create_delegate_pre),
    );

    // ModuleHandle.GetRuntimeTypeHandleFromMetadataToken — converts a metadata
    // token (int32) to a RuntimeTypeHandle by passing the raw token through as
    // a NativeInt, which Type.GetTypeFromHandle extracts correctly.
    manager.register(
        Hook::new("System.ModuleHandle.GetRuntimeTypeHandleFromMetadataToken")
            .match_name(
                "System",
                "ModuleHandle",
                "GetRuntimeTypeHandleFromMetadataToken",
            )
            .pre(module_handle_get_runtime_type_handle_pre),
    );

    manager.register(
        Hook::new("System.Delegate.Invoke")
            .match_name("System", "Delegate", "Invoke")
            .pre(delegate_invoke_pre),
    );

    manager.register(
        Hook::new("System.MulticastDelegate.Invoke")
            .match_name("System", "MulticastDelegate", "Invoke")
            .pre(delegate_invoke_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetValue")
            .match_name("System.Reflection", "PropertyInfo", "GetValue")
            .pre(property_get_value_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.SetValue")
            .match_name("System.Reflection", "PropertyInfo", "SetValue")
            .pre(property_set_value_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_PropertyType")
            .match_name("System.Reflection", "PropertyInfo", "get_PropertyType")
            .pre(property_get_property_type_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_CanRead")
            .match_name("System.Reflection", "PropertyInfo", "get_CanRead")
            .pre(property_get_can_read_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_CanWrite")
            .match_name("System.Reflection", "PropertyInfo", "get_CanWrite")
            .pre(property_get_can_write_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_Name")
            .match_name("System.Reflection", "PropertyInfo", "get_Name")
            .pre(property_get_name_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetGetMethod")
            .match_name("System.Reflection", "PropertyInfo", "GetGetMethod")
            .pre(property_get_get_method_pre),
    );

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetSetMethod")
            .match_name("System.Reflection", "PropertyInfo", "GetSetMethod")
            .pre(property_get_set_method_pre),
    );

    manager.register(
        Hook::new("System.Type.get_FullName")
            .match_name("System", "Type", "get_FullName")
            .pre(type_get_full_name_pre),
    );

    manager.register(
        Hook::new("System.Type.get_Name")
            .match_name("System", "Type", "get_Name")
            .pre(type_get_name_pre),
    );

    manager.register(
        Hook::new("System.Type.get_Namespace")
            .match_name("System", "Type", "get_Namespace")
            .pre(type_get_namespace_pre),
    );

    manager.register(
        Hook::new("System.Type.get_BaseType")
            .match_name("System", "Type", "get_BaseType")
            .pre(type_get_base_type_pre),
    );

    manager.register(
        Hook::new("System.Type.GetElementType")
            .match_name("System", "Type", "GetElementType")
            .pre(|ctx, _thread| {
                // Return the same type for simplicity (arrays return element type)
                if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(*type_ref)));
                }
                PreHookResult::Bypass(Some(EmValue::Null))
            }),
    );

    manager.register(
        Hook::new("System.Type.MakeArrayType")
            .match_name("System", "Type", "MakeArrayType")
            .pre(|ctx, _thread| {
                // Return the same type wrapped as array concept
                if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(*type_ref)));
                }
                PreHookResult::Bypass(Some(EmValue::Null))
            }),
    );

    manager.register(
        Hook::new("System.Type.MakeGenericType")
            .match_name("System", "Type", "MakeGenericType")
            .pre(|ctx, _thread| {
                // Return the same type (sufficient for obfuscator patterns)
                if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(*type_ref)));
                }
                PreHookResult::Bypass(Some(EmValue::Null))
            }),
    );

    manager.register(
        Hook::new("System.Type.get_IsArray")
            .match_name("System", "Type", "get_IsArray")
            .pre(type_get_is_array_pre),
    );

    manager.register(
        Hook::new("System.Type.get_IsEnum")
            .match_name("System", "Type", "get_IsEnum")
            .pre(type_get_is_enum_pre),
    );

    manager.register(
        Hook::new("System.Type.get_IsInterface")
            .match_name("System", "Type", "get_IsInterface")
            .pre(type_get_bool_flag_pre(|cil_type| {
                cil_type.flags.is_interface()
            })),
    );

    manager.register(
        Hook::new("System.Type.get_IsAbstract")
            .match_name("System", "Type", "get_IsAbstract")
            .pre(type_get_bool_flag_pre(|cil_type| {
                cil_type.flags.is_abstract()
            })),
    );

    manager.register(
        Hook::new("System.Type.get_IsSealed")
            .match_name("System", "Type", "get_IsSealed")
            .pre(type_get_bool_flag_pre(|cil_type| {
                cil_type.flags.is_sealed()
            })),
    );

    manager.register(
        Hook::new("System.Type.get_IsPublic")
            .match_name("System", "Type", "get_IsPublic")
            .pre(type_get_bool_flag_pre(|cil_type| {
                cil_type.flags.is_public()
            })),
    );

    manager.register(
        Hook::new("System.Type.get_IsGenericType")
            .match_name("System", "Type", "get_IsGenericType")
            .pre(type_get_bool_flag_pre(|cil_type| {
                !cil_type.generic_params.is_empty()
            })),
    );

    manager.register(
        Hook::new("System.Type.get_IsByRef")
            .match_name("System", "Type", "get_IsByRef")
            .pre(type_get_bool_flag_pre(|cil_type| {
                *cil_type.flavor() == CilFlavor::ByRef
            })),
    );

    manager.register(
        Hook::new("System.Type.get_IsPointer")
            .match_name("System", "Type", "get_IsPointer")
            .pre(type_get_bool_flag_pre(|cil_type| {
                *cil_type.flavor() == CilFlavor::Pointer
            })),
    );

    manager.register(
        Hook::new("System.Type.GetMethods")
            .match_name("System", "Type", "GetMethods")
            .pre(type_get_methods_pre),
    );

    manager.register(
        Hook::new("System.Type.GetProperties")
            .match_name("System", "Type", "GetProperties")
            .pre(type_get_properties_pre),
    );

    manager.register(
        Hook::new("System.Type.GetConstructors")
            .match_name("System", "Type", "GetConstructors")
            .pre(type_get_constructors_pre),
    );

    manager.register(
        Hook::new("System.Type.GetInterfaces")
            .match_name("System", "Type", "GetInterfaces")
            .pre(type_get_interfaces_pre),
    );

    manager.register(
        Hook::new("System.Type.GetNestedTypes")
            .match_name("System", "Type", "GetNestedTypes")
            .pre(type_get_nested_types_pre),
    );

    manager.register(
        Hook::new("System.Type.GetMembers")
            .match_name("System", "Type", "GetMembers")
            .pre(type_get_members_pre),
    );

    // Type.GetCustomAttributes — return empty arrays
    manager.register(
        Hook::new("System.Type.GetCustomAttributes")
            .match_name("System", "Type", "GetCustomAttributes")
            .pre(
                |_ctx, thread| match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
                    Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                },
            ),
    );

    // Type.GetEnumValues / GetEnumNames / GetEnumUnderlyingType
    manager.register(
        Hook::new("System.Type.GetEnumValues")
            .match_name("System", "Type", "GetEnumValues")
            .pre(type_get_enum_values_pre),
    );

    manager.register(
        Hook::new("System.Type.GetEnumNames")
            .match_name("System", "Type", "GetEnumNames")
            .pre(type_get_enum_names_pre),
    );

    manager.register(
        Hook::new("System.Type.GetEnumUnderlyingType")
            .match_name("System", "Type", "GetEnumUnderlyingType")
            .pre(|_ctx, thread| {
                // Return a Type representing Int32 (most common underlying type)
                match thread
                    .heap_mut()
                    .alloc_reflection_type(Token::new(0x7F00_0001))
                {
                    Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }),
    );

    // Type comparison methods
    manager.register(
        Hook::new("System.Type.IsAssignableFrom")
            .match_name("System", "Type", "IsAssignableFrom")
            .pre(type_is_assignable_from_pre),
    );

    manager.register(
        Hook::new("System.Type.IsSubclassOf")
            .match_name("System", "Type", "IsSubclassOf")
            .pre(type_is_subclass_of_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetTypes")
            .match_name("System.Reflection", "Assembly", "GetTypes")
            .pre(assembly_get_types_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetExportedTypes")
            .match_name("System.Reflection", "Assembly", "GetExportedTypes")
            .pre(assembly_get_exported_types_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetType")
            .match_name("System.Reflection", "Assembly", "GetType")
            .pre(assembly_get_type_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.get_FullName")
            .match_name("System.Reflection", "Assembly", "get_FullName")
            .pre(|_ctx, thread| {
                match thread
                    .heap_mut()
                    .alloc_string("EmulatedAssembly, Version=1.0.0.0")
                {
                    Ok(s_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetName")
            .match_name("System.Reflection", "Assembly", "GetName")
            .pre(|_ctx, thread| {
                // Return a stub AssemblyName object
                match thread.heap_mut().alloc_object(Token::new(0x7F00_0014)) {
                    Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }),
    );

    // AssemblyName.get_Name — returns a placeholder assembly name string
    manager.register(
        Hook::new("System.Reflection.AssemblyName.get_Name")
            .match_name("System.Reflection", "AssemblyName", "get_Name")
            .pre(
                |_ctx, thread| match thread.heap_mut().alloc_string("Assembly") {
                    Ok(s_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                },
            ),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetManifestResourceNames")
            .match_name("System.Reflection", "Assembly", "GetManifestResourceNames")
            .pre(
                |_ctx, thread| match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
                    Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                },
            ),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetModules")
            .match_name("System.Reflection", "Assembly", "GetModules")
            .pre(|_ctx, thread| {
                // Return single-element array with a fake Module
                let module = thread.heap_mut().alloc_object(Token::new(0x7F00_0003)).ok();
                if let Some(m_ref) = module {
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, vec![EmValue::ObjectRef(m_ref)])
                    {
                        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
                        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                } else {
                    PreHookResult::Bypass(Some(EmValue::Null))
                }
            }),
    );

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_Name")
            .match_name("System.Reflection", "MethodBase", "get_Name")
            .pre(method_get_name_pre),
    );

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsVirtual")
            .match_name("System.Reflection", "MethodBase", "get_IsVirtual")
            .pre(method_get_is_virtual_pre),
    );

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsAbstract")
            .match_name("System.Reflection", "MethodBase", "get_IsAbstract")
            .pre(method_get_is_abstract_pre),
    );

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsPublic")
            .match_name("System.Reflection", "MethodBase", "get_IsPublic")
            .pre(method_get_is_public_pre),
    );

    manager.register(
        Hook::new("System.Reflection.MethodBase.GetMethodBody")
            .match_name("System.Reflection", "MethodBase", "GetMethodBody")
            .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::Null))),
    );

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_ContainsGenericParameters")
            .match_name(
                "System.Reflection",
                "MethodBase",
                "get_ContainsGenericParameters",
            )
            .pre(method_get_contains_generic_parameters_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_Name")
            .match_name("System.Reflection", "FieldInfo", "get_Name")
            .pre(field_get_name_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsStatic")
            .match_name("System.Reflection", "FieldInfo", "get_IsStatic")
            .pre(field_get_is_static_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsPublic")
            .match_name("System.Reflection", "FieldInfo", "get_IsPublic")
            .pre(field_get_is_public_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsPrivate")
            .match_name("System.Reflection", "FieldInfo", "get_IsPrivate")
            .pre(field_get_is_private_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsLiteral")
            .match_name("System.Reflection", "FieldInfo", "get_IsLiteral")
            .pre(field_get_is_literal_pre),
    );

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsInitOnly")
            .match_name("System.Reflection", "FieldInfo", "get_IsInitOnly")
            .pre(field_get_is_init_only_pre),
    );

    manager.register(
        Hook::new("System.Reflection.ConstructorInfo.get_DeclaringType")
            .match_name("System.Reflection", "ConstructorInfo", "get_DeclaringType")
            .pre(member_get_declaring_type_pre),
    );

    manager.register(
        Hook::new("System.Activator.CreateInstance")
            .match_name("System", "Activator", "CreateInstance")
            .pre(activator_create_instance_pre),
    );

    manager.register(
        Hook::new("System.Exception..ctor")
            .match_name("System", "Exception", ".ctor")
            .pre(|_ctx, _thread| PreHookResult::Bypass(None)),
    );

    manager.register(
        Hook::new("System.Object.GetType")
            .match_name("System", "Object", "GetType")
            .pre(object_get_type_pre),
    );
}

/// Hook for `System.Object.GetType()`.
///
/// Returns a `ReflectionType` representing the runtime type of the object.
/// Inspects the heap object to determine its type token:
/// - For `Object`, `BoxedValue`, `Delegate`: uses the stored `type_token`
/// - For `ReflectionType`: returns itself (Type.GetType() returns System.Type)
/// - For strings/arrays: returns a placeholder type
/// - Fallback: returns `Null`
fn object_get_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.this {
        // Try to get the type token from the heap object
        if let Ok(type_token) = thread.heap().get_type_token(*obj_ref) {
            match thread.heap_mut().alloc_reflection_type(type_token) {
                Ok(type_ref) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)));
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        // Check if it's a ReflectionType — Type.GetType() returns System.Type
        if thread.heap().get_reflection_type_token(*obj_ref).is_some() {
            // Return a ReflectionType for System.Type itself (placeholder token)
            match thread
                .heap_mut()
                .alloc_reflection_type(Token::new(0x7F00_0001))
            {
                Ok(type_ref) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)));
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
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
///
/// Extracts a reflection type token from an `EmValue` that may be an `ObjectRef`
/// pointing to a `ReflectionType` on the heap, or `Null`.
fn extract_type_token(thread: &EmulationThread, val: &EmValue) -> Option<Token> {
    match val {
        EmValue::ObjectRef(href) => thread.heap().get_reflection_type_token(*href),
        EmValue::Null => None,
        _ => None,
    }
}

/// Finds a method by name on a type, searching the inheritance chain.
///
/// If multiple overloads match, prefers the one with fewer parameters
/// (common obfuscator pattern). Walks `cil_type.base()` if not found on
/// the immediate type.
fn find_method_by_name(asm: &CilObject, type_token: Token, name: &str) -> Option<Token> {
    if let Some(cil_type) = asm.types().get(&type_token) {
        // Search the type's own methods
        let mut best: Option<(Token, usize)> = None;
        for (_, method_weak) in cil_type.methods.iter() {
            if let Some(method) = method_weak.upgrade() {
                if method.name == name {
                    let param_count = method.signature.params.len();
                    if best.is_none() || param_count < best.unwrap().1 {
                        best = Some((method.token, param_count));
                    }
                }
            }
        }
        if let Some((token, _)) = best {
            return Some(token);
        }

        // Walk the inheritance chain
        if let Some(base_rc) = cil_type.base() {
            return find_method_by_name(asm, base_rc.token, name);
        }
    }
    None
}

/// Finds a method by token in the assembly's type registry.
///
/// Iterates all types to find the method matching the given token.
/// Returns the `Arc<Method>` if found.
fn find_method_by_token(asm: &CilObject, method_token: Token) -> Option<Arc<Method>> {
    for entry in asm.types().iter() {
        let cil_type = entry.value();
        for (_, method_weak) in cil_type.methods.iter() {
            if let Some(method) = method_weak.upgrade() {
                if method.token == method_token {
                    return Some(method);
                }
            }
        }
    }
    None
}

/// Finds the declaring type token for a method by searching the assembly's type registry.
fn find_declaring_type(asm: &CilObject, method_token: Token) -> Option<Token> {
    for entry in asm.types().iter() {
        let cil_type = entry.value();
        for (_, method_weak) in cil_type.methods.iter() {
            if let Some(method) = method_weak.upgrade() {
                if method.token == method_token {
                    return Some(cil_type.token);
                }
            }
        }
    }
    None
}

/// Extracts a type token from a `TypeSignature`.
///
/// For Class/ValueType, returns the actual token. For primitives, returns a placeholder.
fn type_token_from_signature(sig: &TypeSignature) -> Token {
    match sig {
        TypeSignature::Class(t) | TypeSignature::ValueType(t) => *t,
        _ => Token::new(0x7F00_0001),
    }
}

/// Hook for `System.Type.op_Equality(Type, Type)`.
///
/// Compares two Type references for equality by their underlying metadata tokens.
/// Two null types are considered equal; a null and non-null are not.
fn type_op_equality_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let lhs_null = matches!(ctx.args.first(), Some(EmValue::Null) | None);
    let rhs_null = matches!(ctx.args.get(1), Some(EmValue::Null) | None);

    let equal = match (lhs_null, rhs_null) {
        (true, true) => true,
        (true, false) | (false, true) => false,
        (false, false) => {
            let lhs = ctx.args.first().and_then(|v| extract_type_token(thread, v));
            let rhs = ctx.args.get(1).and_then(|v| extract_type_token(thread, v));
            lhs == rhs
        }
    };
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// Hook for `System.Type.op_Inequality(Type, Type)`.
///
/// Compares two Type references for inequality by their underlying metadata tokens.
fn type_op_inequality_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let lhs_null = matches!(ctx.args.first(), Some(EmValue::Null) | None);
    let rhs_null = matches!(ctx.args.get(1), Some(EmValue::Null) | None);

    let not_equal = match (lhs_null, rhs_null) {
        (true, true) => false,
        (true, false) | (false, true) => true,
        (false, false) => {
            let lhs = ctx.args.first().and_then(|v| extract_type_token(thread, v));
            let rhs = ctx.args.get(1).and_then(|v| extract_type_token(thread, v));
            lhs != rhs
        }
    };
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(not_equal))))
}

fn type_get_module_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x7F00_0003)) {
        Ok(module_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(module_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.get_Assembly` property.
///
/// Gets the assembly in which the type is defined.
///
/// # Handled Overloads
///
/// - `Type.Assembly { get; } -> Assembly`
///
/// # Parameters
///
/// - `this`: The Type instance
///
/// # Returns
///
/// Returns the pre-allocated fake Assembly object from [`FakeObjects`], ensuring
/// consistency with `Module.get_Assembly`.
fn type_get_assembly_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(asm_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref)));
    }

    match thread.heap_mut().alloc_object(Token::new(0x7F00_0008)) {
        Ok(asm_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetTypeFromHandle` method.
///
/// Gets the type referenced by the specified type handle. The `ldtoken` instruction
/// pushes a `NativeInt` containing the raw metadata token, which is then passed as
/// a `RuntimeTypeHandle` argument. We extract this token and allocate a `ReflectionType`
/// heap object that carries it, enabling subsequent calls like `Type.GetFields()` to
/// look up the type's actual fields from assembly metadata.
///
/// # Handled Overloads
///
/// - `Type.GetTypeFromHandle(RuntimeTypeHandle) -> Type`
///
/// # Parameters
///
/// - `handle`: The RuntimeTypeHandle (NativeInt from `ldtoken`)
fn type_get_type_from_handle_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Extract the type token from the RuntimeTypeHandle argument.
    // The emulator represents ldtoken as NativeInt(token_value).
    #[allow(clippy::cast_sign_loss)]
    let type_token = ctx
        .args
        .first()
        .and_then(|arg| match arg {
            EmValue::NativeInt(v) => Some(Token::new(*v as u32)),
            EmValue::I32(v) => Some(Token::new(*v as u32)),
            EmValue::NativeUInt(v) => Some(Token::new(*v as u32)),
            // ValueType wrapping the handle — try the first field
            EmValue::ValueType { fields, .. } => fields.first().and_then(|f| match f {
                EmValue::NativeInt(v) => Some(Token::new(*v as u32)),
                EmValue::I32(v) => Some(Token::new(*v as u32)),
                _ => None,
            }),
            _ => None,
        })
        .unwrap_or_else(|| Token::new(0x7F00_0001));

    match thread.heap_mut().alloc_reflection_type(type_token) {
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
fn type_get_method_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to resolve the method by name if we have a ReflectionType with real metadata
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            // Try to get the method name from the first argument
            if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
                if let Ok(method_name) = thread.heap().get_string(*name_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(resolved) = find_method_by_name(&asm, type_token, &method_name)
                        {
                            match thread.heap_mut().alloc_reflection_method(resolved) {
                                Ok(m_ref) => {
                                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref)))
                                }
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: allocate a generic MethodInfo placeholder
    match thread
        .heap_mut()
        .alloc_reflection_method(Token::new(0x7F00_0002))
    {
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
fn type_get_field_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to resolve the field by name if we have a ReflectionType with real metadata
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            // Try to get the field name from the first argument
            if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
                if let Ok(field_name) = thread.heap().get_string(*name_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(cil_type) = asm.types().get(&type_token) {
                            for (_, field) in cil_type.fields.iter() {
                                if field.name == field_name.as_ref() {
                                    if let Ok(fi_ref) = thread.heap_mut().alloc_reflection_field(
                                        field.token,
                                        type_token,
                                        field.flags.is_static(),
                                    ) {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            fi_ref,
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: allocate a generic FieldInfo placeholder
    debug!("Type.GetField: returning fallback placeholder FieldInfo");
    match thread.heap_mut().alloc_object(Token::new(0x7F00_0004)) {
        Ok(field_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(field_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Type.GetFields` method.
///
/// Returns all fields of the type. When the `this` object is a `ReflectionType`
/// carrying a real metadata token, this hook looks up the type in the assembly's
/// type registry and returns an array of `ReflectionField` heap objects, each
/// carrying the actual field metadata token. This enables `FieldInfo.SetValue()`
/// to write real values to the emulator's heap and static field storage.
///
/// # Handled Overloads
///
/// - `Type.GetFields() -> FieldInfo[]`
/// - `Type.GetFields(BindingFlags) -> FieldInfo[]`
fn type_get_fields_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to get the type token from the 'this' ReflectionType object
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            // Look up the type in the assembly's type registry
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    // Collect all fields into ReflectionField heap objects
                    let mut field_elements = Vec::new();
                    for (_, field) in cil_type.fields.iter() {
                        match thread.heap_mut().alloc_reflection_field(
                            field.token,
                            type_token,
                            field.flags.is_static(),
                        ) {
                            Ok(fi_ref) => field_elements.push(EmValue::ObjectRef(fi_ref)),
                            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                        }
                    }

                    // Allocate an array containing the FieldInfo objects
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, field_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }

    // Fallback: return an empty array
    debug!("Type.GetFields: returning empty fallback array");
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
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
fn type_get_property_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
                if let Ok(property_name) = thread.heap().get_string(*name_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(cil_type) = asm.types().get(&type_token) {
                            // Search properties by name
                            for (_, prop) in cil_type.properties.iter() {
                                if prop.name == property_name.as_ref() {
                                    let getter_token = prop
                                        .fn_getter
                                        .get()
                                        .and_then(|mr| mr.upgrade().map(|m| m.token));
                                    let setter_token = prop
                                        .fn_setter
                                        .get()
                                        .and_then(|mr| mr.upgrade().map(|m| m.token));
                                    match thread.heap_mut().alloc_reflection_property(
                                        Arc::from(property_name.as_ref()),
                                        type_token,
                                        getter_token,
                                        setter_token,
                                    ) {
                                        Ok(p_ref) => {
                                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                                p_ref,
                                            )))
                                        }
                                        Err(_) => {
                                            return PreHookResult::Bypass(Some(EmValue::Null))
                                        }
                                    }
                                }
                            }

                            // Fallback: look for get_Name / set_Name method patterns
                            let get_name = format!("get_{property_name}");
                            let set_name = format!("set_{property_name}");
                            let getter_token = find_method_by_name(&asm, type_token, &get_name);
                            let setter_token = find_method_by_name(&asm, type_token, &set_name);
                            if getter_token.is_some() || setter_token.is_some() {
                                match thread.heap_mut().alloc_reflection_property(
                                    Arc::from(property_name.as_ref()),
                                    type_token,
                                    getter_token,
                                    setter_token,
                                ) {
                                    Ok(p_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            p_ref,
                                        )))
                                    }
                                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: allocate a generic PropertyInfo placeholder
    match thread.heap_mut().alloc_object(Token::new(0x7F00_0005)) {
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
fn type_get_constructor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                // Determine expected parameter count from the Type[] argument
                let expected_params = ctx
                    .args
                    .iter()
                    .find_map(|arg| {
                        if let EmValue::ObjectRef(arr_ref) = arg {
                            if let Ok(HeapObject::Array { elements, .. }) =
                                thread.heap().get(*arr_ref)
                            {
                                return Some(elements.len());
                            }
                        }
                        None
                    })
                    .unwrap_or(0);

                if let Some(cil_type) = asm.types().get(&type_token) {
                    // Search for .ctor with matching parameter count
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.name == ".ctor"
                                && method.signature.params.len() == expected_params
                            {
                                match thread.heap_mut().alloc_reflection_method(method.token) {
                                    Ok(m_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            m_ref,
                                        )))
                                    }
                                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                                }
                            }
                        }
                    }
                    // If no exact match, try first .ctor
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.name == ".ctor" {
                                match thread.heap_mut().alloc_reflection_method(method.token) {
                                    Ok(m_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            m_ref,
                                        )))
                                    }
                                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: allocate a stub ConstructorInfo
    match thread
        .heap_mut()
        .alloc_reflection_method(Token::new(0x7F00_0006))
    {
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

            // Return a reflection invoke request — the controller will
            // redirect execution to the target method
            return PreHookResult::ReflectionInvoke {
                request: Box::new(ReflectionInvokeRequest {
                    method_token,
                    this_ref,
                    args: method_args,
                }),
                bypass_value: Some(EmValue::Null),
            };
        }
    }

    // Fallback: no valid method token found
    debug!("MethodBase.Invoke: no valid method token found, returning Null");
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
fn constructor_invoke_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the constructor's method token from 'this' (ReflectionMethod)
    if let Some(EmValue::ObjectRef(ctor_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*ctor_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                // Find the declaring type to allocate the right object
                let declaring_type_token = find_declaring_type(&asm, method_token)
                    .unwrap_or_else(|| Token::new(0x7F00_0007));

                // Allocate the new object
                match thread.heap_mut().alloc_object(declaring_type_token) {
                    Ok(obj_ref) => {
                        // Extract constructor arguments from the first Object[] argument
                        let ctor_args = ctx
                            .args
                            .iter()
                            .find_map(|arg| {
                                if let EmValue::ObjectRef(arr_ref) = arg {
                                    if let Ok(HeapObject::Array { elements, .. }) =
                                        thread.heap().get(*arr_ref)
                                    {
                                        return Some(elements);
                                    }
                                }
                                None
                            })
                            .unwrap_or_default();

                        // Return a reflection invoke request for the constructor
                        return PreHookResult::ReflectionInvoke {
                            request: Box::new(ReflectionInvokeRequest {
                                method_token,
                                this_ref: Some(EmValue::ObjectRef(obj_ref)),
                                args: ctor_args,
                            }),
                            bypass_value: Some(EmValue::ObjectRef(obj_ref)),
                        };
                    }
                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }
        }
    }

    // Fallback: allocate a generic object instance
    match thread.heap_mut().alloc_object(Token::new(0x7F00_0007)) {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.get_Location` property.
///
/// Returns a plausible file path for the assembly using the module name from metadata
/// and the configured assembly location base path.
///
/// # Handled Overloads
///
/// - `Assembly.Location { get; } -> String`
fn assembly_get_location_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let module_name = thread
        .assembly()
        .and_then(|asm| {
            let tables = asm.tables()?;
            let strings = asm.strings()?;
            let module_table = tables.table::<ModuleRaw>()?;
            let module_row = module_table.iter().next()?;
            strings.get(module_row.name as usize).ok().map(String::from)
        })
        .unwrap_or_else(|| "module.exe".to_string());

    let base = &thread.config().environment.assembly_location_base;
    let path = format!("{base}\\{module_name}");

    match thread.heap_mut().alloc_string(&path) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Module.get_FullyQualifiedName` property.
///
/// Gets a string representing the fully qualified name and path to this module.
/// Reads the module name from metadata and combines it with the configured base path.
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
    let module_name = thread
        .assembly()
        .and_then(|asm| {
            let tables = asm.tables()?;
            let strings = asm.strings()?;
            let module_table = tables.table::<ModuleRaw>()?;
            let module_row = module_table.iter().next()?;
            strings.get(module_row.name as usize).ok().map(String::from)
        })
        .unwrap_or_else(|| "module.exe".to_string());

    let base = &thread.config().environment.module_base_path;
    let path = format!("{base}\\{module_name}");

    match thread.heap_mut().alloc_string(&path) {
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
    match thread.heap_mut().alloc_object(Token::new(0x7F00_0008)) {
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
    let method_token = if let Some(token_value) = ctx.args.first().and_then(EmValue::as_i32) {
        // The argument is the raw metadata token value (e.g., 0x06000001 for MethodDef)
        Token::new(token_value as u32)
    } else {
        // Fallback to generic MethodBase type if no token provided
        Token::new(0x7F00_0002)
    };

    debug!("Module.ResolveMethod: token 0x{:08X}", method_token.value(),);

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
fn module_resolve_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the metadata token from the first argument (int32)
    #[allow(clippy::cast_sign_loss)]
    let type_token = if let Some(token_value) = ctx.args.first().and_then(EmValue::as_i32) {
        Token::new(token_value as u32)
    } else {
        Token::new(0x7F00_0001)
    };

    match thread.heap_mut().alloc_reflection_type(type_token) {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Module.ResolveField` method.
///
/// Returns the field identified by the specified metadata token, along with its
/// declaring type and static flag so that downstream `FieldInfo.GetValue`/`SetValue`
/// hooks can read and write the correct storage.
///
/// # Handled Overloads
///
/// - `Module.ResolveField(Int32) -> FieldInfo`
/// - `Module.ResolveField(Int32, Type[], Type[]) -> FieldInfo`
///
/// # Parameters
///
/// - `metadataToken`: A metadata token that identifies a field in the module
/// - `genericTypeArguments`: An array of Type objects for generic type arguments (optional)
/// - `genericMethodArguments`: An array of Type objects for generic method arguments (optional)
fn module_resolve_field_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the metadata token from the first argument (int32)
    #[allow(clippy::cast_sign_loss)]
    let field_token = if let Some(token_value) = ctx.args.first().and_then(EmValue::as_i32) {
        Token::new(token_value as u32)
    } else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Find the declaring type and static flag by scanning all types for this field token
    if let Some(asm) = thread.assembly().cloned() {
        for entry in asm.types().iter() {
            let cil_type = entry.value();
            for (_, field) in cil_type.fields.iter() {
                if field.token == field_token {
                    match thread.heap_mut().alloc_reflection_field(
                        field_token,
                        cil_type.token,
                        field.flags.is_static(),
                    ) {
                        Ok(fi_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(fi_ref)));
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }

    // Field not found in assembly — return null
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.ModuleHandle.GetRuntimeTypeHandleFromMetadataToken`.
///
/// Converts a metadata token (int32) to a `RuntimeTypeHandle`. In real .NET, this
/// involves module-level token resolution. For emulation, we pass the raw token
/// through as a `NativeInt`, which `Type.GetTypeFromHandle` extracts correctly.
///
/// # Handled Overloads
///
/// - `ModuleHandle.GetRuntimeTypeHandleFromMetadataToken(int32) -> RuntimeTypeHandle`
///
/// # Parameters
///
/// - `metadataToken`: The metadata token to convert
fn module_handle_get_runtime_type_handle_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let token_value = match ctx.args.first() {
        Some(EmValue::I32(v)) => i64::from(*v),
        Some(EmValue::NativeInt(v)) => *v,
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::NativeInt(token_value)))
}

/// Hook for `System.Reflection.FieldInfo.GetValue` method.
///
/// Returns the value of a field. When the `this` object is a `ReflectionField`
/// carrying a real field token, reads the value from the emulator's heap (for
/// instance fields) or static field storage (for static fields).
///
/// # Handled Overloads
///
/// - `FieldInfo.GetValue(Object) -> Object`
///
/// # Parameters
///
/// - `obj`: The object whose field value will be returned (null for static fields)
fn field_get_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, _declaring_type, is_static)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if is_static {
                // Read from static field storage
                if let Some(value) = thread.address_space().get_static(field_token) {
                    return PreHookResult::Bypass(Some(box_value_if_needed(thread, value)));
                }
            } else {
                // Read from instance field on the target object
                let target = ctx.args.first();
                if let Some(EmValue::ObjectRef(obj_ref)) = target {
                    if let Ok(value) = thread.heap().get_field(*obj_ref, field_token) {
                        return PreHookResult::Bypass(Some(box_value_if_needed(thread, value)));
                    }
                }
                debug!(
                    "FieldInfo.GetValue: instance field 0x{:08X} → target not found or field missing",
                    field_token.value(),
                );
            }
        } else {
            debug!(
                "FieldInfo.GetValue: no reflection field info for {:?}",
                fi_ref
            );
        }
    } else {
        debug!(
            "FieldInfo.GetValue: this is not an ObjectRef: {:?}",
            ctx.this
        );
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Reflection.FieldInfo.SetValue` method.
///
/// Sets the value of a field. When the `this` object is a `ReflectionField`
/// carrying a real field token, writes the value to the emulator's heap (for
/// instance fields) or static field storage (for static fields). The value
/// argument is unboxed if it's a `BoxedValue` to extract the inner primitive.
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
fn field_set_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, _declaring_type, is_static)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            // Get the value to set (args[1] for SetValue(obj, value))
            let value = ctx.args.get(1).cloned().unwrap_or(EmValue::Null);

            // Unbox the value if it's a BoxedValue on the heap
            let unboxed = unbox_value(thread, &value);

            if is_static {
                // Write to static field storage — works for both null and non-null target
                thread.address_space().set_static(field_token, unboxed);
            } else {
                // Write to instance field on the target object
                let target = ctx.args.first();
                if let Some(EmValue::ObjectRef(obj_ref)) = target {
                    let _ = thread.heap().set_field(*obj_ref, field_token, unboxed);
                }
            }

            return PreHookResult::Bypass(None);
        }
        debug!(
            "FieldInfo.SetValue: no reflection field info for {:?}",
            fi_ref
        );
    } else {
        debug!(
            "FieldInfo.SetValue: this is not an ObjectRef: {:?}",
            ctx.this
        );
    }

    // Fallback: no-op if we can't identify the field
    PreHookResult::Bypass(None)
}

/// Hook for `System.Reflection.FieldInfo.get_FieldType` property.
///
/// Returns the type of the field. When the `this` object is a `ReflectionField`
/// carrying a real field token, looks up the field's type signature in the assembly
/// metadata and returns a `ReflectionType` for it.
///
/// # Handled Overloads
///
/// - `FieldInfo.FieldType { get; } -> Type`
fn field_get_field_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, _declaring_type, _is_static)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(sig) = asm.types().get_field_signature(&field_token) {
                    // Extract the type token from the signature. For Class/ValueType,
                    // use the actual TypeDef/TypeRef token. For primitives, use a
                    // placeholder (the initialization code typically just needs to
                    // distinguish value types from reference types).
                    let type_token = match &sig {
                        TypeSignature::Class(t) | TypeSignature::ValueType(t) => *t,
                        _ => Token::new(0x7F00_0001),
                    };
                    match thread.heap_mut().alloc_reflection_type(type_token) {
                        Ok(type_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }

    // Fallback: return a generic Type object
    match thread
        .heap_mut()
        .alloc_reflection_type(Token::new(0x7F00_0001))
    {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `MemberInfo.get_MetadataToken` property.
///
/// Returns the metadata token of the member. For `ReflectionField`, returns the
/// field token. For `ReflectionMethod`, returns the method token. For
/// `ReflectionType`, returns the type token.
///
/// # Handled Overloads
///
/// - `MemberInfo.MetadataToken { get; } -> Int32`
fn member_get_metadata_token_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(member_ref)) = ctx.this {
        if let Ok(obj) = thread.heap().get(*member_ref) {
            #[allow(clippy::cast_possible_wrap)]
            let token = match &obj {
                HeapObject::ReflectionField { field_token, .. } => Some(field_token.value() as i32),
                HeapObject::ReflectionMethod { method_token } => Some(method_token.value() as i32),
                HeapObject::ReflectionType { type_token } => Some(type_token.value() as i32),
                _ => None,
            };
            if let Some(token_val) = token {
                return PreHookResult::Bypass(Some(EmValue::I32(token_val)));
            }
        }
    }
    // Fallback: return 0 (invalid token)
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MethodBase.get_IsStatic` property.
///
/// Checks whether the method is static by looking up its flags in the assembly metadata.
///
/// # Handled Overloads
///
/// - `MethodBase.IsStatic { get; } -> Boolean`
fn method_get_is_static_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                // Look up method in the type registry to check its flags
                for entry in asm.types().iter() {
                    let cil_type = entry.value();
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.token == method_token {
                                let is_static = method.is_static();
                                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                    is_static,
                                ))));
                            }
                        }
                    }
                }
            }
        }
    }
    // Fallback: assume static
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `DynamicMethod.GetILGenerator()`.
///
/// Creates a proper `HeapObject::ILGenerator` linked to the DynamicMethod's
/// `HeapObject::DynamicMethod` so that subsequent `Emit(OpCode, MethodInfo)`
/// calls can store the target method on the correct DynamicMethod.
fn dynamic_method_get_il_generator_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dm_ref)) = ctx.this {
        match thread.heap_mut().alloc_il_generator(*dm_ref) {
            Ok(il_ref) => {
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(il_ref)));
            }
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }
    // Fallback: stub ILGenerator for non-DynamicMethod `this`
    match thread.heap_mut().alloc_object(Token::new(0x7F00_000A)) {
        Ok(il_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(il_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for all `ILGenerator.Emit(...)` overloads.
///
/// Most overloads are no-ops (Ldarg, Ret, Tailcall, etc.). The critical overload
/// is `Emit(OpCode, MethodInfo)` — when the MethodInfo arg is a `ReflectionMethod`,
/// we extract its method token and store it on the owning DynamicMethod as the
/// call target. This mirrors how the .NET runtime stores method references in the
/// `DynamicScope` for later resolution.
fn il_generator_emit_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Check if any argument is a ReflectionMethod — indicates Emit(OpCode, MethodInfo)
    let mut target_method = None;
    for arg in ctx.args.iter() {
        if let EmValue::ObjectRef(href) = arg {
            if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*href) {
                target_method = Some(method_token);
                break;
            }
        }
    }

    // If we found a MethodInfo arg, store its token on the owning DynamicMethod
    if let Some(method_token) = target_method {
        if let Some(EmValue::ObjectRef(il_ref)) = ctx.this {
            if let Some(dm_ref) = thread.heap().get_il_generator_owner(*il_ref) {
                thread
                    .heap()
                    .set_dynamic_method_target(dm_ref, method_token);
            }
        }
    }

    PreHookResult::Bypass(None)
}

/// Hook for `DynamicMethod.CreateDelegate(Type)`.
///
/// Reads the target method token stored on the `HeapObject::DynamicMethod` by
/// `ILGenerator.Emit(OpCode, MethodInfo)` and creates a proper `HeapObject::Delegate`
/// that will dispatch to the correct target when invoked.
///
/// If no target was stored (the DynamicMethod IL wasn't tracked), falls back to
/// a stub delegate.
fn dynamic_method_create_delegate_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Extract delegate type from args (the Type argument)
    let mut type_token = Token::new(0x7F00_000C);
    for arg in ctx.args.iter() {
        if let EmValue::ObjectRef(href) = arg {
            if let Ok(HeapObject::ReflectionType { type_token: tt }) = thread.heap().get(*href) {
                type_token = tt;
                break;
            }
        }
    }

    // Read the target method from the DynamicMethod heap object
    if let Some(EmValue::ObjectRef(dm_ref)) = ctx.this {
        if let Some(target) = thread.heap().get_dynamic_method_target(*dm_ref) {
            match thread.heap_mut().alloc_delegate(type_token, None, target) {
                Ok(del_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(del_ref))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }

    // Fallback: no target stored — return stub delegate
    debug!("DynamicMethod.CreateDelegate: no target method found, returning stub");
    match thread
        .heap_mut()
        .alloc_delegate(type_token, None, Token::new(0x7F00_0002))
    {
        Ok(del_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(del_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Delegate.CreateDelegate(Type, MethodInfo)` static method.
///
/// Creates a functional `HeapObject::Delegate` using the method token from the
/// `ReflectionMethod` argument. This enables delegate dispatch to actually invoke
/// the target method.
///
/// # Handled Overloads
///
/// - `Delegate.CreateDelegate(Type, MethodInfo) -> Delegate`
/// - `Delegate.CreateDelegate(Type, Object, MethodInfo) -> Delegate`
fn delegate_create_delegate_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Find the MethodInfo argument — it's the last ObjectRef that's a ReflectionMethod.
    // Overloads: (Type, MethodInfo) or (Type, Object, MethodInfo)
    let mut method_token = None;
    let mut target = None;
    let mut type_token = Token::new(0x7F00_000C);

    for arg in ctx.args.iter() {
        if let EmValue::ObjectRef(href) = arg {
            if let Ok(obj) = thread.heap().get(*href) {
                match &obj {
                    HeapObject::ReflectionMethod { method_token: mt } => {
                        method_token = Some(*mt);
                    }
                    HeapObject::ReflectionType { type_token: tt } => {
                        type_token = *tt;
                    }
                    _ => {
                        // Could be the target object for instance delegates
                        target = Some(*href);
                    }
                }
            }
        }
    }

    if let Some(mt) = method_token {
        match thread.heap_mut().alloc_delegate(type_token, target, mt) {
            Ok(del_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(del_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }

    // Fallback: return a stub delegate
    debug!("Delegate.CreateDelegate: no method token found, returning stub delegate");
    match thread
        .heap_mut()
        .alloc_delegate(type_token, None, Token::new(0x7F00_0002))
    {
        Ok(del_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(del_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Delegate.Invoke` and `MulticastDelegate.Invoke`.
///
/// When the `this` object is a `HeapObject::Delegate` with a valid MethodDef target,
/// sets up a `ReflectionInvokeRequest` to redirect execution to the target method.
/// This is the MemberRef hook path — internal delegate types (MethodDef Invoke methods)
/// are handled directly in the controller's delegate dispatch logic.
fn delegate_invoke_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(HeapObject::Delegate {
            method_token: target_token,
            ..
        }) = thread.heap().get(*href)
        {
            // Only dispatch if the target is a real MethodDef token (table 0x06).
            // Placeholder tokens (0x7F00_xxxx) and zero tokens are not dispatched.
            if target_token.is_table(TableId::MethodDef) {
                // Return a reflection invoke request — the controller will
                // redirect execution to the delegate's target method.
                return PreHookResult::ReflectionInvoke {
                    request: Box::new(ReflectionInvokeRequest {
                        method_token: target_token,
                        this_ref: None,
                        args: ctx.args.to_vec(),
                    }),
                    bypass_value: Some(EmValue::Null),
                };
            }
        }
    }
    // Fallback: no valid delegate target
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_IsValueType` property.
fn type_get_is_value_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let is_value = *cil_type.flavor() == CilFlavor::ValueType;
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_value))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MemberInfo.get_DeclaringType` property.
///
/// Handles `ReflectionField`, `ReflectionMethod`, and `ReflectionProperty`.
fn member_get_declaring_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(member_ref)) = ctx.this {
        if let Ok(obj) = thread.heap().get(*member_ref) {
            let declaring_token = match &obj {
                HeapObject::ReflectionField {
                    declaring_type_token,
                    ..
                } => Some(*declaring_type_token),
                HeapObject::ReflectionProperty {
                    declaring_type_token,
                    ..
                } => Some(*declaring_type_token),
                HeapObject::ReflectionMethod { method_token } => thread
                    .assembly()
                    .and_then(|asm| find_declaring_type(asm, *method_token)),
                _ => None,
            };
            if let Some(dt) = declaring_token {
                match thread.heap_mut().alloc_reflection_type(dt) {
                    Ok(type_ref) => {
                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)))
                    }
                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }
        }
    }
    // Fallback
    match thread
        .heap_mut()
        .alloc_reflection_type(Token::new(0x7F00_0001))
    {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `MethodInfo.get_ReturnType` property.
fn method_get_return_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                // Find the method in the type registry to get its return type
                for entry in asm.types().iter() {
                    let cil_type = entry.value();
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.token == method_token {
                                let ret_token = match &method.signature.return_type.base {
                                    TypeSignature::Class(t) | TypeSignature::ValueType(t) => *t,
                                    _ => Token::new(0x7F00_0001),
                                };
                                match thread.heap_mut().alloc_reflection_type(ret_token) {
                                    Ok(type_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            type_ref,
                                        )))
                                    }
                                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Fallback
    match thread
        .heap_mut()
        .alloc_reflection_type(Token::new(0x7F00_0001))
    {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `MethodBase.GetParameters()`.
///
/// Returns an array of `ParameterInfo` objects with real parameter type information
/// when the method token resolves to real assembly metadata.
fn method_get_parameters_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, method_token) {
                    let mut param_elements = Vec::new();
                    #[allow(clippy::cast_possible_truncation)]
                    for (i, param) in method.signature.params.iter().enumerate() {
                        match thread.heap_mut().alloc_reflection_parameter(
                            method_token,
                            i as u32,
                            param.base.clone(),
                        ) {
                            Ok(p_ref) => param_elements.push(EmValue::ObjectRef(p_ref)),
                            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, param_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }

    // Fallback: return an empty array
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `PropertyInfo.GetValue(object)` — invoke the getter via reflection.
fn property_get_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, Some(getter), _)) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            let this_ref = ctx.args.first().cloned();
            return PreHookResult::ReflectionInvoke {
                request: Box::new(ReflectionInvokeRequest {
                    method_token: getter,
                    this_ref,
                    args: Vec::new(),
                }),
                bypass_value: Some(EmValue::Null),
            };
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.SetValue(object, object)` — invoke the setter via reflection.
fn property_set_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, _, Some(setter))) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            let this_ref = ctx.args.first().cloned();
            let set_args = ctx.args.get(1).cloned().into_iter().collect();
            return PreHookResult::ReflectionInvoke {
                request: Box::new(ReflectionInvokeRequest {
                    method_token: setter,
                    this_ref,
                    args: set_args,
                }),
                bypass_value: None,
            };
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `PropertyInfo.get_PropertyType`.
fn property_get_property_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, Some(getter), _)) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, getter) {
                    let ret_token = type_token_from_signature(&method.signature.return_type.base);
                    match thread.heap_mut().alloc_reflection_type(ret_token) {
                        Ok(type_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread
        .heap_mut()
        .alloc_reflection_type(Token::new(0x7F00_0001))
    {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `PropertyInfo.get_CanRead`.
fn property_get_can_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, getter_token, _)) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(getter_token.is_some()))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `PropertyInfo.get_CanWrite`.
fn property_get_can_write_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, _, setter_token)) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(setter_token.is_some()))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `PropertyInfo.get_Name`.
fn property_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((name, _, _, _)) = thread.heap().get_reflection_property_info(*prop_ref) {
            match thread.heap_mut().alloc_string(&name) {
                Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.GetGetMethod`.
fn property_get_get_method_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, Some(getter), _)) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            match thread.heap_mut().alloc_reflection_method(getter) {
                Ok(m_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.GetSetMethod`.
fn property_get_set_method_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, _, Some(setter))) = thread.heap().get_reflection_property_info(*prop_ref)
        {
            match thread.heap_mut().alloc_reflection_method(setter) {
                Ok(m_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `ParameterInfo.get_ParameterType` — return real type from ReflectionParameter.
fn parameter_get_parameter_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(param_ref)) = ctx.this {
        if let Some((_, _, param_type)) = thread.heap().get_reflection_parameter_info(*param_ref) {
            let type_token = type_token_from_signature(&param_type);
            match thread.heap_mut().alloc_reflection_type(type_token) {
                Ok(type_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    match thread
        .heap_mut()
        .alloc_reflection_type(Token::new(0x7F00_0001))
    {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.get_FullName`.
fn type_get_full_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let full_name = if cil_type.namespace.is_empty() {
                        cil_type.name.clone()
                    } else {
                        format!("{}.{}", cil_type.namespace, cil_type.name)
                    };
                    match thread.heap_mut().alloc_string(&full_name) {
                        Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_Name`.
fn type_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    match thread.heap_mut().alloc_string(&cil_type.name) {
                        Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_Namespace`.
fn type_get_namespace_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    match thread.heap_mut().alloc_string(&cil_type.namespace) {
                        Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_BaseType`.
fn type_get_base_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    if let Some(base_type) = cil_type.base() {
                        match thread.heap_mut().alloc_reflection_type(base_type.token) {
                            Ok(t_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(t_ref)))
                            }
                            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_IsArray`.
fn type_get_is_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let is_array = matches!(cil_type.flavor(), CilFlavor::Array { .. });
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_array))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Type.get_IsEnum`.
fn type_get_is_enum_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let is_enum = cil_type
                        .base()
                        .is_some_and(|base| base.name == "Enum" && base.namespace == "System");
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_enum))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Factory for Type boolean flag hooks that check CilType metadata.
fn type_get_bool_flag_pre(
    check: fn(&CilType) -> bool,
) -> impl Fn(&HookContext<'_>, &mut EmulationThread) -> PreHookResult {
    move |ctx, thread| {
        if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
            if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
                if let Some(asm) = thread.assembly().cloned() {
                    if let Some(cil_type) = asm.types().get(&type_token) {
                        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(check(
                            &cil_type,
                        )))));
                    }
                }
            }
        }
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `Type.GetMethods()` / `Type.GetMethods(BindingFlags)`.
fn type_get_methods_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut method_elements = Vec::new();
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            // Skip constructors — GetMethods() doesn't include them
                            if method.name == ".ctor" || method.name == ".cctor" {
                                continue;
                            }
                            match thread.heap_mut().alloc_reflection_method(method.token) {
                                Ok(m_ref) => method_elements.push(EmValue::ObjectRef(m_ref)),
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, method_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetProperties()` / `Type.GetProperties(BindingFlags)`.
fn type_get_properties_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut prop_elements = Vec::new();
                    for (_, prop) in cil_type.properties.iter() {
                        let getter_token = prop
                            .fn_getter
                            .get()
                            .and_then(|mr| mr.upgrade().map(|m| m.token));
                        let setter_token = prop
                            .fn_setter
                            .get()
                            .and_then(|mr| mr.upgrade().map(|m| m.token));
                        match thread.heap_mut().alloc_reflection_property(
                            Arc::from(prop.name.as_str()),
                            type_token,
                            getter_token,
                            setter_token,
                        ) {
                            Ok(p_ref) => prop_elements.push(EmValue::ObjectRef(p_ref)),
                            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, prop_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetConstructors()` / `Type.GetConstructors(BindingFlags)`.
fn type_get_constructors_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut ctor_elements = Vec::new();
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.name == ".ctor" {
                                match thread.heap_mut().alloc_reflection_method(method.token) {
                                    Ok(m_ref) => ctor_elements.push(EmValue::ObjectRef(m_ref)),
                                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                                }
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, ctor_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetInterfaces()`.
fn type_get_interfaces_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut iface_elements = Vec::new();
                    for (_, iface_entry) in cil_type.interfaces.iter() {
                        if let Some(iface_type) = iface_entry.interface.upgrade() {
                            match thread.heap_mut().alloc_reflection_type(iface_type.token) {
                                Ok(t_ref) => iface_elements.push(EmValue::ObjectRef(t_ref)),
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, iface_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetNestedTypes()`.
fn type_get_nested_types_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut nested_elements = Vec::new();
                    for (_, nested_ref) in cil_type.nested_types.iter() {
                        if let Some(nested_type) = nested_ref.upgrade() {
                            match thread.heap_mut().alloc_reflection_type(nested_type.token) {
                                Ok(t_ref) => nested_elements.push(EmValue::ObjectRef(t_ref)),
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, nested_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetMembers()` — returns combined fields + methods + properties.
fn type_get_members_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut member_elements = Vec::new();

                    // Add fields
                    for (_, field) in cil_type.fields.iter() {
                        match thread.heap_mut().alloc_reflection_field(
                            field.token,
                            type_token,
                            field.flags.is_static(),
                        ) {
                            Ok(fi_ref) => member_elements.push(EmValue::ObjectRef(fi_ref)),
                            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                        }
                    }

                    // Add methods
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            match thread.heap_mut().alloc_reflection_method(method.token) {
                                Ok(m_ref) => member_elements.push(EmValue::ObjectRef(m_ref)),
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }

                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, member_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetEnumValues()`.
fn type_get_enum_values_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut values = Vec::new();
                    for (_, field) in cil_type.fields.iter() {
                        if field.flags.is_literal() && field.flags.is_static() {
                            // Get the constant value if available
                            if let Some(val) = field.default.get() {
                                #[allow(clippy::cast_possible_wrap)]
                                let em_val = match &val.data {
                                    CilPrimitiveData::I4(v) => EmValue::I32(*v),
                                    CilPrimitiveData::I8(v) => EmValue::I64(*v),
                                    CilPrimitiveData::U4(v) => EmValue::I32(*v as i32),
                                    CilPrimitiveData::I2(v) => EmValue::I32(i32::from(*v)),
                                    CilPrimitiveData::U2(v) => EmValue::I32(i32::from(*v)),
                                    CilPrimitiveData::I1(v) => EmValue::I32(i32::from(*v)),
                                    CilPrimitiveData::U1(v) => EmValue::I32(i32::from(*v)),
                                    _ => EmValue::I32(0),
                                };
                                values.push(em_val);
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::I4, values)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::I4, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.GetEnumNames()`.
fn type_get_enum_names_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    let mut names = Vec::new();
                    for (_, field) in cil_type.fields.iter() {
                        if field.flags.is_literal() && field.flags.is_static() {
                            match thread.heap_mut().alloc_string(&field.name) {
                                Ok(s_ref) => names.push(EmValue::ObjectRef(s_ref)),
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, names)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Type.IsAssignableFrom(Type)`.
fn type_is_assignable_from_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Some(this_token) = thread.heap().get_reflection_type_token(*this_ref) {
            if let Some(EmValue::ObjectRef(other_ref)) = ctx.args.first() {
                if let Some(other_token) = thread.heap().get_reflection_type_token(*other_ref) {
                    // Same type
                    if this_token == other_token {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }
                    // Walk inheritance chain of 'other' looking for 'this'
                    if let Some(asm) = thread.assembly().cloned() {
                        let mut current = Some(other_token);
                        while let Some(tok) = current {
                            if tok == this_token {
                                return PreHookResult::Bypass(Some(EmValue::I32(1)));
                            }
                            current = asm
                                .types()
                                .get(&tok)
                                .and_then(|t| t.base().map(|b| b.token));
                        }
                        // Check interfaces
                        if let Some(other_type) = asm.types().get(&other_token) {
                            for (_, iface_entry) in other_type.interfaces.iter() {
                                if let Some(iface) = iface_entry.interface.upgrade() {
                                    if iface.token == this_token {
                                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Type.IsSubclassOf(Type)`.
fn type_is_subclass_of_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Some(this_token) = thread.heap().get_reflection_type_token(*this_ref) {
            if let Some(EmValue::ObjectRef(other_ref)) = ctx.args.first() {
                if let Some(other_token) = thread.heap().get_reflection_type_token(*other_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        // Walk inheritance chain of 'this' looking for 'other'
                        let mut current = asm
                            .types()
                            .get(&this_token)
                            .and_then(|t| t.base().map(|b| b.token));
                        while let Some(tok) = current {
                            if tok == other_token {
                                return PreHookResult::Bypass(Some(EmValue::I32(1)));
                            }
                            current = asm
                                .types()
                                .get(&tok)
                                .and_then(|t| t.base().map(|b| b.token));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Assembly.GetTypes()`.
fn assembly_get_types_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        let mut type_elements = Vec::new();
        for entry in asm.types().iter() {
            let cil_type = entry.value();
            match thread.heap_mut().alloc_reflection_type(cil_type.token) {
                Ok(t_ref) => type_elements.push(EmValue::ObjectRef(t_ref)),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        match thread
            .heap_mut()
            .alloc_array_with_values(CilFlavor::Object, type_elements)
        {
            Ok(arr_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Assembly.GetExportedTypes()` — same as GetTypes but only public.
fn assembly_get_exported_types_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        let mut type_elements = Vec::new();
        for entry in asm.types().iter() {
            let cil_type = entry.value();
            if cil_type.flags.is_public() {
                match thread.heap_mut().alloc_reflection_type(cil_type.token) {
                    Ok(t_ref) => type_elements.push(EmValue::ObjectRef(t_ref)),
                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }
        }
        match thread
            .heap_mut()
            .alloc_array_with_values(CilFlavor::Object, type_elements)
        {
            Ok(arr_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Assembly.GetType(string)` / `Assembly.GetType(string, bool)`.
fn assembly_get_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
        if let Ok(type_name) = thread.heap().get_string(*name_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                for entry in asm.types().iter() {
                    let cil_type = entry.value();
                    let full_name = if cil_type.namespace.is_empty() {
                        &cil_type.name
                    } else {
                        // Check both "Namespace.Name" formats
                        &format!("{}.{}", cil_type.namespace, cil_type.name)
                    };
                    if full_name == type_name.as_ref() || cil_type.name == type_name.as_ref() {
                        match thread.heap_mut().alloc_reflection_type(cil_type.token) {
                            Ok(t_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(t_ref)))
                            }
                            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `MethodBase.get_Name`.
fn method_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, method_token) {
                    match thread.heap_mut().alloc_string(&method.name) {
                        Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `MethodBase.get_IsVirtual`.
fn method_get_is_virtual_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, method_token) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_virtual(),
                    ))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MethodBase.get_IsAbstract`.
fn method_get_is_abstract_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, method_token) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_abstract(),
                    ))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MethodBase.get_IsPublic`.
fn method_get_is_public_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, method_token) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_public(),
                    ))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MethodBase.get_ContainsGenericParameters`.
fn method_get_contains_generic_parameters_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token }) = thread.heap().get(*method_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = find_method_by_token(&asm, method_token) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        !method.generic_params.is_empty(),
                    ))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_Name`.
fn field_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            match thread.heap_mut().alloc_string(&field.name) {
                                Ok(s_ref) => {
                                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref)))
                                }
                                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                            }
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `FieldInfo.get_IsStatic`.
fn field_get_is_static_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((_, _, is_static)) = thread.heap().get_reflection_field_info(*fi_ref) {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_static))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsPublic`.
fn field_get_is_public_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            let is_public = field.flags.access() == FieldAttributes::PUBLIC;
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_public))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsPrivate`.
fn field_get_is_private_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            let is_private = field.flags.access() == FieldAttributes::PRIVATE;
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                is_private,
                            ))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsLiteral`.
fn field_get_is_literal_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                field.flags.is_literal(),
                            ))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsInitOnly`.
fn field_get_is_init_only_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            thread.heap().get_reflection_field_info(*fi_ref)
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                field.flags.is_init_only(),
                            ))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Activator.CreateInstance(Type)` and `Activator.CreateInstance(Type, object[])`.
fn activator_create_instance_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Find the Type argument (first arg that's a ReflectionType)
    let type_token = ctx.args.iter().find_map(|arg| {
        if let EmValue::ObjectRef(href) = arg {
            thread.heap().get_reflection_type_token(*href)
        } else {
            None
        }
    });

    if let Some(type_token) = type_token {
        // Allocate the object
        match thread.heap_mut().alloc_object(type_token) {
            Ok(obj_ref) => {
                // Find a matching constructor
                if let Some(asm) = thread.assembly().cloned() {
                    // Extract args from object[] parameter if present
                    let ctor_args: Vec<EmValue> = ctx
                        .args
                        .iter()
                        .find_map(|arg| {
                            if let EmValue::ObjectRef(arr_ref) = arg {
                                if let Ok(HeapObject::Array { elements, .. }) =
                                    thread.heap().get(*arr_ref)
                                {
                                    return Some(elements);
                                }
                            }
                            None
                        })
                        .unwrap_or_default();

                    let expected_params = ctor_args.len();
                    if let Some(cil_type) = asm.types().get(&type_token) {
                        // Find matching .ctor
                        for (_, method_weak) in cil_type.methods.iter() {
                            if let Some(method) = method_weak.upgrade() {
                                if method.name == ".ctor"
                                    && method.signature.params.len() == expected_params
                                {
                                    return PreHookResult::ReflectionInvoke {
                                        request: Box::new(ReflectionInvokeRequest {
                                            method_token: method.token,
                                            this_ref: Some(EmValue::ObjectRef(obj_ref)),
                                            args: ctor_args,
                                        }),
                                        bypass_value: Some(EmValue::ObjectRef(obj_ref)),
                                    };
                                }
                            }
                        }
                    }
                }
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref)));
            }
            Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
        }
    }

    // Fallback
    match thread.heap_mut().alloc_object(Token::new(0x7F00_0007)) {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Unbox a value if it's a `BoxedValue` on the heap, otherwise return as-is.
///
/// In .NET, `FieldInfo.SetValue(obj, value)` passes the value as `object`,
/// so primitives are boxed. This helper extracts the inner value.
fn unbox_value(thread: &EmulationThread, value: &EmValue) -> EmValue {
    if let EmValue::ObjectRef(href) = value {
        if let Ok(HeapObject::BoxedValue { value: inner, .. }) = thread.heap().get(*href) {
            return *inner;
        }
    }
    value.clone()
}

/// Box a primitive value for return from `FieldInfo.GetValue`.
///
/// If the value is already an `ObjectRef` or `Null`, return as-is.
/// Otherwise, box it so it can be used as an `object` return value.
fn box_value_if_needed(thread: &EmulationThread, value: EmValue) -> EmValue {
    match &value {
        EmValue::ObjectRef(_) | EmValue::Null => value,
        EmValue::I32(_) => {
            // Box int32
            match thread.heap().alloc_boxed(Token::new(0x7F00_0001), value) {
                Ok(href) => EmValue::ObjectRef(href),
                Err(_) => EmValue::Null,
            }
        }
        EmValue::I64(_) => match thread.heap().alloc_boxed(Token::new(0x7F00_0001), value) {
            Ok(href) => EmValue::ObjectRef(href),
            Err(_) => EmValue::Null,
        },
        // For other types, return as-is (the caller may need to handle boxing)
        _ => value,
    }
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
        let manager = HookManager::new();
        register(&manager);
        assert_eq!(manager.len(), 101);
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
