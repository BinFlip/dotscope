//! `System.AppDomain` and `System.Reflection.Assembly` method hooks.
//!
//! This module provides hook implementations for application domain and assembly-related
//! methods that are commonly used in obfuscated .NET assemblies for dynamic assembly
//! loading, event handling, and resource access.
//!
//! # Overview
//!
//! Obfuscators frequently use dynamic assembly loading to hide payloads or decrypt
//! embedded code at runtime. This module's hooks intercept these operations and capture
//! the loaded assembly bytes for analysis, which is crucial for unpacking protected
//! executables.
//!
//! # Emulated .NET Methods
//!
//! ## AppDomain Methods
//!
//! | .NET Method | Hook Behavior |
//! |-------------|---------------|
//! | `AppDomain.CurrentDomain` | Returns a symbolic `AppDomain` object |
//! | `AppDomain.add_AssemblyResolve` | No-op (event registration ignored) |
//! | `AppDomain.remove_AssemblyResolve` | No-op (event unregistration ignored) |
//! | `AppDomain.GetAssemblies()` | Returns an empty `Assembly[]` array |
//!
//! ## Assembly Methods
//!
//! | .NET Method | Hook Behavior |
//! |-------------|---------------|
//! | `Assembly.Load(byte[])` | **Captures bytes**, returns symbolic `Assembly` |
//! | `Assembly.LoadFrom(string)` | Returns symbolic `Assembly` (path not loaded) |
//! | `Assembly.GetExecutingAssembly()` | Returns symbolic `Assembly` |
//! | `Assembly.GetCallingAssembly()` | Returns symbolic `Assembly` |
//! | `Assembly.GetEntryAssembly()` | Returns symbolic `Assembly` |
//! | `Assembly.GetManifestResourceStream()` | Returns stream with resource data |
//! | `Assembly.GetManifestResourceNames()` | Returns empty `string[]` |
//!
//! ## Delegate Methods
//!
//! | .NET Method | Hook Behavior |
//! |-------------|---------------|
//! | `Delegate..ctor` | Returns symbolic delegate object |
//! | `MulticastDelegate..ctor` | Returns symbolic delegate object |
//! | `ResolveEventHandler..ctor` | Returns symbolic delegate object |
//!
//! # Deobfuscation Use Cases
//!
//! ## Unpacking Embedded Assemblies
//!
//! Many packers store encrypted assemblies as resources or embedded data. At runtime,
//! they decrypt the bytes and call `Assembly.Load(byte[])`. This hook captures those
//! bytes, allowing the analyst to extract the unpacked assembly.

use crate::{
    emulation::{
        capture::{AssemblyLoadMethod, CaptureSource},
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::{token::Token, typesystem::CilFlavor},
};

/// Registers all AppDomain and Assembly method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `AppDomain.get_CurrentDomain`
/// - `AppDomain.add_AssemblyResolve` / `remove_AssemblyResolve`
/// - `AppDomain.GetAssemblies()`
/// - `Assembly.Load(byte[])` - **captures assembly bytes**
/// - `Assembly.LoadFrom(string)`
/// - `Assembly.GetExecutingAssembly()` / `GetCallingAssembly()` / `GetEntryAssembly()`
/// - `Assembly.GetManifestResourceStream()` / `GetManifestResourceNames()`
/// - `Delegate..ctor` / `MulticastDelegate..ctor` / `ResolveEventHandler..ctor`
pub fn register(manager: &mut HookManager) {
    // AppDomain methods
    manager.register(
        Hook::new("System.AppDomain.get_CurrentDomain")
            .match_name("System", "AppDomain", "get_CurrentDomain")
            .pre(appdomain_get_current_domain_pre),
    );

    manager.register(
        Hook::new("System.AppDomain.add_AssemblyResolve")
            .match_name("System", "AppDomain", "add_AssemblyResolve")
            .pre(appdomain_add_assembly_resolve_pre),
    );

    manager.register(
        Hook::new("System.AppDomain.remove_AssemblyResolve")
            .match_name("System", "AppDomain", "remove_AssemblyResolve")
            .pre(appdomain_remove_assembly_resolve_pre),
    );

    manager.register(
        Hook::new("System.AppDomain.GetAssemblies")
            .match_name("System", "AppDomain", "GetAssemblies")
            .pre(appdomain_get_assemblies_pre),
    );

    // Assembly methods
    manager.register(
        Hook::new("System.Reflection.Assembly.Load")
            .match_name("System.Reflection", "Assembly", "Load")
            .pre(assembly_load_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.LoadFrom")
            .match_name("System.Reflection", "Assembly", "LoadFrom")
            .pre(assembly_load_from_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetExecutingAssembly")
            .match_name("System.Reflection", "Assembly", "GetExecutingAssembly")
            .pre(assembly_get_executing_assembly_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetCallingAssembly")
            .match_name("System.Reflection", "Assembly", "GetCallingAssembly")
            .pre(assembly_get_calling_assembly_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetEntryAssembly")
            .match_name("System.Reflection", "Assembly", "GetEntryAssembly")
            .pre(assembly_get_entry_assembly_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetManifestResourceStream")
            .match_name("System.Reflection", "Assembly", "GetManifestResourceStream")
            .pre(assembly_get_manifest_resource_stream_pre),
    );

    manager.register(
        Hook::new("System.Reflection.Assembly.GetManifestResourceNames")
            .match_name("System.Reflection", "Assembly", "GetManifestResourceNames")
            .pre(assembly_get_manifest_resource_names_pre),
    );

    // Delegate methods
    manager.register(
        Hook::new("System.Delegate..ctor")
            .match_name("System", "Delegate", ".ctor")
            .pre(delegate_ctor_pre),
    );

    manager.register(
        Hook::new("System.MulticastDelegate..ctor")
            .match_name("System", "MulticastDelegate", ".ctor")
            .pre(delegate_ctor_pre),
    );

    manager.register(
        Hook::new("System.ResolveEventHandler..ctor")
            .match_name("System", "ResolveEventHandler", ".ctor")
            .pre(delegate_ctor_pre),
    );
}

/// Hook for `System.AppDomain.get_CurrentDomain` property.
///
/// # Handled Overloads
///
/// - `AppDomain.CurrentDomain -> AppDomain` (property getter)
///
/// # Parameters
///
/// None (static property).
///
/// # Returns
///
/// The cached `AppDomain` object reference for consistent equality checks.
fn appdomain_get_current_domain_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Return cached fake app domain for consistent equality checks
    if let Some(domain_ref) = thread.fake_objects().app_domain() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(domain_ref)));
    }

    // Fallback: allocate new object if cache not initialized
    match thread.heap_mut().alloc_object(Token::new(0x0100_0011)) {
        Ok(domain_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(domain_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.AppDomain.add_AssemblyResolve` event accessor.
///
/// # Handled Overloads
///
/// - `AppDomain.add_AssemblyResolve(ResolveEventHandler) -> void`
///
/// # Parameters
///
/// - `value`: The `ResolveEventHandler` delegate to add to the event.
///
/// # Returns
///
/// None. This hook is a no-op (event subscription is ignored during emulation).
fn appdomain_add_assembly_resolve_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.AppDomain.remove_AssemblyResolve` event accessor.
///
/// # Handled Overloads
///
/// - `AppDomain.remove_AssemblyResolve(ResolveEventHandler) -> void`
///
/// # Parameters
///
/// - `value`: The `ResolveEventHandler` delegate to remove from the event.
///
/// # Returns
///
/// None. This hook is a no-op (event unsubscription is ignored during emulation).
fn appdomain_remove_assembly_resolve_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.AppDomain.GetAssemblies` method.
///
/// # Handled Overloads
///
/// - `AppDomain.GetAssemblies() -> Assembly[]`
///
/// # Parameters
///
/// None (instance method, `this` is the AppDomain).
///
/// # Returns
///
/// An empty `Assembly[]` array.
fn appdomain_get_assemblies_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.Load` method.
///
/// This is one of the most important hooks for deobfuscation. When obfuscated code
/// dynamically loads an assembly from a byte array, this hook captures the raw bytes
/// for later extraction and analysis.
///
/// # Handled Overloads
///
/// - `Assembly.Load(Byte[]) -> Assembly`
/// - `Assembly.Load(Byte[], Byte[]) -> Assembly` (with symbols)
/// - `Assembly.Load(String) -> Assembly` (by name, not captured)
/// - `Assembly.Load(AssemblyName) -> Assembly` (by AssemblyName, not captured)
///
/// # Parameters
///
/// - `rawAssembly`: The byte array containing the raw assembly data (PE file).
/// - `rawSymbolStore`: Optional byte array containing debugging symbols.
/// - `assemblyString`: Assembly display name (for string overload).
/// - `assemblyRef`: AssemblyName object (for AssemblyName overload).
///
/// # Returns
///
/// A symbolic `Assembly` object reference. The raw bytes are captured for analysis.
fn assembly_load_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Assembly.Load(byte[]) - first arg is the byte array
    if let Some(EmValue::ObjectRef(array_ref)) = ctx.args.first() {
        if let Some(bytes) = thread.heap().get_byte_array(*array_ref) {
            // Capture the assembly bytes
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread
                .capture()
                .capture_assembly(bytes, source, AssemblyLoadMethod::LoadBytes, None);
        }
    }

    // Return a fake Assembly object
    match thread.heap_mut().alloc_object(Token::new(0x0100_0010)) {
        Ok(assembly_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.LoadFrom` method.
///
/// # Handled Overloads
///
/// - `Assembly.LoadFrom(String) -> Assembly`
/// - `Assembly.LoadFrom(String, Evidence) -> Assembly`
/// - `Assembly.LoadFrom(String, Byte[], AssemblyHashAlgorithm) -> Assembly`
///
/// # Parameters
///
/// - `assemblyFile`: The file path to the assembly to load.
/// - `securityEvidence`: Optional security evidence for the assembly.
/// - `hashValue`: Optional hash value for verification.
/// - `hashAlgorithm`: Hash algorithm used for the hash value.
///
/// # Returns
///
/// A symbolic `Assembly` object reference. The file is not actually loaded.
fn assembly_load_from_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0010)) {
        Ok(assembly_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.GetExecutingAssembly` method.
///
/// # Handled Overloads
///
/// - `Assembly.GetExecutingAssembly() -> Assembly`
///
/// # Parameters
///
/// None (static method).
///
/// # Returns
///
/// The cached `Assembly` object reference for consistent equality checks.
///
/// # Note
///
/// This returns the same reference as `GetCallingAssembly()` to ensure that
/// anti-tamper checks like `GetExecutingAssembly().Equals(GetCallingAssembly())`
/// pass during emulation.
fn assembly_get_executing_assembly_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Return cached fake assembly for consistent equality checks
    if let Some(assembly_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref)));
    }

    // Fallback: allocate new object if cache not initialized
    match thread.heap_mut().alloc_object(Token::new(0x0100_0010)) {
        Ok(assembly_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.GetCallingAssembly` method.
///
/// # Handled Overloads
///
/// - `Assembly.GetCallingAssembly() -> Assembly`
///
/// # Parameters
///
/// None (static method).
///
/// # Returns
///
/// The cached `Assembly` object reference for consistent equality checks.
///
/// # Note
///
/// This returns the same reference as `GetExecutingAssembly()` to ensure that
/// anti-tamper checks like `GetExecutingAssembly().Equals(GetCallingAssembly())`
/// pass during emulation.
fn assembly_get_calling_assembly_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Return cached fake assembly for consistent equality checks
    if let Some(assembly_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref)));
    }

    // Fallback: allocate new object if cache not initialized
    match thread.heap_mut().alloc_object(Token::new(0x0100_0010)) {
        Ok(assembly_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.GetEntryAssembly` method.
///
/// # Handled Overloads
///
/// - `Assembly.GetEntryAssembly() -> Assembly`
///
/// # Parameters
///
/// None (static method).
///
/// # Returns
///
/// The cached `Assembly` object reference for consistent equality checks.
///
/// # Note
///
/// This returns the same reference as `GetExecutingAssembly()` and `GetCallingAssembly()`
/// to ensure that any equality checks between these methods pass during emulation.
fn assembly_get_entry_assembly_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Return cached fake assembly for consistent equality checks
    if let Some(assembly_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref)));
    }

    // Fallback: allocate new object if cache not initialized
    match thread.heap_mut().alloc_object(Token::new(0x0100_0010)) {
        Ok(assembly_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(assembly_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.GetManifestResourceStream` method.
///
/// # Handled Overloads
///
/// - `Assembly.GetManifestResourceStream(String) -> Stream`
/// - `Assembly.GetManifestResourceStream(Type, String) -> Stream`
///
/// # Parameters
///
/// - `name`: The case-sensitive name of the manifest resource.
/// - `type`: The type whose namespace is used to scope the resource name.
///
/// # Returns
///
/// A `Stream` object containing the resource data, or `null` if not found.
fn assembly_get_manifest_resource_stream_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the resource name from the first argument
    let resource_name = match ctx.args.first() {
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .ok()
            .map(|arc| arc.to_string()),
        _ => None,
    };

    let Some(resource_name) = resource_name else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Get the assembly from the thread
    let Some(assembly) = thread.assembly() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Look up the resource
    let resources = assembly.resources();
    let resource = resources.get(&resource_name);

    let Some(resource) = resource else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Get the resource data
    let Some(data) = resources.get_data(&resource) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Allocate a stream with the resource data
    match thread.heap_mut().alloc_stream(data.to_vec()) {
        Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Reflection.Assembly.GetManifestResourceNames` method.
///
/// # Handled Overloads
///
/// - `Assembly.GetManifestResourceNames() -> String[]`
///
/// # Parameters
///
/// None (instance method, `this` is the Assembly).
///
/// # Returns
///
/// An empty `String[]` array (resource enumeration not implemented).
fn assembly_get_manifest_resource_names_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_array(CilFlavor::String, 0) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for delegate constructor methods.
///
/// # Handled Overloads
///
/// - `Delegate..ctor(Object, IntPtr) -> void`
/// - `MulticastDelegate..ctor(Object, IntPtr) -> void`
/// - `ResolveEventHandler..ctor(Object, IntPtr) -> void`
///
/// # Parameters
///
/// - `target`: The object on which the delegate invokes the instance method.
/// - `method`: A pointer to the method to be invoked.
///
/// # Returns
///
/// A symbolic delegate object reference.
fn delegate_ctor_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(Token::new(0x0100_0012)) {
        Ok(delegate_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(delegate_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
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
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 14);
    }

    #[test]
    fn test_get_current_domain() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "AppDomain",
            "get_CurrentDomain",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = appdomain_get_current_domain_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef"),
        }
    }

    #[test]
    fn test_assembly_load_captures_bytes() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Reflection",
            "Assembly",
            "Load",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();

        // Allocate a byte array on the heap
        let test_data = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header start
        let array_ref = thread.heap_mut().alloc_byte_array(&test_data).unwrap();

        let args = [EmValue::ObjectRef(array_ref)];
        let ctx = ctx.with_args(&args);

        let result = assembly_load_pre(&ctx, &mut thread);

        // Should return an Assembly object
        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef"),
        }

        // Check that assembly was captured
        let captured = thread.capture().assemblies();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].data, test_data);
    }
}
