//! `System.Diagnostics.Process` method hooks.
//!
//! Provides stub implementations for the `Process.GetCurrentProcess()` →
//! `Process.MainModule` → `ProcessModule.FileName` chain commonly used by
//! obfuscated code to discover the executable path at runtime.

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        tokens, EmValue,
    },
    metadata::tables::ModuleRaw,
    Result,
};

/// Registers all `System.Diagnostics.Process` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Diagnostics.Process.GetCurrentProcess")
            .match_name("System.Diagnostics", "Process", "GetCurrentProcess")
            .pre(process_get_current_process_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.Process.get_MainModule")
            .match_name("System.Diagnostics", "Process", "get_MainModule")
            .pre(process_get_main_module_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.ProcessModule.get_FileName")
            .match_name("System.Diagnostics", "ProcessModule", "get_FileName")
            .pre(process_module_get_file_name_pre),
    )?;

    Ok(())
}

/// Hook for `Process.GetCurrentProcess()` (static).
///
/// Allocates a fake `Process` object with a linked `ProcessModule` and filename
/// string derived from the assembly's module name.
fn process_get_current_process_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Build the fake executable path
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

    // Allocate filename string
    let filename_ref = try_hook!(thread.heap_mut().alloc_string(&path));

    // Allocate ProcessModule and set FileName field
    let pm_ref = try_hook!(thread
        .heap_mut()
        .alloc_object(tokens::system::PROCESS_MODULE));
    try_hook!(thread.heap_mut().set_field(
        pm_ref,
        tokens::process_fields::FILE_NAME,
        EmValue::ObjectRef(filename_ref),
    ));

    // Allocate Process and set MainModule field
    let proc_ref = try_hook!(thread.heap_mut().alloc_object(tokens::system::PROCESS));
    try_hook!(thread.heap_mut().set_field(
        proc_ref,
        tokens::process_fields::MAIN_MODULE,
        EmValue::ObjectRef(pm_ref),
    ));

    PreHookResult::Bypass(Some(EmValue::ObjectRef(proc_ref)))
}

/// Hook for `Process.get_MainModule` (instance).
///
/// Reads the `MAIN_MODULE` field from the Process object.
fn process_get_main_module_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(proc_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*proc_ref, tokens::process_fields::MAIN_MODULE)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `ProcessModule.get_FileName` (instance).
///
/// Reads the `FILE_NAME` field from the ProcessModule object.
fn process_module_get_file_name_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(pm_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*pm_ref, tokens::process_fields::FILE_NAME)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 3);
    }

    #[test]
    fn test_process_chain() {
        let mut thread = create_test_thread();

        let args: [EmValue; 0] = [];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Diagnostics",
            "Process",
            "GetCurrentProcess",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = process_get_current_process_pre(&ctx, &mut thread);
        let proc_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            other => panic!("Expected Bypass with ObjectRef, got {other:?}"),
        };

        // get_MainModule
        let this = EmValue::ObjectRef(proc_ref);
        let ctx2 = HookContext::new(
            Token::new(0x0A000002),
            "System.Diagnostics",
            "Process",
            "get_MainModule",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result2 = process_get_main_module_pre(&ctx2, &mut thread);
        let pm_ref = match result2 {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            other => panic!("Expected Bypass with ObjectRef, got {other:?}"),
        };

        // get_FileName
        let this2 = EmValue::ObjectRef(pm_ref);
        let ctx3 = HookContext::new(
            Token::new(0x0A000003),
            "System.Diagnostics",
            "ProcessModule",
            "get_FileName",
            PointerSize::Bit64,
        )
        .with_this(Some(&this2));

        let result3 = process_module_get_file_name_pre(&ctx3, &mut thread);
        match result3 {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => {
                let s = thread.heap().get_string(r).unwrap();
                assert!(
                    s.contains("module.exe"),
                    "Expected path with module.exe, got: {s}"
                );
            }
            other => panic!("Expected Bypass with ObjectRef, got {other:?}"),
        }
    }
}
