use std::{
    io::{self, BufWriter, Write},
    path::Path,
};

use anyhow::{bail, Context};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, EngineConfig},
    formatting::{FormatterOptions, IlFormatter},
};
use log::info;

use crate::commands::{
    common::load_assembly,
    resolution::{resolve_methods, resolve_types},
};

/// Re-export as `DisasmOptions` for CLI backward compatibility.
pub type DisasmOptions = FormatterOptions;

pub fn run(
    path: &Path,
    method_filter: Option<&str>,
    type_filter: Option<&str>,
    opts: DisasmOptions,
    deobfuscate: bool,
) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let assembly = if deobfuscate {
        let config = EngineConfig::default();
        let engine = DeobfuscationEngine::new(config);
        let (deobfuscated, result) = engine
            .process_assembly(assembly)
            .with_context(|| "deobfuscation failed")?;
        info!("{}", result.detailed_summary());
        deobfuscated
    } else {
        assembly
    };

    let fmt = IlFormatter::new(opts);

    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());

    let entry_point_token = assembly.cor20header().entry_point_token;

    if let Some(method_filter) = method_filter {
        let methods = resolve_methods(&assembly, method_filter)?;
        if methods.is_empty() {
            bail!("no methods matching '{method_filter}' found");
        }
        for method in &methods {
            fmt.format_method(&mut w, method, entry_point_token, &assembly, None)?;
        }
    } else if let Some(type_filter) = type_filter {
        let types = resolve_types(&assembly, type_filter)?;
        if types.is_empty() {
            bail!("no types matching '{type_filter}' found");
        }
        for cil_type in &types {
            fmt.format_type(&mut w, cil_type, &assembly, entry_point_token, None)?;
        }
    } else {
        fmt.format_assembly(&mut w, &assembly)?;
    }

    w.flush()?;
    Ok(())
}
