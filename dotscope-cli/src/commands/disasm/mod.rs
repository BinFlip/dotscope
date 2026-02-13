mod formatter;

use std::{
    io::{self, BufWriter, Write},
    path::Path,
};

use anyhow::{bail, Context};
use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
use log::info;

pub use crate::commands::disasm::formatter::DisasmOptions;
use crate::commands::{
    common::load_assembly,
    disasm::formatter::CilFormatter,
    resolution::{resolve_methods, resolve_types},
};

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
        let mut engine = DeobfuscationEngine::new(config);
        let (deobfuscated, result) = engine
            .process_assembly(assembly)
            .with_context(|| "deobfuscation failed")?;
        info!("{}", result.detailed_summary());
        deobfuscated
    } else {
        assembly
    };

    let fmt = CilFormatter::new(opts);

    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());

    let entry_point_token = assembly.cor20header().entry_point_token;

    if !fmt.opts.no_header && !fmt.opts.raw {
        CilFormatter::format_header(&mut w, &assembly)?;
    }

    if let Some(method_filter) = method_filter {
        let methods = resolve_methods(&assembly, method_filter)?;
        if methods.is_empty() {
            bail!("no methods matching '{method_filter}' found");
        }
        for method in &methods {
            fmt.format_method(&mut w, method, entry_point_token, &assembly)?;
        }
    } else if let Some(type_filter) = type_filter {
        let types = resolve_types(&assembly, type_filter)?;
        if types.is_empty() {
            bail!("no types matching '{type_filter}' found");
        }
        for cil_type in &types {
            if !fmt.opts.raw {
                CilFormatter::format_type_begin(&mut w, cil_type)?;
            }
            for method in &cil_type.query_methods() {
                fmt.format_method(&mut w, &method, entry_point_token, &assembly)?;
            }
            if !fmt.opts.raw {
                CilFormatter::format_type_end(&mut w)?;
            }
        }
    } else {
        // --all: iterate all types, disassemble everything
        let all_types = assembly
            .query_types()
            .defined()
            .filter(|t| t.name != "<Module>" || !t.methods.is_empty())
            .find_all();
        for cil_type in &all_types {
            if !fmt.opts.raw {
                CilFormatter::format_type_begin(&mut w, cil_type)?;
            }
            for method in &cil_type.query_methods() {
                fmt.format_method(&mut w, &method, entry_point_token, &assembly)?;
            }
            if !fmt.opts.raw {
                CilFormatter::format_type_end(&mut w)?;
            }
        }
    }

    w.flush()?;
    Ok(())
}
