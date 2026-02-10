use std::path::Path;

use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::load_assembly,
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct TypeEntry {
    token: String,
    visibility: String,
    kind: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct TypesOutput {
    types: Vec<TypeEntry>,
    count: usize,
}

pub fn run(
    path: &Path,
    namespace: Option<&str>,
    public_only: bool,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let registry = assembly.types();

    let mut entries = Vec::new();

    for entry in registry.iter() {
        let cil_type = entry.value();

        if cil_type.is_typeref() {
            continue;
        }

        if public_only && !cil_type.is_public() {
            continue;
        }

        if let Some(ns) = namespace {
            if cil_type.namespace != ns {
                continue;
            }
        }

        let vis = if cil_type.is_public() {
            "public"
        } else {
            "internal"
        };

        entries.push(TypeEntry {
            token: cil_type.token.to_string(),
            visibility: vis.to_string(),
            kind: cil_type.flavor().to_string(),
            name: cil_type.fullname(),
        });
    }

    let count = entries.len();
    let output = TypesOutput {
        types: entries,
        count,
    };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(vec![
            ("Token", Align::Left),
            ("Vis", Align::Left),
            ("Kind", Align::Left),
            ("Name", Align::Left),
        ]);
        for e in &out.types {
            tw.row(vec![
                e.token.clone(),
                e.visibility.clone(),
                e.kind.clone(),
                e.name.clone(),
            ]);
        }
        tw.print();
        println!("\n{} type(s) listed.", out.count);
    })
}
