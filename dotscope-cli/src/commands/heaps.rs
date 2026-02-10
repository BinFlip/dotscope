use std::path::Path;

use anyhow::{bail, Context};
use dotscope::CilObject;
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::load_assembly,
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct HeapSummary {
    name: String,
    entries: usize,
}

#[derive(Debug, Serialize)]
struct HeapsSummaryOutput {
    heaps: Vec<HeapSummary>,
}

#[derive(Debug, Serialize)]
struct StringEntry {
    offset: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct StringsOutput {
    entries: Vec<StringEntry>,
}

#[derive(Debug, Serialize)]
struct UserStringEntry {
    offset: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct UserStringsOutput {
    entries: Vec<UserStringEntry>,
}

#[derive(Debug, Serialize)]
struct GuidEntry {
    index: usize,
    guid: String,
}

#[derive(Debug, Serialize)]
struct GuidsOutput {
    entries: Vec<GuidEntry>,
}

#[derive(Debug, Serialize)]
struct BlobEntry {
    offset: String,
    size: usize,
    preview: String,
}

#[derive(Debug, Serialize)]
struct BlobOutput {
    entries: Vec<BlobEntry>,
}

#[derive(Debug, Serialize)]
struct BlobDetail {
    offset: String,
    size: usize,
    data: String,
}

#[derive(Debug, Serialize)]
struct StringDetail {
    offset: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct GuidDetail {
    index: String,
    guid: String,
}

pub fn run(
    path: &Path,
    heap_filter: Option<&str>,
    offset: Option<&str>,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    if offset.is_some() && heap_filter.is_none() {
        bail!("--offset requires --heap to specify which heap to look up");
    }

    let assembly = load_assembly(path)?;

    match heap_filter {
        None => print_summary(&assembly, opts),
        Some(h) => {
            let h_lower = h.to_lowercase();
            match (h_lower.as_str(), offset) {
                ("strings", Some(off)) => lookup_string(&assembly, off, opts),
                ("strings", None) => dump_strings(&assembly, opts),
                ("userstrings" | "us", Some(off)) => lookup_userstring(&assembly, off, opts),
                ("userstrings" | "us", None) => dump_userstrings(&assembly, opts),
                ("guid" | "guids", Some(off)) => lookup_guid(&assembly, off, opts),
                ("guid" | "guids", None) => dump_guids(&assembly, opts),
                ("blob", Some(off)) => lookup_blob(&assembly, off, opts),
                ("blob", None) => dump_blob(&assembly, opts),
                (other, _) => {
                    bail!("unknown heap '{other}' (expected: strings, userstrings, guid, blob)")
                }
            }
        }
    }
}

/// Parse an offset string supporting hex (0x...) and decimal.
fn parse_offset(s: &str) -> anyhow::Result<usize> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).with_context(|| format!("invalid hex offset: {s}"))
    } else {
        trimmed
            .parse::<usize>()
            .with_context(|| format!("invalid offset: {s}"))
    }
}

fn lookup_string(
    assembly: &CilObject,
    offset_str: &str,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    let offset = parse_offset(offset_str)?;
    let strings = assembly
        .strings()
        .with_context(|| "assembly has no #Strings heap")?;
    let value = strings
        .get(offset)
        .with_context(|| format!("no string at offset 0x{offset:x}"))?;

    let output = StringDetail {
        offset: format!("0x{offset:06x}"),
        value: value.to_string(),
    };

    print_output(&output, opts, |out| {
        println!("Offset: {}", out.offset);
        println!("Value:  {}", out.value);
    })
}

fn lookup_userstring(
    assembly: &CilObject,
    offset_str: &str,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    let offset = parse_offset(offset_str)?;
    let us = assembly
        .userstrings()
        .with_context(|| "assembly has no #US heap")?;
    let value = us
        .get(offset)
        .with_context(|| format!("no user string at offset 0x{offset:x}"))?;

    let output = StringDetail {
        offset: format!("0x{offset:06x}"),
        value: value.to_string_lossy(),
    };

    print_output(&output, opts, |out| {
        println!("Offset: {}", out.offset);
        println!("Value:  {}", out.value);
    })
}

fn lookup_guid(assembly: &CilObject, offset_str: &str, opts: &GlobalOptions) -> anyhow::Result<()> {
    let index = parse_offset(offset_str)?;
    let guids = assembly
        .guids()
        .with_context(|| "assembly has no #GUID heap")?;
    let guid = guids
        .get(index)
        .with_context(|| format!("no GUID at index {index}"))?;

    let output = GuidDetail {
        index: index.to_string(),
        guid: guid.to_string(),
    };

    print_output(&output, opts, |out| {
        println!("Index: {}", out.index);
        println!("GUID:  {}", out.guid);
    })
}

fn lookup_blob(assembly: &CilObject, offset_str: &str, opts: &GlobalOptions) -> anyhow::Result<()> {
    let offset = parse_offset(offset_str)?;
    let blob = assembly
        .blob()
        .with_context(|| "assembly has no #Blob heap")?;
    let data = blob
        .get(offset)
        .with_context(|| format!("no blob at offset 0x{offset:x}"))?;

    let hex_full: String = data
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");

    let output = BlobDetail {
        offset: format!("0x{offset:06x}"),
        size: data.len(),
        data: hex_full,
    };

    print_output(&output, opts, |out| {
        println!("Offset: {}", out.offset);
        println!("Size:   {} bytes", out.size);
        if out.size == 0 {
            println!("(empty)");
            return;
        }
        println!();
        // 16-byte hex dump rows
        for (i, chunk) in data.chunks(16).enumerate() {
            let row_offset = i * 16;
            let hex: String = chunk
                .iter()
                .enumerate()
                .map(|(j, b)| {
                    if j == 8 {
                        format!(" {b:02x}")
                    } else {
                        format!("{b:02x}")
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..=0x7e).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            // Pad hex to fixed width (16 bytes = 48 chars + 1 gap char)
            println!("{row_offset:04x}: {hex:<49} |{ascii}|");
        }
    })
}

fn print_summary(assembly: &CilObject, opts: &GlobalOptions) -> anyhow::Result<()> {
    let strings_count = assembly.strings().map(|s| s.iter().count()).unwrap_or(0);
    let us_count = assembly
        .userstrings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let guid_count = assembly.guids().map(|g| g.iter().count()).unwrap_or(0);
    let blob_count = assembly.blob().map(|b| b.iter().count()).unwrap_or(0);

    let output = HeapsSummaryOutput {
        heaps: vec![
            HeapSummary {
                name: "#Strings".to_string(),
                entries: strings_count,
            },
            HeapSummary {
                name: "#US".to_string(),
                entries: us_count,
            },
            HeapSummary {
                name: "#GUID".to_string(),
                entries: guid_count,
            },
            HeapSummary {
                name: "#Blob".to_string(),
                entries: blob_count,
            },
        ],
    };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(vec![("Heap", Align::Left), ("Entries", Align::Right)]);
        for h in &out.heaps {
            tw.row(vec![h.name.clone(), h.entries.to_string()]);
        }
        tw.print();
    })
}

fn dump_strings(assembly: &CilObject, opts: &GlobalOptions) -> anyhow::Result<()> {
    let strings = assembly
        .strings()
        .with_context(|| "assembly has no #Strings heap")?;

    let entries: Vec<StringEntry> = strings
        .iter()
        .map(|(offset, value)| StringEntry {
            offset: format!("0x{offset:06x}"),
            value: value.to_string(),
        })
        .collect();

    let output = StringsOutput { entries };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(vec![("Offset", Align::Left), ("Value", Align::Left)]);
        for e in &out.entries {
            tw.row(vec![e.offset.clone(), e.value.clone()]);
        }
        tw.print();
    })
}

fn dump_userstrings(assembly: &CilObject, opts: &GlobalOptions) -> anyhow::Result<()> {
    let userstrings = assembly
        .userstrings()
        .with_context(|| "assembly has no #US heap")?;

    let entries: Vec<UserStringEntry> = userstrings
        .iter()
        .map(|(offset, value)| UserStringEntry {
            offset: format!("0x{offset:06x}"),
            value: value.to_string_lossy(),
        })
        .collect();

    let output = UserStringsOutput { entries };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(vec![("Offset", Align::Left), ("Value", Align::Left)]);
        for e in &out.entries {
            tw.row(vec![e.offset.clone(), e.value.clone()]);
        }
        tw.print();
    })
}

fn dump_guids(assembly: &CilObject, opts: &GlobalOptions) -> anyhow::Result<()> {
    let guids = assembly
        .guids()
        .with_context(|| "assembly has no #GUID heap")?;

    let entries: Vec<GuidEntry> = guids
        .iter()
        .map(|(index, guid)| GuidEntry {
            index,
            guid: guid.to_string(),
        })
        .collect();

    let output = GuidsOutput { entries };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(vec![("Index", Align::Left), ("GUID", Align::Left)]);
        for e in &out.entries {
            tw.row(vec![e.index.to_string(), e.guid.clone()]);
        }
        tw.print();
    })
}

fn dump_blob(assembly: &CilObject, opts: &GlobalOptions) -> anyhow::Result<()> {
    let blob = assembly
        .blob()
        .with_context(|| "assembly has no #Blob heap")?;

    let entries: Vec<BlobEntry> = blob
        .iter()
        .map(|(offset, data)| {
            let preview_len = data.len().min(32);
            let hex: String = data[..preview_len]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let suffix = if data.len() > 32 { "..." } else { "" };
            BlobEntry {
                offset: format!("0x{offset:06x}"),
                size: data.len(),
                preview: format!("{hex}{suffix}"),
            }
        })
        .collect();

    let output = BlobOutput { entries };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(vec![
            ("Offset", Align::Left),
            ("Size", Align::Right),
            ("Preview", Align::Left),
        ]);
        for e in &out.entries {
            tw.row(vec![
                e.offset.clone(),
                e.size.to_string(),
                e.preview.clone(),
            ]);
        }
        tw.print();
    })
}
