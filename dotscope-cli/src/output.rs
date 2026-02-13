use comfy_table::{presets, CellAlignment, ContentArrangement, Table};
use serde::Serialize;

use crate::app::GlobalOptions;

/// Print `data` as JSON (if `--json`) or call `display_fn` for human-readable output.
pub fn print_output<T: Serialize>(
    data: &T,
    opts: &GlobalOptions,
    display_fn: impl FnOnce(&T),
) -> anyhow::Result<()> {
    if opts.json {
        let json = serde_json::to_string_pretty(data)?;
        println!("{json}");
    } else {
        display_fn(data);
    }
    Ok(())
}

/// Column alignment for tabular output.
#[derive(Clone, Copy)]
pub enum Align {
    Left,
    Right,
}

/// Format binary data as a hex dump with 16-byte rows and an ASCII side panel.
pub fn format_hex_dump(data: &[u8]) -> String {
    let mut lines = Vec::new();
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
        lines.push(format!("{row_offset:04x}: {hex:<49} |{ascii}|"));
    }
    lines.join("\n")
}

/// Tabular writer backed by `comfy-table` for clean, dynamically-aligned CLI output.
///
/// Columns are sized to the widest entry. No borders or separators — just
/// whitespace-aligned columns suitable for terminal output.
pub struct TabWriter {
    table: Table,
    indent: String,
}

impl TabWriter {
    /// Create a new `TabWriter` with the given column definitions.
    ///
    /// Each column is a `(header, alignment)` pair.
    pub fn new(columns: &[(&str, Align)]) -> Self {
        let mut table = Table::new();
        table
            .load_preset(presets::NOTHING)
            .set_content_arrangement(ContentArrangement::Dynamic);

        let headers: Vec<&str> = columns.iter().map(|(name, _)| *name).collect();
        table.set_header(headers);

        // Apply alignment and padding to each column.
        // First column: no left padding. Last column: no right padding.
        // Inner columns: (1, 1) padding for a 2-space gap between columns.
        let last = columns.len().saturating_sub(1);
        for (i, (_, align)) in columns.iter().enumerate() {
            let cell_align = match align {
                Align::Left => CellAlignment::Left,
                Align::Right => CellAlignment::Right,
            };
            if let Some(col) = table.column_mut(i) {
                col.set_cell_alignment(cell_align);
                let pad_left = u16::from(i != 0);
                let pad_right = u16::from(i != last);
                col.set_padding((pad_left, pad_right));
            }
        }

        Self {
            table,
            indent: String::new(),
        }
    }

    /// Set the indent prefix for every line (e.g. `"  "` for 2-space indent).
    pub fn indent(mut self, prefix: &str) -> Self {
        self.indent = prefix.to_string();
        self
    }

    /// Add a row. Values are given in column order.
    pub fn row(&mut self, values: Vec<String>) {
        self.table.add_row(values);
    }

    /// Print the table to stdout.
    pub fn print(&self) {
        let output = self.table.to_string();
        for line in output.lines() {
            let trimmed = line.trim_end();
            if self.indent.is_empty() {
                println!("{trimmed}");
            } else {
                println!("{}{trimmed}", self.indent);
            }
        }
    }
}
