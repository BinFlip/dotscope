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
    pub fn new(columns: Vec<(&str, Align)>) -> Self {
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
                let pad_left = if i == 0 { 0 } else { 1 };
                let pad_right = if i == last { 0 } else { 1 };
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
