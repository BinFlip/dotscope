use std::sync::Arc;

use anyhow::bail;
use dotscope::{
    metadata::{method::Method, token::Token, typesystem::CilType},
    CilObject,
};

/// Parse a filter string as either a hex token or a name pattern.
pub fn parse_token_filter(filter: &str) -> Option<Token> {
    let hex = filter
        .strip_prefix("0x")
        .or_else(|| filter.strip_prefix("0X"))?;
    u32::from_str_radix(hex, 16).ok().map(Token::new)
}

/// Find methods matching a filter (by token or name).
pub fn resolve_methods(assembly: &CilObject, filter: &str) -> anyhow::Result<Vec<Arc<Method>>> {
    // Try token first
    if let Some(token) = parse_token_filter(filter) {
        if let Some(entry) = assembly.methods().get(&token) {
            return Ok(vec![entry.value().clone()]);
        }
        bail!("no method with token {filter} found");
    }

    // Name matching: "Type::Method" or just "Method"
    let (type_part, method_part) = if let Some(pos) = filter.rfind("::") {
        (Some(&filter[..pos]), &filter[pos + 2..])
    } else {
        (None, filter)
    };

    let filter_lower = method_part.to_lowercase();
    let type_filter_lower = type_part.map(|t| t.to_lowercase());

    let mut results = Vec::new();
    for entry in assembly.methods().iter() {
        let method = entry.value();

        if !method.name.to_lowercase().contains(&filter_lower) {
            continue;
        }

        if let Some(ref type_filter) = type_filter_lower {
            let declaring_name = method
                .declaring_type
                .get()
                .and_then(|r| r.upgrade())
                .map(|t| t.fullname().to_lowercase())
                .unwrap_or_default();
            if !declaring_name.contains(type_filter) {
                continue;
            }
        }

        results.push(method.clone());
    }

    Ok(results)
}

/// Find types matching a filter (by token or name).
pub fn resolve_types(assembly: &CilObject, filter: &str) -> anyhow::Result<Vec<Arc<CilType>>> {
    // Try token first
    if let Some(token) = parse_token_filter(filter) {
        if let Some(cil_type) = assembly.types().get(&token) {
            return Ok(vec![cil_type]);
        }
        bail!("no type with token {filter} found");
    }

    let filter_lower = filter.to_lowercase();
    let mut results = Vec::new();
    for entry in assembly.types().iter() {
        let cil_type = entry.value();
        if cil_type.is_typeref() {
            continue;
        }
        if cil_type.fullname().to_lowercase().contains(&filter_lower) {
            results.push(cil_type.clone());
        }
    }

    Ok(results)
}

/// Resolve a single method from a filter, bailing if zero or multiple matches.
pub fn resolve_single_method(assembly: &CilObject, filter: &str) -> anyhow::Result<Arc<Method>> {
    let methods = resolve_methods(assembly, filter)?;
    match methods.len() {
        0 => bail!("no methods matching '{filter}' found"),
        1 => Ok(methods.into_iter().next().unwrap()),
        n => bail!(
            "{n} methods match '{filter}'; narrow the filter (e.g. Type::Method or use a token like 0x06000001)"
        ),
    }
}
