use std::sync::Arc;

use anyhow::bail;
use dotscope::{
    metadata::{method::Method, token::Token, typesystem::CilType},
    CilObject,
};

use crate::commands::common::name_contains_ignore_case;

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
        if let Some(method) = assembly.method(&token) {
            return Ok(vec![method]);
        }
        bail!("no method with token {filter} found");
    }

    // Name matching: "Type::Method" or just "Method"
    let (type_part, method_part) = if let Some(pos) = filter.rfind("::") {
        (Some(&filter[..pos]), &filter[pos + 2..])
    } else {
        (None, filter)
    };

    let mut results = Vec::new();
    for entry in assembly.methods() {
        let method = entry.value();

        if !name_contains_ignore_case(&method.name, method_part) {
            continue;
        }

        if let Some(type_filter) = type_part {
            let declaring_name = method
                .declaring_type_rc()
                .map(|t| t.fullname())
                .unwrap_or_default();
            if !name_contains_ignore_case(&declaring_name, type_filter) {
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

    let results = assembly
        .query_types()
        .defined()
        .filter(move |t| name_contains_ignore_case(&t.fullname(), filter))
        .find_all();

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
