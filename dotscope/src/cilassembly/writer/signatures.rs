//! Renumbering the type tokens inside signature blobs.
//!
//! A signature names types by token (`TypeDefOrRefOrSpecEncoded`, ECMA-335 II.23.2.8), so when
//! a write deletes TypeDef, TypeRef or TypeSpec rows and the rows after them shift, the tokens
//! in signatures must follow, and a token naming a deleted row is a dangling reference like any
//! other.
//!
//! What a blob holds is known only from the column that references it: the heap itself is
//! untyped, and a custom attribute value or a constant can read as a signature. So only the
//! blobs a signature column references are renumbered, each parsed as that column's kind
//! ([`signature_blobs`]), through the same [`TokenRemap`] the instruction operands use.
//!
//! A blob that a signature column and a non-signature column both reference would need two
//! renderings; compilers share a blob only between identical contents, and a signature with
//! type tokens is not byte-identical to an attribute value or a constant in practice, so this
//! case is not handled.

use std::collections::HashMap;

use crate::{
    cilassembly::{
        modifications::TableModifications, operation::Operation, writer::remapper::TokenRemap,
        CilAssembly,
    },
    metadata::{
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_method_spec_signature, encode_property_signature, encode_typespec_signature,
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
            SIGNATURE_HEADER,
        },
        tables::{
            skip_unreadable, FieldRaw, MemberRefRaw, MethodDefRaw, MethodSpecRaw, PropertyRaw,
            StandAloneSigRaw, TableDataOwned, TableId, TypeSpecRaw,
        },
        token::Token,
    },
    Referrer, Result,
};

/// The kind of signature a blob holds, by the column that references it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// `MethodDef.Signature`: a method signature.
    Method,
    /// `Field.Signature`: a field signature.
    Field,
    /// `MemberRef.Signature`: a field signature (`FIELD` header) or a method signature.
    MemberRef,
    /// `StandAloneSig.Signature`: a local variable list (`LOCAL_SIG` header) or, for a `calli`,
    /// a method signature.
    StandAlone,
    /// `Property.Type`: a property signature.
    Property,
    /// `TypeSpec.Signature`: a type specification.
    TypeSpec,
    /// `MethodSpec.Instantiation`: the type arguments of a generic method instantiation.
    MethodSpec,
}

/// A signature blob: its kind, and a column that references it, for the error naming a
/// dangling token in it.
#[derive(Debug, Clone, Copy)]
pub struct SignatureBlob {
    /// What the blob holds.
    pub kind: SignatureKind,
    /// A column referencing the blob.
    pub referrer: Referrer,
}

/// The blobs the signature columns of `assembly` reference, keyed as the blob heap writer
/// meets them: by heap offset for the input's blobs, by placeholder for appended ones.
///
/// Covers the input's surviving rows and every surviving row the pending changes insert or
/// update.
#[must_use]
pub fn signature_blobs(assembly: &CilAssembly) -> HashMap<u32, SignatureBlob> {
    let mut blobs = HashMap::new();
    let mut record = |index: u32, kind: SignatureKind, row: Token, column: &'static str| {
        if index != 0 {
            blobs.insert(
                index,
                SignatureBlob {
                    kind,
                    referrer: Referrer::Column { row, column },
                },
            );
        }
    };

    let view = assembly.view();
    if let Some(tables) = view.tables() {
        let live = |table: TableId, rid: u32| !assembly.changes().is_row_deleted(table, rid);
        if let Some(table) = tables.table::<MethodDefRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::MethodDef, row.rid) {
                    record(row.signature, SignatureKind::Method, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<FieldRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::Field, row.rid) {
                    record(row.signature, SignatureKind::Field, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<MemberRefRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::MemberRef, row.rid) {
                    record(
                        row.signature,
                        SignatureKind::MemberRef,
                        row.token,
                        "Signature",
                    );
                }
            }
        }
        if let Some(table) = tables.table::<StandAloneSigRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::StandAloneSig, row.rid) {
                    record(
                        row.signature,
                        SignatureKind::StandAlone,
                        row.token,
                        "Signature",
                    );
                }
            }
        }
        if let Some(table) = tables.table::<PropertyRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::Property, row.rid) {
                    record(row.signature, SignatureKind::Property, row.token, "Type");
                }
            }
        }
        if let Some(table) = tables.table::<TypeSpecRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::TypeSpec, row.rid) {
                    record(
                        row.signature,
                        SignatureKind::TypeSpec,
                        row.token,
                        "Signature",
                    );
                }
            }
        }
        if let Some(table) = tables.table::<MethodSpecRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::MethodSpec, row.rid) {
                    record(
                        row.instantiation,
                        SignatureKind::MethodSpec,
                        row.token,
                        "Instantiation",
                    );
                }
            }
        }
    }

    for table_id in [
        TableId::MethodDef,
        TableId::Field,
        TableId::MemberRef,
        TableId::StandAloneSig,
        TableId::Property,
        TableId::TypeSpec,
        TableId::MethodSpec,
    ] {
        let rows: Vec<(u32, &TableDataOwned)> =
            match assembly.changes().get_table_modifications(table_id) {
                Some(TableModifications::Sparse { operations, .. }) => operations
                    .iter()
                    .filter_map(|op| match &op.operation {
                        // A row a later operation deletes references nothing.
                        Operation::Insert(rid, data) | Operation::Update(rid, data)
                            if !assembly.changes().is_row_deleted(table_id, *rid) =>
                        {
                            Some((*rid, data))
                        }
                        _ => None,
                    })
                    .collect(),
                Some(TableModifications::Replaced(rows)) => (1u32..).zip(rows).collect(),
                None => Vec::new(),
            };
        for (rid, data) in rows {
            let row = Token::from_parts(table_id, rid);
            match data {
                TableDataOwned::MethodDef(r) => {
                    record(r.signature, SignatureKind::Method, row, "Signature");
                }
                TableDataOwned::Field(r) => {
                    record(r.signature, SignatureKind::Field, row, "Signature");
                }
                TableDataOwned::MemberRef(r) => {
                    record(r.signature, SignatureKind::MemberRef, row, "Signature");
                }
                TableDataOwned::StandAloneSig(r) => {
                    record(r.signature, SignatureKind::StandAlone, row, "Signature");
                }
                TableDataOwned::Property(r) => {
                    record(r.signature, SignatureKind::Property, row, "Type");
                }
                TableDataOwned::TypeSpec(r) => {
                    record(r.signature, SignatureKind::TypeSpec, row, "Signature");
                }
                TableDataOwned::MethodSpec(r) => {
                    record(
                        r.instantiation,
                        SignatureKind::MethodSpec,
                        row,
                        "Instantiation",
                    );
                }
                _ => {}
            }
        }
    }

    blobs
}

/// What the blob heap writer needs to renumber signatures: which blobs are signatures, and
/// how the write renumbers tokens.
pub struct SignatureRemap<'a> {
    /// The signature blobs, from [`signature_blobs`].
    pub blobs: &'a HashMap<u32, SignatureBlob>,
    /// How the write renumbers tokens.
    pub tokens: &'a TokenRemap,
}

impl SignatureRemap<'_> {
    /// The blob at `index` with its type tokens renumbered, or `None` when it is not a
    /// signature or nothing in it changes. A signature that does not parse as its kind is kept
    /// as it is.
    ///
    /// # Errors
    ///
    /// [`crate::Error::DanglingReference`] when the signature names a deleted row, under
    /// [`DanglingPolicy::Error`](crate::cilassembly::writer::DanglingPolicy::Error), and an
    /// encoding error for a signature that cannot be written back.
    pub fn remap(&self, index: u32, blob: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.tokens.is_empty() {
            return Ok(None);
        }
        let Some(signature) = self.blobs.get(&index) else {
            return Ok(None);
        };
        remap_signature_tokens(blob, signature.kind, self.tokens, signature.referrer)
    }
}

/// `signature`, read as `kind`, with every type token renumbered by `tokens`; `None` when it
/// does not parse as `kind` or nothing in it changes.
///
/// # Errors
///
/// [`crate::Error::DanglingReference`] naming `referrer` when a token names a deleted row,
/// under [`DanglingPolicy::Error`](crate::cilassembly::writer::DanglingPolicy::Error), and an
/// encoding error for a signature that cannot be written back.
pub fn remap_signature_tokens(
    signature: &[u8],
    kind: SignatureKind,
    tokens: &TokenRemap,
    referrer: Referrer,
) -> Result<Option<Vec<u8>>> {
    let mut changed = false;
    let mut renumber = |token: &mut Token| -> Result<()> {
        let new = tokens.remap(referrer, token.value())?;
        if new != token.value() {
            *token = Token::new(new);
            changed = true;
        }
        Ok(())
    };
    let header = signature.first().copied();
    // A signature that does not parse as its kind is kept as it is.
    let encoded = match (kind, header) {
        (SignatureKind::Field, _) | (SignatureKind::MemberRef, Some(SIGNATURE_HEADER::FIELD)) => {
            let Ok(mut parsed) = parse_field_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_field_signature(&parsed)
        }
        (SignatureKind::StandAlone, Some(SIGNATURE_HEADER::LOCAL_SIG)) => {
            let Ok(mut parsed) = parse_local_var_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_local_var_signature(&parsed)
        }
        (SignatureKind::Method | SignatureKind::MemberRef | SignatureKind::StandAlone, _) => {
            let Ok(mut parsed) = parse_method_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_method_signature(&parsed)
        }
        (SignatureKind::Property, _) => {
            let Ok(mut parsed) = parse_property_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_property_signature(&parsed)
        }
        (SignatureKind::TypeSpec, _) => {
            let Ok(mut parsed) = parse_type_spec_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_typespec_signature(&parsed)
        }
        (SignatureKind::MethodSpec, _) => {
            let Ok(mut parsed) = parse_method_spec_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_method_spec_signature(&parsed)
        }
    };
    if changed {
        Ok(Some(encoded?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cilassembly::writer::DanglingPolicy, Error};

    const REFERRER: Referrer = Referrer::Column {
        row: Token::new(0x0600_0001),
        column: "Signature",
    };

    /// TypeRef 5 becomes 3, TypeDef 4 becomes 2, TypeSpec 2 becomes 1; TypeRef 9 is deleted.
    fn tokens(dangling: DanglingPolicy) -> TokenRemap {
        TokenRemap::for_tests(
            &[
                (0x0100_0005, 0x0100_0003),
                (0x0200_0004, 0x0200_0002),
                (0x1B00_0002, 0x1B00_0001),
            ],
            &[0x0100_0009],
            dangling,
        )
    }

    fn remapped(signature: &[u8], kind: SignatureKind) -> Option<Vec<u8>> {
        remap_signature_tokens(signature, kind, &tokens(DanglingPolicy::Error), REFERRER).unwrap()
    }

    /// Each kind of signature has its tokens renumbered, read as its column says.
    #[test]
    fn every_kind_of_signature_is_renumbered() {
        // CLASS TypeRef 5 is 0x12 0x15; TypeRef 3 is 0x12 0x0D.
        assert_eq!(
            remapped(&[0x00, 0x00, 0x12, 0x15], SignatureKind::Method),
            Some(vec![0x00, 0x00, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x06, 0x12, 0x15], SignatureKind::Field),
            Some(vec![0x06, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x06, 0x12, 0x15], SignatureKind::MemberRef),
            Some(vec![0x06, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x20, 0x00, 0x12, 0x15], SignatureKind::MemberRef),
            Some(vec![0x20, 0x00, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x07, 0x01, 0x12, 0x15], SignatureKind::StandAlone),
            Some(vec![0x07, 0x01, 0x12, 0x0D])
        );
        // A calli signature: DEFAULT, no parameters, returning CLASS TypeRef 5.
        assert_eq!(
            remapped(&[0x00, 0x00, 0x12, 0x15], SignatureKind::StandAlone),
            Some(vec![0x00, 0x00, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x28, 0x00, 0x12, 0x15], SignatureKind::Property),
            Some(vec![0x28, 0x00, 0x12, 0x0D])
        );
        // GENERICINST CLASS TypeDef 4 <CLASS TypeSpec 2>; TypeDef 4 is 0x10, TypeSpec 2 is 0x0A.
        assert_eq!(
            remapped(
                &[0x15, 0x12, 0x10, 0x01, 0x12, 0x0A],
                SignatureKind::TypeSpec
            ),
            Some(vec![0x15, 0x12, 0x08, 0x01, 0x12, 0x06])
        );
        assert_eq!(
            remapped(&[0x0A, 0x01, 0x12, 0x15], SignatureKind::MethodSpec),
            Some(vec![0x0A, 0x01, 0x12, 0x0D])
        );
    }

    /// The extra arguments of a vararg call site and a TypeSpec's custom modifiers are
    /// signature tokens too.
    #[test]
    fn varargs_and_type_spec_modifiers_are_renumbered() {
        // VARARG, one fixed and one extra parameter: void (I4, SENTINEL, CLASS TypeRef 5)
        assert_eq!(
            remapped(
                &[0x05, 0x02, 0x01, 0x08, 0x41, 0x12, 0x15],
                SignatureKind::MemberRef
            ),
            Some(vec![0x05, 0x02, 0x01, 0x08, 0x41, 0x12, 0x0D])
        );
        // CMOD_OPT TypeRef 5, then I4
        assert_eq!(
            remapped(&[0x20, 0x15, 0x08], SignatureKind::TypeSpec),
            Some(vec![0x20, 0x0D, 0x08])
        );
    }

    /// A signature naming a deleted row is a dangling reference naming its column; under the
    /// null policy the token becomes the null token of its table.
    #[test]
    fn a_deleted_type_in_a_signature_is_a_dangling_reference() {
        // CLASS TypeRef 9 is 0x12 0x25.
        let signature = [0x06, 0x12, 0x25];
        let error = remap_signature_tokens(
            &signature,
            SignatureKind::Field,
            &tokens(DanglingPolicy::Error),
            REFERRER,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::DanglingReference { referrer, target }
                    if referrer == REFERRER && target == Token::new(0x0100_0009)
            ),
            "{error}"
        );
        assert_eq!(
            remap_signature_tokens(
                &signature,
                SignatureKind::Field,
                &tokens(DanglingPolicy::Null),
                REFERRER
            )
            .unwrap(),
            Some(vec![0x06, 0x12, 0x01])
        );
    }

    /// Nothing to renumber, or bytes that are not the kind their column says, leave the blob
    /// as it is.
    #[test]
    fn an_unchanged_or_unreadable_signature_is_kept() {
        assert_eq!(remapped(&[0x06, 0x08], SignatureKind::Field), None);
        assert_eq!(remapped(&[0x06, 0x12, 0x11], SignatureKind::Field), None);
        assert_eq!(remapped(&[0xFF, 0xFF], SignatureKind::Method), None);
    }

    /// Only blobs a signature column references are touched: an attribute value that reads
    /// as a method signature (`01 00 11 4D...`: C calling convention, no parameters, returning
    /// VALUETYPE TypeRef 19) is not one.
    #[test]
    fn a_blob_no_signature_column_references_is_untouched() {
        let tokens =
            TokenRemap::for_tests(&[(0x0100_0013, 0x0100_0010)], &[], DanglingPolicy::Error);
        let mut blobs = HashMap::new();
        blobs.insert(
            0x40,
            SignatureBlob {
                kind: SignatureKind::Field,
                referrer: REFERRER,
            },
        );
        let remap = SignatureRemap {
            blobs: &blobs,
            tokens: &tokens,
        };
        let attribute_value = [0x01, 0x00, 0x11, 0x4D, 0x65, 0x74, 0x61, 0x00, 0x00];
        assert_eq!(remap.remap(0x10, &attribute_value).unwrap(), None);
        assert_eq!(
            remap.remap(0x40, &[0x06, 0x11, 0x4D]).unwrap(),
            Some(vec![0x06, 0x11, 0x41])
        );
    }
}
