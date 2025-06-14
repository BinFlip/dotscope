use std::sync::OnceLock;

use crate::metadata::{
    customattributes::CustomAttributeValueList, method::MethodRef, token::Token,
    typesystem::CilTypeRef,
};

/// Represents an Event that a Type can have. Similar to `EventRaw` but with resolved indexes and owned data.
pub struct Event {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `EventAttributes`, §II.23.1.4
    pub flags: u32,
    /// The name of the event
    pub name: String,
    /// an index into a `TypeDef`, a `TypeRef`, or `TypeSpec` table; more precisely, a `TypeDefOrRef` (§II.24.2.6) coded index
    pub event_type: CilTypeRef,
    /// The `Method` that triggers '`OnAdd`'
    pub fn_on_add: OnceLock<MethodRef>,
    /// The `Method` that triggers '`OnRemove`'
    pub fn_on_remove: OnceLock<MethodRef>,
    /// The `Method` that triggers '`OnRaise`'
    pub fn_on_raise: OnceLock<MethodRef>,
    /// The `Method` that triggers '`OnOther`'
    pub fn_on_other: OnceLock<MethodRef>,
    /// Custom attributes attached to this event
    pub custom_attributes: CustomAttributeValueList,
}
