# Symbol Renaming

| Property | Value |
|----------|-------|
| **Protection** | Symbol Renaming |
| **Class** | `Obfuscator` (core pipeline) |
| **Category** | Data (renaming) |
| **Targets** | Types, methods, fields, properties, events, parameters, generic parameters |
| **Configuration** | `RenameFields`, `RenameProperties`, `RenameEvents`, `KeepPublicApi`, `HidePrivateApi`, `ReuseNames`, `UseUnicodeNames`, `UseKoreanNames`, `CustomChars` |
| **Dependencies** | `InheritMap` (virtual method grouping), `MethodSemantics` (getter/setter associations) |

## Overview

Symbol renaming is Obfuscar's primary protection and the core of its obfuscation strategy. It renames types, methods, fields, properties, events, parameters, and generic parameters using sequential name generation with configurable character sets. Unlike ConfuserEx (which has a single `Ki.Rename` protection), Obfuscar's renaming is implemented as six separate pipeline steps, each handling a different member kind. The renaming pipeline includes virtual method grouping for inheritance consistency, overload renaming for compact output, and special handling for WPF BAML references and resource names.

## Name Generation Algorithm

**Source**: `NameMaker.cs`

Names are generated using base-N encoding where N is the size of the character set.

```
UniqueName(index):
    if index < charsetSize:
        return charset[index]           // Single char: "A", "a", "B", etc.
    else:
        result = ""
        while index >= charsetSize:
            result = charset[index % charsetSize] + result
            index = index / charsetSize - 1
        result = charset[index] + result
        return result
```

### Character Sets

Four naming modes are available, controlled by configuration settings:

| Mode | Setting | Character Set | Count | Example Names |
|------|---------|--------------|-------|---------------|
| Default | (none) | `AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz` | 52 | `A`, `a`, `B`, `Ab`, `Ba` |
| Unicode | `UseUnicodeNames=true` | Invisible Unicode chars (U+00A0, U+1680, U+2000-U+2057, U+2060-U+206F, U+3000) | ~106 | Invisible/confusing |
| Korean | `UseKoreanNames=true` | Random Hangul syllables (U+AC00-U+D5D0) | 128 | Korean characters |
| Custom | `CustomChars="..."` | User-specified character set | Varies | User-defined |

Unicode mode uses whitespace, formatting, and punctuation characters that are invisible or near-invisible in most editors, making disassembled code extremely difficult to read.

### Type-Specific Name Variants

- **`UniqueTypeName(index)`**: Generates names with `"."` separator for namespace-qualified names
- **`UniqueNestedTypeName(index)`**: No separator (nested types don't have namespaces)
- **`UniqueNamespace(index)`**: Namespace-only names with `"."` separator, generated from `index / charsetSize` to create dotted namespace components like `A.B`

### Collision Avoidance

The `NameGroup` class maintains a `HashSet<string>` of used names within each scope. Before assigning a name, the generator checks whether it collides with existing names in the same scope. If a collision is detected, the index is incremented until a unique name is found.

## Overload Renaming

**Setting**: `ReuseNames=true` (default)

Overload renaming is a key characteristic of Obfuscar-processed assemblies. When enabled, members are grouped by their type signature (`ParamSig` for methods, field type for fields). Within each group, the name counter resets — different methods with different parameter signatures can receive the same name (creating IL-level overloads), while methods with identical signatures get different names.

This produces compact output where many members share the same short name, which is valid in CIL even though most source languages don't support it. For example:

```
// Original:
void ProcessData(string input)
int CalculateHash(string input)
void SendResult(int code)

// After overload renaming (ReuseNames=true):
void A(string)    // Same name, different return type (valid in IL)
int A(string)
void A(int32)     // Same name, different parameter type
```

When `ReuseNames=false`, a global counter produces unique names across all members — no name collisions, but longer names.

## Type Renaming

**Pipeline step**: `RenameTypes()` (step 8 — last renaming step)

### Algorithm

1. **BAML analysis** (if `AnalyzeXaml=true`): Extract all type names referenced in WPF BAML resources and add them to the skip list (see [BAML Awareness](#baml-awareness) below)
2. **Iterate all types** in all assemblies being processed
3. **Check skip rules**: Apply `TypeTester` rules (see [Skip Rules](skip-rules.md))
4. **Generate new name**: Namespace via `UniqueNamespace()`, type name via `UniqueTypeName()`
5. **Handle nested types**: Use `UniqueNestedTypeName()` with position index in parent's `NestedTypes` list
6. **Preserve generic arity**: Append `` `N `` to the new name for generic types (e.g., `A`1` for `List<T>`)
7. **Update references**: Scan all referencing assemblies and update type references in method bodies, custom attributes, IL instructions, generic instantiations, exception handlers, and local variable types
8. **Update resources**: Rename resources named after the type (see [Resource Renaming](#resource-renaming) below)
9. **Update ResourceManager references**: Fix `ldstr` operands in methods returning `ResourceManager`

### Resource Renaming

When types are renamed, embedded resources following the pattern `Namespace.TypeName.resources` are updated to match the new type name:

```
// Before: MyApp.Strings.resources
// After:  A.A.resources
```

### BAML Awareness

When `AnalyzeXaml=true`, Obfuscar parses WPF BAML resources before renaming:

1. Iterates `assembly.MainModule.Resources` for embedded resources ending in `.baml`
2. Deserializes each BAML document using `BamlReader.ReadDocument()`
3. Extracts `TypeFullName` from all `TypeInfoRecord` instances
4. Adds collected type names to the skip list — these types are not renamed

This prevents runtime errors from hardcoded type references in compiled XAML.

## Method Renaming

**Pipeline step**: `RenameMethods()` (step 7)

### Two-Pass Algorithm

**Pass 1 — Virtual method grouping**:

All methods in an override chain are collected into a `MethodGroup` (built by `InheritMap`). If any method in the group is external (defined outside the project assemblies) or is an interface method from an external interface, the entire group is skipped. Otherwise, a single name is assigned to the entire group, ensuring all overrides share the same name.

**Pass 2 — Actual renaming**:

- **Virtual methods**: Use the group name assigned in Pass 1
- **Non-virtual methods**: Get a unique sequential name from `NameMaker`
- **Property getter/setter methods**: Follow the parent property's renaming decision — if the property is renamed, the accessor methods are too; if skipped, the accessors are skipped
- **Event add/remove methods**: Same — follow the parent event's decision

### Overload Renaming for Methods

Methods are grouped by `ParamSig` (the tuple of all parameter types). Within each signature group, methods can receive the same name. Methods with identical signatures must get different names.

## Field Renaming

**Pipeline step**: `RenameFields()` (step 3)

Fields are grouped by field type signature. With `ReuseNames=true`, fields of different types can share the same name (valid in IL even though C# doesn't allow it). Field references in all referencing assemblies are updated, including method body instructions (`ldsfld`, `stsfld`, `ldfld`, `stfld`).

## Property Renaming

**Pipeline step**: `RenameProperties()` (step 5)

Properties are either **renamed** or **dropped entirely** from metadata:

- If `KeepProperties=true` or the property has custom attributes: property definition is **renamed** (getter/setter methods also renamed)
- Otherwise: property definition is **removed** from metadata (getter/setter methods survive but lose their property association)

Property definitions on custom attribute types with public setters are always preserved to maintain attribute functionality.

After renaming, property method semantics attributes (`MethodSemanticsAttributes.Getter/Setter`) are cleared to prevent IL verification issues.

## Event Renaming

**Pipeline step**: `RenameEvents()` (step 6)

Events follow the same pattern as properties:

- If the event has custom attributes: event definition is **renamed**
- Otherwise: event definition is **removed** from metadata (add/remove methods survive)

## Parameter Renaming

**Pipeline step**: `RenameParams()` (step 4)

- **Method parameters**: Set to `null` (erased entirely, not renamed to a new value)
- **Generic type parameters**: Renamed via `NameMaker.UniqueName()`

This is a lossy transformation — original parameter names are irrecoverable from the obfuscated assembly.

## ObfuscationAttribute Support

Obfuscar respects the standard `System.Reflection.ObfuscationAttribute`:

```csharp
[Obfuscation(Feature = "...", Exclude = true/false, ApplyToMembers = true/false)]
```

- **Exclude**: `true` means don't obfuscate this member
- **ApplyToMembers**: If on a type, cascade the setting to all members
- **StripAfterObfuscation**: If `true` (default), the attribute is removed during `PostProcessing()`

When `MarkedOnly=true`, only members explicitly decorated with `[Obfuscation]` are candidates for obfuscation.

## Detection Signatures

- **Overload-renamed methods**: Multiple methods or fields with the same name but different signatures (characteristic of `ReuseNames=true`)
- **Single-character or short names**: From the default charset (`A`, `a`, `B`, `Ab`, `Ba`)
- **Unicode whitespace names**: Members named with invisible Unicode characters
- **Null parameter names**: Parameters with no name (set to null, not empty string)
- **Missing PropertyDef/EventDef**: Getter/setter methods exist but no corresponding property definition; add/remove methods exist but no event definition
- **Short dotted namespaces**: Single-character namespace components like `A.B`

## dotscope Handling

Renaming is inherently lossy — original names are irrecoverably lost and cannot be reversed by any deobfuscation tool. The mapping file (Mapping.txt/xml) that records renames is only available to the obfuscator operator and is not embedded in the output assembly.
