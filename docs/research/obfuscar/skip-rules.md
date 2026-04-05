# Skip Rules System

| Property | Value |
|----------|-------|
| **Feature** | Skip/Force Rules |
| **Class** | `TypeTester`, `MethodTester`, `FieldTester`, `PropertyTester`, `EventTester`, `NamespaceTester` |
| **Category** | Configuration (not a protection) |
| **Configuration** | XML `<SkipType>`, `<ForceType>`, `<SkipMethod>`, `<ForceMethod>`, `<SkipField>`, `<ForceField>`, `<SkipProperty>`, `<SkipEvent>`, `<SkipNamespace>`, `<SkipStringHiding>`, plus global `KeepPublicApi`, `HidePrivateApi`, `MarkedOnly` |

## Overview

The skip rules system controls which members are obfuscated and which are left untouched. Rules are declared as XML elements within `<Module>` blocks in the project file (`obfuscar.xml`). Each rule type has a corresponding tester class that evaluates members against the rule's criteria. The system supports literal name matching, wildcards, regular expressions, visibility filters, type inheritance checks, and custom attribute (decorator) filters.

## Global Visibility Controls

Three global settings provide baseline visibility behavior before any per-member rules are evaluated:

| Setting | Default | Effect |
|---------|---------|--------|
| `KeepPublicApi` | `true` | Public types/members are skipped (not renamed) by default |
| `HidePrivateApi` | `true` | Non-public types/members are renamed by default |
| `MarkedOnly` | `false` | Only members with `[Obfuscation]` attribute are candidates for renaming |

### Evaluation Precedence

1. **MarkedOnly**: If enabled, only process members with `[Obfuscation(Exclude = false)]`
2. **KeepPublicApi**: If `true`, public members default to skipped
3. **HidePrivateApi**: If `true`, non-public members default to renamed
4. **Explicit Skip/Force rules**: Applied in declaration order, overriding defaults
5. **Type cascading**: `SkipType` with member-affect flags cascades to child members

## Rule Elements

### SkipType / ForceType

Controls whether a type is renamed. Can cascade to members via flags.

```xml
<SkipType name="MyNamespace.MyType"
          rx="regex_pattern"
          attrib="public"
          typeinherits="System.IDisposable"
          static="true"
          serializable="true"
          decorator="MyCustomAttribute"
          decoratorAll="Attr1,Attr2"
          skipMethods="true"
          skipFields="true"
          skipProperties="true"
          skipEvents="true"
          skipStringHiding="true" />
```

**Type affect flags** (bitmask controlling cascading):

| Attribute | Flag | Effect |
|-----------|------|--------|
| `skipEvents` | 0x01 | Skip event renaming for this type |
| `skipProperties` | 0x02 | Skip property renaming for this type |
| `skipFields` | 0x04 | Skip field renaming for this type |
| `skipMethods` | 0x08 | Skip method renaming for this type |
| `skipStringHiding` | 0x10 | Skip string hiding for methods in this type |

### SkipMethod / ForceMethod

Controls whether a method is renamed.

```xml
<SkipMethod name="OnPropertyChanged"
            rx="^Get.*"
            type="MyNamespace.MyType"
            attrib="public"
            typeattrib="public"
            typeinherits="System.ComponentModel.INotifyPropertyChanged"
            static="true" />
```

### SkipField / ForceField

Controls whether a field is renamed.

```xml
<SkipField name="connectionString"
           rx="^_.*"
           type="System.String"
           attrib="public"
           typeattrib="public"
           static="true"
           serializable="true"
           decorator="System.NonSerializedAttribute"
           typeinherits="System.Data.DbConnection" />
```

### SkipProperty / SkipEvent

Controls whether a property or event is renamed (or dropped from metadata).

```xml
<SkipProperty name="Name" type="MyType" attrib="public" />
<SkipEvent name="PropertyChanged" type="MyType" />
```

### SkipNamespace

Skips an entire namespace and all its types.

```xml
<SkipNamespace name="MyApp.PublicApi" />
```

### SkipStringHiding / ForceStringHiding

Controls string hiding per-method.

```xml
<SkipStringHiding type="MyType" name="GetConnectionString" />
<ForceStringHiding type="*" name="*" />
```

## Matching Criteria

### Name Matching

Three modes, evaluated in priority order:

1. **Regex** (`rx="pattern"`): Full regex pattern match against the member name. Takes priority when present.
2. **Wildcard** (`name="Type*"`): Glob-style matching — `*` matches any sequence of characters. Applied when `name` contains `*` or `?`.
3. **Literal** (`name="ExactName"`): Exact case-sensitive string comparison.

### Visibility Matching (`attrib`)

| Value | Matches |
|-------|---------|
| `public` | Public visibility only |
| `protected` | Family (protected) visibility only |
| (omitted) | All visibilities |

If `attrib` is specified and the member doesn't match the requested visibility, the rule is ignored for that member.

### Type Visibility (`typeattrib`)

Same as `attrib` but checks the declaring type's visibility rather than the member's.

### Type Inheritance (`typeinherits`)

Checks whether the declaring type inherits from or implements the specified type. Uses `InheritMap` for full inheritance chain resolution, including interfaces.

### Decorator Matching

- **Single**: `decorator="System.SerializableAttribute"` — type must have this custom attribute
- **Multiple**: `decoratorAll="Attr1,Attr2,Attr3"` — type must have ALL listed attributes
- **Compiler-generated detection**: Types with names starting with `<` are treated as compiler-generated (equivalent to `CompilerGeneratedAttribute`)

### Other Filters

| Attribute | Values | Description |
|-----------|--------|-------------|
| `static` | `true`/`false` | Match only static or instance members |
| `serializable` | `true`/`false` | Match based on `[Serializable]` attribute on type |

## Configuration Examples

### Protect public API, rename everything else

```xml
<Var name="KeepPublicApi" value="true" />
<Var name="HidePrivateApi" value="true" />
```

### Rename everything including public API

```xml
<Var name="KeepPublicApi" value="false" />
<Var name="HidePrivateApi" value="true" />
```

### Skip all types implementing ISerializable

```xml
<SkipType typeinherits="System.Runtime.Serialization.ISerializable"
          skipMethods="true"
          skipFields="true"
          skipProperties="true" />
```

### Only rename types with [Obfuscation] attribute

```xml
<Var name="MarkedOnly" value="true" />
```

### Skip specific methods by regex

```xml
<SkipMethod rx="^(get_|set_).*" attrib="public" />
```

### Force rename a specific private method

```xml
<ForceMethod name="InternalHelper" type="MyNamespace.MyClass" />
```

## dotscope Handling

The skip rules system is a configuration-time feature — it controls which members Obfuscar processes, but leaves no trace in the output assembly. There is nothing to detect or reverse. Understanding the rules is useful for interpreting why certain members are renamed while others retain their original names.
