# Mapping File

| Property | Value |
|----------|-------|
| **Feature** | Mapping File Generation |
| **Class** | `MapWriter` |
| **Category** | Output (not a protection) |
| **Configuration** | `LogFile` (output path), `XmlMapping` (format selection) |

## Overview

Obfuscar produces a mapping file that records all renaming decisions — original names, new names, and skip reasons. The mapping file is written to disk alongside the obfuscated assembly and is available only to the obfuscator operator. It is **not** embedded in the output assembly. Two formats are supported: text (default) and XML.

## Text Format

The default format when `XmlMapping=false` (or unset):

```
Renamed Types:

[AssemblyName]MyNamespace.MyClass -> [AssemblyName]A.A
{
    System.String MyMethod(System.String) -> A
    System.Int32 MyField -> A
    System.String MyProperty -> A
    System.EventHandler MyEvent -> A
}

[AssemblyName]MyNamespace.OtherClass -> [AssemblyName]A.a
{
    System.Void Process() -> A
    System.Void Process(System.Int32) -> A    // overload renamed to same name
}

Skipped Types:

[AssemblyName]MyNamespace.PublicClass skipped:  public
{
    System.Void PublicMethod() skipped:  public
    System.Int32 get_Value() skipped:  property accessor
}

Renamed Resources:

MyNamespace.MyClass.resources -> A.A.resources

Skipped Resources:

MyNamespace.PublicClass.resources (kept due to type skip)
```

### Text Format Structure

- **Renamed types section**: Each type shows `oldFullName -> newFullName`, with members listed in braces
- **Skipped types section**: Each type shows `name skipped: reason`, with members and their skip reasons
- **Renamed resources section**: `oldName -> newName` for each renamed resource
- **Skipped resources section**: Lists resources that were not renamed

### Skip Reasons

| Reason | Description |
|--------|-------------|
| `public` | Member is public and `KeepPublicApi=true` |
| `virtual` | Virtual method with external base class |
| `external base class` | Overrides a method from an assembly not being obfuscated |
| `property accessor` | Getter/setter follows the property's skip decision |
| `event accessor` | Add/remove follows the event's skip decision |
| `inherits from ...` | Type inheritance rule matched |
| `filtered by rule` | Explicit `SkipType`/`SkipMethod`/etc. rule matched |

## XML Format

When `XmlMapping=true`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<mapping>
  <renamedTypes>
    <renamedClass oldName="[AssemblyName]MyNamespace.MyClass"
                  newName="[AssemblyName]A.A">
      <renamedMethod oldName="MyMethod(System.String)" newName="A" />
      <renamedField oldName="MyField" newName="A" />
      <renamedProperty oldName="MyProperty" newName="A" />
      <renamedEvent oldName="MyEvent" newName="A" />
    </renamedClass>
  </renamedTypes>
  <skippedTypes>
    <skippedClass name="[AssemblyName]MyNamespace.PublicClass" reason="public">
      <skippedMethod name="PublicMethod()" reason="public" />
    </skippedClass>
  </skippedTypes>
  <renamedResources>
    <renamedResource oldName="MyNamespace.MyClass.resources"
                     newName="A.A.resources" />
  </renamedResources>
  <skippedResources>
    <skippedResource name="MyNamespace.PublicClass.resources"
                     reason="kept due to type skip" />
  </skippedResources>
</mapping>
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `LogFile` | `""` (no output) | Absolute path to the mapping output file |
| `XmlMapping` | `false` | Output XML format instead of text |

If `LogFile` is empty or not set, no mapping file is written.

## dotscope Handling

The mapping file is not embedded in the obfuscated assembly and is only available to the obfuscator operator. It cannot be used for deobfuscation. Understanding the format is useful for test validation — when both the mapping file and original assembly are available, it can verify that deobfuscation correctly identifies the same members that were renamed.
