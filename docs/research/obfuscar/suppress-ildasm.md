# SuppressIldasm Attribute

| Property | Value |
|----------|-------|
| **Protection** | SuppressIldasm |
| **Class** | `Obfuscator` (inline in `PostProcessing()`) |
| **Category** | Anti-Analysis (metadata) |
| **Targets** | Module |
| **Configuration** | `SuppressIldasm` (default: `true`) |
| **Dependencies** | Runs during post-processing (step 9), after all renaming |

## Overview

Injects `System.Runtime.CompilerServices.SuppressIldasmAttribute` as a module-level custom attribute. This causes Microsoft's ILDASM disassembler to refuse to open the assembly. The attribute has no effect on other disassemblers or decompilers (ILSpy, dnSpy, dotPeek, etc.) and is trivially bypassed by hex-editing or removing the attribute.

## Mechanism

During `PostProcessing()`:

1. Check if `SuppressIldasm` setting is `true` (the default)
2. Check if the module already has a `SuppressIldasmAttribute` (avoid duplicates)
3. If not present, resolve the `SuppressIldasmAttribute` type from `mscorlib`/`System.Runtime`
4. Find or create the parameterless constructor reference
5. Create a new `CustomAttribute` instance with the constructor
6. Add the attribute to the module's `CustomAttributes` collection

The attribute is a standard ECMA-335 custom attribute — no IL transformation or metadata corruption is involved. It's purely advisory: ILDASM checks for this specific attribute name and refuses to proceed if found.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `SuppressIldasm` | `true` | Add SuppressIldasmAttribute to module |

## Detection Signatures

- Module-level `System.Runtime.CompilerServices.SuppressIldasmAttribute` custom attribute
- Low confidence as a standalone Obfuscar indicator — many obfuscators inject this attribute, and developers can add it manually

## dotscope Handling

Handled generically by `NeutralizationPass` — the attribute is identified and removed during metadata cleanup. Not Obfuscar-specific.
