# AntiILdasm

| Property | Value |
|----------|-------|
| **Protection** | `AntiILdasm` |
| **Class** | `Protection` |
| **Category** | Metadata (disassembly prevention) |
| **Targets** | Module (assembly-level attribute) |

## Overview

Injects `System.Runtime.CompilerServices.SuppressIldasmAttribute` onto the module. This is an advisory attribute that tells the `ildasm` tool to refuse to disassemble the assembly. It has no effect on other tools or runtime behavior.

## Algorithm

Simply adds the `SuppressIldasmAttribute` custom attribute to the module definition.

## Detection Signatures

- `SuppressIldasmAttribute` present on the module
- Same attribute is also used by Obfuscar

## dotscope Handling

Handled by the shared `utils::check_suppress_ildasm()` utility — same detection used for Obfuscar's identical protection.
