# AntiDe4dot

| Property | Value |
|----------|-------|
| **Protection** | `AntiDe4dot` |
| **Class** | `Protection` |
| **Category** | Metadata (tool confusion) |
| **Targets** | Module (assembly-level attributes) |

## Overview

Injects fake obfuscator-identification custom attributes onto the module to confuse de4dot, a popular .NET deobfuscation tool. De4dot uses these attributes to identify which obfuscator was used, so flooding the module with conflicting identifiers prevents automatic detection.

## Algorithm

Adds the following fake custom attributes to the module:

| Attribute Name | Mimics |
|----------------|--------|
| `SmartAssembly.Attributes.PoweredBy` | SmartAssembly |
| `Xenocode.Client.Attributes.AssemblyAttributes.PoweredBy` | Xenocode |
| `ObfuscatedByGoliath` | Goliath Obfuscator |
| `SecureTeam.Attributes.ObfuscatedByAgileDotNet` | Agile.NET |
| `TrinityObfuscator` | Trinity Obfuscator |
| `SecureTeam.Attributes.ObfuscatedByCliSecure` | CliSecure |
| `ZYXDNGuarder` | ZYXDNGuarder |
| `BabelObfuscator` (×2) | Babel Obfuscator |
| `Dotfuscator` | Dotfuscator |
| `Centos` | Centos |
| `ConfusedBy` | ConfuserEx |
| `NineRays.Obfuscator.Evaluation` | 9Rays |
| `CryptoObfuscator.ProtectedWithCryptoObfuscator` | Crypto Obfuscator |
| `();\u0009` | Obfuscated junk name |
| `EMyPID_8234_` | Obfuscated junk name |

All attributes reference non-existent types, making them easy to identify as fake.

## Detection Signatures

- Multiple custom attributes on the module from different obfuscator vendors simultaneously
- Attribute TypeRefs point to non-existent assemblies/types
- Presence of known junk names (`();\u0009`, `EMyPID_8234_`)

## dotscope Handling

Not specifically targeted — fake custom attributes are removed as part of general cleanup when their referenced types don't exist in any loaded assembly.
