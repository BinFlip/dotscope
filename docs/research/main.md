# Obfuscator Research

Research documentation for .NET obfuscators supported or investigated by dotscope.

## Supported Obfuscators

| Obfuscator | Status | Documentation |
|------------|--------|---------------|
| [ConfuserEx](confuserex/main.md) | Fully supported (18/18 samples pass) | 14 protection docs + architecture |
| [Obfuscar](obfuscar/main.md) | Fully supported (6/6 samples pass) | 5 protection/feature docs + architecture |
| [BitMono](bitmono/main.md) | Fully supported (16/16 samples pass) | 17 protection docs + architecture |
| [JIEJIE.NET](jiejie.net/main.md) | Fully supported (10/10 samples pass) | 16 protection docs + architecture |

## Under Investigation

| Obfuscator | Status | Documentation |
|------------|--------|---------------|
| [PureLogs](purelogs/main.md) | Active research (Phase 1 complete) | 10 analysis docs |
| [.NET Reactor](netreactor.md) | Gap analysis complete | Tier-based implementation plan |

## Obfuscator Comparison

### Common Protection Techniques

| Technique | ConfuserEx | Obfuscar | BitMono | JIEJIE.NET | PureLogs | .NET Reactor |
|-----------|-----------|----------|---------|------------|----------|-------------|
| Symbol renaming | Yes | Yes | Yes | Yes | — | Yes |
| String encryption | Yes | Yes | Yes | Yes | Yes | Yes |
| Control flow flattening | Yes | — | — | Yes | Yes | Yes |
| Constant encoding | Yes | — | — | Yes | — | Yes |
| Resource encryption | Yes | — | — | Yes | — | Yes |
| Anti-debug | Yes | — | Yes | — | — | Yes |
| Anti-tamper | Yes | — | — | — | — | Yes |
| Reference proxy/delegates | Yes | — | Yes | — | Yes | Yes |
| Opaque predicates | — | — | — | — | Yes | — |
| Packing/compression | Yes | — | — | — | — | Yes |
| Type scrambling | Yes | — | — | — | — | — |

### Deobfuscation Approach

Each obfuscator uses the same core pipeline in dotscope:

1. **Detection**: Identify which obfuscator(s) were applied (technique registry)
2. **Technique-specific passes**: Decrypt strings, resolve proxies, etc.
3. **Generic passes**: CFF reconstruction, constant propagation, dead code elimination
4. **Cleanup**: Remove injected types/methods, restore metadata
5. **Code generation**: Emit cleaned IL back to a valid PE
