# Resources Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.Resources` |
| **Short ID** | `resources` |
| **Preset** | Normal |
| **Targets** | Methods |
| **Pipeline Stages** | InjectPhase: PreStage ProcessModule; MDPhase: hooks ModuleWriter events |
| **Dependencies** | Must run before `Ki.ControlFlow`, must run after `Ki.Constants` |

## Overview

Encrypts embedded resources by moving them to a separate satellite assembly, compressing and encrypting that assembly, and storing it as static field data. At runtime, the protection decrypts and loads the satellite assembly to service resource requests. Satellite assemblies for non-default cultures are skipped.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `mode` | `Normal`, `Dynamic` | `Normal` | Encryption algorithm |

## Architecture

The protection operates in two phases with a ModuleWriter hook:

### Phase 1: InjectPhase

1. **Runtime injection**: Injects `Confuser.Runtime.Resource` type into module's global type
2. **Decompressor injection**: Gets LZMA decompressor from `ICompressionService`
3. **Key deriver injection**: Injects Normal or Dynamic key deriver
4. **Data structure creation**: Creates explicit-layout `ValueType` with static FieldRVA field
5. **Module integration**: Inserts `call Initialize` in module `.cctor`

### Phase 2: MDPhase (ModuleWriter Hook)

Hooks `MDBeginAddResources` event to intercept resource writing:

1. **Resource assembly creation**:
   - Creates new `AssemblyDef` with random name and version `0.0`
   - Copies all `EmbeddedResource` objects to the new assembly
   - Serializes the assembly to a byte buffer
2. **Compression**: LZMA compress the assembly buffer
3. **Alignment**: Pad to 16 `uint32` boundary (fill with zeros)
4. **Encryption**: Block-encrypt the compressed data
5. **Storage**: Write encrypted buffer to static field with FieldRVA

## Encryption Algorithm

### Key Derivation (LFSR)

```
state = keySeed    // random uint32 with bit 4 set
for i in 0..15:
    state ^= state >> 13
    state ^= state << 25
    state ^= state >> 27
    key[i] = state
```

### Block Encryption

Processes in 16-`uint32` blocks:

```
for each 16-word block at offset:
    encrypted[0..15] = ModeHandler.Encrypt(data[offset..offset+15], key[0..15])
    key[j] ^= data[offset + j]    for j in 0..15   // Key chaining with plaintext
```

### Normal Mode Encryption

Simple XOR:
```
result[i] = data[offset + i] ^ key[i]    for i in 0..15
```

### Dynamic Mode Encryption

Uses `IDynCipherService` to generate a random symmetric cipher pair:
- Forward cipher compiled as .NET delegate (protection time)
- Inverse cipher emitted as CIL (injected into `Initialize()`)

See [DynCipher](dynciper.md) for cipher generation details.

## Runtime Decryption

### Initialize() Method

```
1. Extract keySeed from mutation placeholder
2. Generate 16-element key via LFSR
3. Load encrypted buffer from static field
4. Decrypt in 16-word blocks:
   for each block:
       Apply decryption (Normal: XOR, Dynamic: cipher)
       Update key: key[j] ^= decrypted[j]
5. LZMA decompress → satellite assembly bytes
6. Assembly.Load(decompressedBytes) → loaded assembly
7. Register AppDomain.AssemblyResolve handler
```

### AssemblyResolve Handler

When the runtime requests a resource assembly:
1. Compare requested assembly name against loaded satellite assembly
2. If match, return the loaded assembly
3. Resources are then accessible through the satellite assembly's resource streams

## dotscope Handling

Handled by `ConfuserExDump` technique which replays LFSR key derivation, decrypts the buffer, LZMA decompresses, and restores embedded resources to the original module.
