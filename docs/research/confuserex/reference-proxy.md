# Reference Proxy Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.RefProxy` |
| **Short ID** | `ref proxy` |
| **Preset** | Normal |
| **Targets** | Methods |
| **Pipeline Stage** | PreStage of ProcessModule |
| **Dependencies** | Must run before `Ki.ControlFlow`; must run after `Ki.AntiDebug`, `Ki.AntiDump` |

## Overview

Replaces direct method call references with indirect calls through dynamically resolved delegate proxies. This obfuscates the call graph and prevents static analysis tools from determining which methods are actually called at each call site. Two modes (Mild and Strong) provide different levels of indirection, and three encoding schemes protect the target token resolution.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `mode` | `Mild`, `Strong` | `Mild` | Proxy generation strategy |
| `encoding` | `Normal`, `Expression`, `x86` | `Normal` | Token encoding scheme |
| `internal` | `true`/`false` | `false` | Proxy internal (same-assembly) references |
| `typeErasure` | `true`/`false` | `false` | Replace parameter types with `object` |
| `depth` | 1–N | 3 | Expression/x86 nesting depth |

## Mode: Mild

Creates simple wrapper methods that delegate to the original target.

### Algorithm

For each eligible call instruction:

1. **Create proxy method**: A static method in the same declaring type with identical parameter/return signature
2. **Generate body**: Loads all arguments, calls the original target, returns result
3. **Replace call**: Original call instruction now targets the proxy method

### Restrictions

Mild mode skips calls that:
- Target non-public/non-assembly methods (visibility constraint)
- Target value type instance methods
- Target generic methods or methods in generic types
- Use `varargs` calling convention
- Are constructor calls (`newobj`)

### Example

```
// Original
call string String::Concat(string, string)

// After Mild proxy
call string proxy_Ab3x(string, string)    // Proxy method

// Proxy body:
static string proxy_Ab3x(string a, string b) {
    return String.Concat(a, b);
}
```

## Mode: Strong

Creates delegate fields that are resolved at runtime via metadata parsing. Significantly more complex and harder to reverse.

### Architecture

1. **Delegate field creation**: For each proxied call, creates a static field of a matching delegate type
2. **Field decoration**: Encodes the target method token into the field's metadata (signature, name, custom attribute)
3. **Runtime initialization**: An `Initialize()` method resolves all delegate fields at startup
4. **Call replacement**: Original calls replaced with delegate invocation

### Delegate Field Encoding

Each proxy field carries encoded information in three locations:

**Field name** (5 characters):
- 4 bytes from `nameKey` placed at shuffled indices (randomized per-method)
- 1 byte: opcode indicator XORed with `opKey` at random index
- Example: character positions determined by `KeyI4-KeyI7` mutation values

**Field signature CModOpt**:
- Custom optional modifier encodes the delegate type token
- Format: `CModOpt(randomType, delegateType)`

**Custom attribute** (`RefProxyKey`):
- A synthesized attribute class injected per initialization method
- Constructor contains mode-specific encoding expression (via `Mutation.Placeholder`)
- `GetHashCode()` call on attribute instance returns the encoded key

### Token Encoding in Field Signature

```
token_value = (actual_token * encoding_key) - delegate_type_token
final_value = token_value ^ nameKey_as_uint32
```

Stored as extra bytes in the field signature with sentinel `0xC0` bytes at specific positions.

### Runtime Resolution

The `Initialize(RuntimeFieldHandle field, byte opKey)` method:

1. **Extract token**: Reads field name, signature extra data, and custom attribute
2. **Decode nameKey**: Extracts 4 bytes from field name using injected index mappings
3. **Compute encoding key**: Calls `GetHashCode()` on custom attribute (applies encoding expression)
4. **Recover token**: Applies multiplicative inverse to recover `actual_token`
5. **Resolve method**: `Module.ResolveMethod(token)`
6. **Create delegate**:
   - Static methods: direct `Delegate.CreateDelegate()`
   - Instance methods: creates `DynamicMethod` with proper IL:
     - Loads arguments with appropriate unboxing (`castclass` for reference types)
     - Emits correct call opcode (`call`/`callvirt`/`newobj`) based on decoded `opKey`

### Call Replacement Strategies

**Invoke path** (preferred): When the delegate can be loaded before arguments are pushed:
```
// Original: arg1, arg2, call Target
// After:    ldsfld delegate, arg1, arg2, call Invoke
```

**Bridge path** (fallback): When arguments are already on the stack:
```
// Creates a bridge method that loads the delegate and calls Invoke
// Original: arg1, arg2, call Target
// After:    arg1, arg2, call BridgeMethod
```

## Encoding Schemes

All encodings apply to the method token stored in field metadata.

### Normal Encoding

Multiplicative cipher:

```csharp
// Protection time
encoded = actual_token * key    // key is random odd number

// Runtime
decoded = encoded * modInverse(key)
```

Emitted as simple `ldc.i4; mul` IL instructions in the initialization method.

### Expression Encoding

Uses `IDynCipherService` to generate random mathematical expression pairs:

```csharp
// Protection time: apply forward expression
encoded = expression(actual_token)

// Runtime: emit inverse expression as CIL
decoded = inverse(encoded)
```

Configurable depth increases expression complexity. See [DynCipher](dynciper.md).

### x86 Encoding

Generates native x86 machine code for token decoding:

1. Generates DynCipher expression pair
2. Compiles inverse expression to x86 assembly via `x86CodeGen`
3. Creates native method (`PinvokeImpl | Native | Unmanaged | PreserveSig`)
4. Injected into PE via `ModuleWriter` event hooks
5. Runtime calls native method for decoding

Removes `ILOnly` flag from PE header.

## Type Erasure

When `typeErasure=true`, all parameter and return types in proxy signatures are replaced with `System.Object`. This:

- Prevents type-based static analysis from inferring call targets
- Requires boxing/unboxing at call sites
- Makes the delegate signatures non-unique (harder to match back to targets)

## dotscope Handling

Handled by `ConfuserExProxy` technique which identifies delegate fields, emulates token resolution, and restores direct calls. Mild mode proxies are also resolved via the generic `DelegateProxyResolutionPass`.
