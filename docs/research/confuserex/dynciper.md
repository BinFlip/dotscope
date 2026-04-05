# DynCipher — Dynamic Cipher Infrastructure

## Overview

DynCipher is a shared infrastructure component used by multiple ConfuserEx protections (Control Flow, Constants, Resources, Reference Proxy, Anti-Tamper). It generates **unique, randomized cipher code** for each protected assembly, ensuring that no two protections produce identical encryption/decryption routines. This makes generic deobfuscation tools ineffective — each protected binary requires individual analysis.

DynCipher produces two artifacts:
1. **Forward cipher** (encryption): Used at protection time to encrypt data
2. **Inverse cipher** (decryption): Emitted as CIL and injected into the protected assembly for runtime decryption

## Architecture

### Service Interface

```csharp
IDynCipherService {
    void GenerateCipherPair(RandomGenerator random, out StatementBlock encrypt, out StatementBlock decrypt);
    void GenerateExpressionPair(RandomGenerator random, out Expression expression, out Expression inverse);
}
```

Two generation modes:
- **Cipher pairs**: Full block ciphers operating on 16-element `uint32` arrays (used by Constants, Resources, Anti-Tamper, Reference Proxy)
- **Expression pairs**: Single-value mathematical expressions (used by Control Flow predicates, Constants x86 mode)

## AST System

DynCipher uses an Abstract Syntax Tree to represent cipher operations before compiling to CIL:

### Expressions

| Type | Description | Example |
|------|-------------|---------|
| `LiteralExpression` | Constant uint32 value | `0xDEADBEEF` |
| `VariableExpression` | Variable reference | `v0`, `t1`, `key` |
| `ArrayIndexExpression` | Array element access | `key[3]` |
| `BinOpExpression` | Binary operation | `v0 + v1`, `v2 ^ key[i]` |
| `UnaryOpExpression` | Unary operation | `~v0`, `-v1` |

**Binary operations**: Add, Sub, Mul, Div, Or, And, Xor, Lsh (left shift), Rsh (right shift)

**Unary operations**: Not (bitwise), Negate (arithmetic)

Operator overloads allow natural expression construction: `v0 + v1`, `v0 ^ literal`, `~v0`

### Statements

| Type | Description |
|------|-------------|
| `AssignmentStatement` | `variable = expression` or `array[index] = expression` |
| `LoopStatement` | `for i in begin..limit` |
| `StatementBlock` | Container for sequential statements |

## Cipher Generation (CipherGenerator)

### Element Types

The cipher is composed of randomly selected cryptographic building blocks:

| Element | Data Variables | Operation | Inverse |
|---------|---------------|-----------|---------|
| **Matrix** | 4 | 4x4 unimodular matrix transform | Adjugate (cofactor) matrix |
| **NumOp** | 1 | Single-variable: Add/Xor/Mul/Xnor | Sub/Xor/MulInverse/Xnor |
| **BinOp** | 2 | Two-variable: Add/Xor/Xnor | Sub/Xor/Xnor |
| **RotateBit** | 1 | Bit rotation (left/right, 1-31 bits) | Opposite rotation |
| **Swap** | 2 | Conditional bit swap with mask | Same operation (self-inverse) |
| **AddKey** | 0 | XOR with key array: `v[i] ^= key[i]` | Same operation (self-inverse) |

### Element Ratios

Element types are weighted to control cipher composition:

| Element | Weight | Typical Count |
|---------|--------|---------------|
| Matrix | 4 | ~1 |
| NumOp | 10 | ~2-3 |
| BinOp | 9 | ~2-3 |
| RotateBit | 6 | ~1-2 |
| Swap | 6 | ~1-2 |
| AddKey | 16 | ~4 (one per 4 data vars) |

Total elements: `(random(0,1) + 1) * RATIO_SUM * variance(0.8, 1.2)`

### Generation Algorithm

```
1. Compute total element count from ratios and variance
2. Distribute elements proportionally across all 16 data variables
3. For each element:
   a. Initialize with random parameters (keys, rotation amounts, matrices)
   b. Assign 1-4 data variable indices (based on DataCount)
4. ENCRYPT: Emit all elements in random order
5. DECRYPT: Emit all elements in REVERSE order, calling EmitInverse()
```

### Matrix Element Details

Generates random 4x4 unimodular matrices via LU decomposition:
- Determinant is always 1 (guarantees invertibility over integers mod 2^32)
- Each matrix transforms 4 data variables via linear combinations
- Inverse is the adjugate (cofactor) matrix
- Operations: multiply, add (all mod 2^32)

### NumOp Element Details

| Operation | Forward | Inverse |
|-----------|---------|---------|
| Add | `v += key` | `v -= key` |
| Xor | `v ^= key` | `v ^= key` (self-inverse) |
| Mul | `v *= key` (key odd) | `v *= modInverse(key)` |
| Xnor | `v = ~(v ^ key)` | `v = v ^ ~key` |

## Expression Generation (ExpressionGenerator)

Generates single-value mathematical expression pairs for predicates.

### Algorithm

Builds expression trees recursively to target depth:

```
GenerateExpression(depth):
    if depth == 0: return input_variable
    choose random operation: Add, Sub, Mul, Xor, Not, Negate
    left = GenerateExpression(depth - 1)
    right = random_literal (for binary ops)
    return BinOp(left, right) or UnaryOp(left)
```

### Inverse Computation

Walks the expression tree from output to input, applying algebraic inverses:

| Forward | Inverse Rule |
|---------|-------------|
| `v + k = r` | `v = r - k` |
| `v - k = r` | `v = r + k` |
| `k - v = r` | `v = k - r` |
| `v * k = r` | `v = r * modInverse(k)` (k must be odd) |
| `v ^ k = r` | `v = r ^ k` (self-inverse) |
| `~v = r` | `v = ~r` |
| `-v = r` | `v = -r` |

## Post-Processing Transforms

After generation, both encrypt and decrypt blocks undergo optimization:

### 1. MulToShiftTransform

Decomposes multiplications by constants with ≤2 set bits into shift+add sequences:

```
v * 5  →  (v << 2) + v      // 5 = 100 + 1
v * 12 →  (v << 3) + (v << 2)  // 12 = 1000 + 100
```

### 2. NormalizeBinOpTransform

Left-associates binary operations and removes identity operations:

```
a + (b + c) → (a + b) + c
x + 0 → x
```

### 3. ExpansionTransform

Breaks nested expressions into sequential assignments:

```
a = (b + c) ^ d
→
a = b + c
a = a ^ d
```

### 4. ShuffleTransform

Randomly reorders statements while respecting data dependencies (20 iterations):

```
For each statement:
    Compute upward kill point (last write to variables we read)
    Compute downward kill point (first read of variables we write)
    Move to random valid position within [upKill, downKill]
```

### 5. ConvertVariables

Final variable name transformation for code emission.

## CIL Code Generation (CILCodeGen)

Converts AST to CIL instructions:

| AST Node | CIL Output |
|----------|------------|
| `LiteralExpression` | `ldc.i4 value` |
| `VariableExpression` | `ldloc variable` |
| `ArrayIndexExpression` (load) | `ldloc array; ldc.i4 index; ldelem.u4` |
| `ArrayIndexExpression` (store) | `ldloc array; ldc.i4 index; value; stelem.i4` |
| `BinOp(Add)` | `add` |
| `BinOp(Sub)` | `sub` |
| `BinOp(Mul)` | `mul` |
| `BinOp(Xor)` | `xor` |
| `BinOp(Or)` | `or` |
| `BinOp(And)` | `and` |
| `BinOp(Lsh)` | `shl` |
| `BinOp(Rsh)` | `shr.un` |
| `UnaryOp(Not)` | `not` |
| `UnaryOp(Negate)` | `neg` |
| `AssignmentStatement` | EmitStore (stloc or stelem.i4) |
| `LoopStatement` | `br check; body; check: dup; ldc.i4 limit; blt body` |

All variables are allocated as `uint32` locals. `Commit()` adds all locals to the method body.

## x86 Code Generation

For x86 predicates and encodings, the inverse expression is also compiled to native x86:

1. `x86CodeGen.GenerateX86(inverse, callback)` — converts AST to x86 instructions
2. `CodeGenUtils.AssembleCode()` — assembles to raw bytes
3. Result injected as native method body via ModuleWriter events

## Usage by Protections

| Protection | Uses Cipher Pairs | Uses Expression Pairs |
|------------|------------------|----------------------|
| Constants (Dynamic/x86 mode) | Buffer encryption | x86 ID decoding |
| Control Flow (Expression predicate) | — | Key transformation |
| Control Flow (x86 predicate) | — | Key transformation (compiled to x86) |
| Resources (Dynamic mode) | Buffer encryption | — |
| Reference Proxy (Expression encoding) | — | Token encoding |
| Reference Proxy (x86 encoding) | — | Token encoding (compiled to x86) |
| Anti-Tamper (Dynamic key) | Key derivation | — |
| Compressor (Dynamic deriver) | Key derivation | — |

## Security Properties

- **Uniqueness**: Each assembly gets a different cipher, preventing universal deobfuscation tools
- **Mathematical correctness**: Inverse operations are algebraically proven
- **Randomization**: Element selection, ordering, parameters, and post-processing shuffling all randomized
- **Obfuscation**: Post-processing transforms make the generated code harder to analyze

## dotscope Handling

Since every cipher is unique, pattern-matching is impossible. dotscope's CIL emulation engine executes DynCipher-generated code directly, making the specific cipher implementation irrelevant.
