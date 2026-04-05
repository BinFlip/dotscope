# Type Scrambler Protection

| Property | Value |
|----------|-------|
| **ID** | `BahNahNah.typescramble` |
| **Short ID** | `typescramble` |
| **Preset** | None (must be explicitly enabled) |
| **Targets** | Types, Methods, Fields |
| **Pipeline Stages** | AnalyzePhase: PreStage Inspection; ScramblePhase: PostStage ProcessModule |
| **Dependencies** | None |

## Overview

Replaces concrete type references with generic type parameters throughout the assembly. This obscures the actual types being used, making decompiled code extremely confusing — every concrete type appears as an opaque generic parameter. This is a community-contributed protection (prefix `BahNahNah` indicates external origin).

## Configuration

No configuration parameters (beyond enable/disable).

## Architecture

### Phase 1: AnalyzePhase

Scans all types and methods to determine what can be scrambled.

**ScannedType analysis**:
- Registers field types as generic parameter candidates
- Skips: enums, ComImport types, delegate types, value types

**ScannedMethod analysis**:
- Registers parameter types, return types, and local variable types as candidates
- Skips methods that:
  - Are entry points
  - Have P/Invoke declarations
  - Are abstract or virtual (including overrides)
  - Are constructors, getters, or setters
  - Are in types that already have generic parameters
  - Have overloaded signatures in the same type
  - Implement interface methods
  - Are in delegate, ComImport, or global types
  - Are publicly visible (unless explicitly configured)

### Phase 2: ScramblePhase

Applies the generic parameter substitution.

**Generic parameter registration**:
For each eligible type/method, `RegisterGeneric(TypeSig)` collects unique types:
- Creates `GenericParamUser` with names T0, T1, T2, etc.
- Maintains mapping: `original TypeSig → GenericParam`

**Type conversion**:
`ConvertToGenericIfAvailable(TypeSig)`:
1. Extract leaf type (strip array, pointer, byref modifiers)
2. Look up in `Generics` dictionary
3. If found, replace with `GenericVar` (for type parameters) or `GenericMVar` (for method parameters)
4. Copy all modifiers (array rank, byref, custom modifiers) to the generic reference

### Instruction Rewriting

The `TypeRewriter` processes all instructions using specialized rewriters:
- **TypeRefRewriter**: Rewrites TypeRef operands
- **TypeDefRewriter**: Rewrites TypeDef operands
- **FieldDefRewriter**: Rewrites field reference operands
- **MethodDefRewriter**: Rewrites method reference operands
- **MemberRefRewriter**: Rewrites MemberRef operands
- **MethodSpecRewriter**: Rewrites generic method instantiations

All local variable types, parameter types, and return types are also updated.

## Transformation Example

```csharp
// Original
class MyClass {
    private string _name;
    private int _count;

    void Process(string input, List<int> data) {
        string result = input.ToUpper();
        int length = result.Length;
    }
}

// After Type Scrambling
class MyClass<T0, T1> {          // T0=string, T1=int
    private T0 _name;
    private T1 _count;

    void Process<T2, T3>(T2 input, T3 data) {   // T2=string, T3=List<int>
        T2 result = input.ToUpper();             // T2 used for string
        T1 length = result.Length;               // T1 used for int
    }
}
```

All call sites must be updated to provide the correct generic arguments:
```csharp
// Original
obj.Process("hello", myList);

// After scrambling
obj.Process<string, List<int>>("hello", myList);
```

## Semantic Preservation

- Generic parameters have the same constraints as original types
- IL semantics are preserved (generics maintain inheritance)
- Runtime type relationships are maintained through generic instantiation
- The transformation is purely syntactic — no behavioral change

## Limitations

- Does not scramble publicly visible APIs (would break external callers)
- Cannot scramble virtual/abstract methods (would break polymorphism)
- Cannot scramble types already using generics (would conflict)
- Interface method implementations must maintain exact signatures
- Value types cannot be scrambled (boxing semantics differ)

## dotscope Handling

Not yet implemented. Uncommon in practice (Preset: None, community-contributed). Call sites contain the concrete generic arguments needed for reversal if support is added.
