# dotscope CLI

Command-line tool for .NET assembly analysis, inspection, and deobfuscation.

## Installation

```bash
# From the repository
cargo install --path dotscope-cli

# Or build directly
cargo build --release
# Binary at target/release/dotscope
```

## Quick Reference

| Command | Description |
|---------|-------------|
| `info` | Display assembly overview: name, version, runtime, entry point, and counts |
| `validate` | Validate assembly metadata at a chosen strictness level |
| `tables` | List metadata tables and row counts |
| `heaps` | Dump metadata heaps (strings, blob, guid, userstrings) |
| `attrs` | List decoded custom attributes grouped by owner |
| `types` | List type definitions |
| `methods` | List method definitions |
| `imports` | List assembly imports (TypeRef, MemberRef, native P/Invoke) |
| `exports` | List exported types and native PE exports |
| `disasm` | Disassemble CIL instructions (ildasm-style output) |
| `cfg` | Display control flow graph for a method |
| `callgraph` | Display inter-procedural call graph |
| `ssa` | Display SSA form of a method |
| `resources` | List or extract embedded resources |
| `detect` | Identify obfuscator without modifying the assembly |
| `deobfuscate` | Deobfuscate a .NET assembly |

## Global Options

```
--json     Emit output as JSON instead of human-readable text
-h, --help     Print help
-V, --version  Print version
```

All subcommands support `--json` for machine-readable output.

---

## Assembly Overview

### info

Display assembly metadata: name, version, runtime target, entry point, type/method/resource counts, and referenced assemblies.

```
$ dotscope info crafted_2.exe
Assembly:        crafted_2
Version:         1.2.3.4
Module:          crafted_2.exe
Runtime:         v4.0.30319
Entry point:     0x06000039
Hash algorithm:  SHA1
Assembly flags:  None
Machine:         i386
Subsystem:       Windows CUI
Characteristics: Executable, LargeAddressAware
COR flags:       ILOnly
Strong-named:    no
Types:           217
Methods:         97
Resources:       0
Assembly refs:   2

References:
  Name         Version
  mscorlib     4.0.0.0
  System.Core  4.0.0.0
```

### validate

Validate assembly metadata at a chosen strictness level.

```
$ dotscope validate crafted_2.exe
PASS  crafted_2.exe  (level: production)

$ dotscope validate --level strict crafted_2.exe
```

Levels: `minimal`, `production` (default), `comprehensive`, `strict`.

---

## Metadata Inspection

### tables

List metadata tables and their row counts.

```
$ dotscope tables crafted_2.exe
Table                   Rows
Module                     1
TypeRef                   65
TypeDef                   36
Field                     48
MethodDef                 97
Param                     72
InterfaceImpl              5
MemberRef                 67
Constant                   7
CustomAttribute           88
# ...
GenericParam              19
MethodSpec                 7
GenericParamConstraint    16
```

Filter to a specific table with `--table`:

```
$ dotscope tables --table TypeDef crafted_2.exe
```

### heaps

Dump metadata heaps: `strings`, `blob`, `guid`, `userstrings`.

```
$ dotscope heaps --heap strings crafted_2.exe
Offset    Value
0x000001  74F81FE167D99B4CB41D6D0CCDA82278CAEE9F3E2F25D5E5A3936FF3DCEC60D0
0x000042  <>c__DisplayClass0_0
0x000057  <Main>b__0
0x000062  <>9__0_1
0x00006b  <Main>b__0_1
0x000078  <>u__1
0x00007f  NestedGeneric`1
0x00008f  IEnumerable`1
# ...
```

Fetch a specific entry by offset with `--offset`:

```
$ dotscope heaps --heap strings --offset 0x14e crafted_2.exe
```

### attrs

List decoded custom attributes grouped by owner.

```
$ dotscope attrs crafted_2.exe
[module] 0x00000001
  UnverifiableCodeAttribute()
  RefSafetyRulesAttribute()
  DefaultCharSetAttribute(CharSet(3))

[assembly] crafted_2
  ExtensionAttribute()
  CompilationRelaxationsAttribute(8)
  RuntimeCompatibilityAttribute(WrapNonExceptionThrows = true)
  DebuggableAttribute(DebuggingModes(263))
  AssemblyTitleAttribute("MetadataTestCases")
  AssemblyDescriptionAttribute("Test assembly for CIL metadata reverse engineering")
  CLSCompliantAttribute(false)
  MetadataTestAttribute(42, "Test")

[type] Microsoft.CodeAnalysis.EmbeddedAttribute
  CompilerGeneratedAttribute()
  EmbeddedAttribute()
# ...
```

Filter by owner with `--owner` (token or name substring):

```
$ dotscope attrs --owner BaseClass crafted_2.exe
```

---

## Types & Members

### types

List type definitions with token, visibility, kind, and full name.

```
$ dotscope types crafted_2.exe
Token       Vis       Kind         Name
0x02000001  internal  class        <Module>
0x02000002  internal  class        Microsoft.CodeAnalysis.EmbeddedAttribute
0x02000003  internal  class        System.Runtime.CompilerServices.RefSafetyRulesAttribute
0x02000004  public    class        MetadataTestAttribute
0x02000005  public    class        Globals
0x02000006  public    interface    IBaseInterface
0x02000007  public    interface    IDerivedInterface
0x02000008  public    class        SimpleDelegate
0x02000009  public    class        GenericDelegate`2
0x0200000a  public    valuetype    TestEnum
0x0200000b  public    valuetype    StructWithExplicitLayout
0x0200000c  public    valuetype    GenericStruct`2
0x0200000d  public    class        BaseClass
0x0200000e  public    class        DerivedClass
# ...
```

Filter options: `--namespace`, `--public_only`.

### methods

List method definitions with token, access, declaring type, and name.

```
$ dotscope methods crafted_2.exe
Token       Access     Type                                                     Method
0x06000001  public     Microsoft.CodeAnalysis.EmbeddedAttribute                 .ctor
0x06000002  public     System.Runtime.CompilerServices.RefSafetyRulesAttribute  .ctor
0x06000003  public     MetadataTestAttribute                                    .ctor
0x06000004  public     MetadataTestAttribute                                    get_PropertyValue
0x06000005  public     MetadataTestAttribute                                    set_PropertyValue
0x06000008  public     Globals                                                  LoadLibrary
0x06000009  public     Globals                                                  MessageBox
0x0600000a  public     IBaseInterface                                           Method1
# ...
```

Filter options: `--type`, `--signatures`, `--group`.

### imports

List assembly imports: TypeRef, MemberRef, and native P/Invoke entries.

```
$ dotscope imports crafted_2.exe
CIL imports (66 entries):
  Token       Assembly     Name
  0x01000001  mscorlib     System.Runtime.CompilerServices.ExtensionAttribute
  0x01000002  mscorlib     System.Runtime.CompilerServices.CompilationRelaxationsAttribute
  0x01000003  mscorlib     System.Runtime.CompilerServices.RuntimeCompatibilityAttribute
  0x01000004  mscorlib     System.Diagnostics.DebuggableAttribute
  0x01000006  mscorlib     System.Reflection.AssemblyTitleAttribute
  # ...
```

### exports

List exported types and native PE exports.

```
$ dotscope exports crafted_2.exe
No exports found.
```

---

## Code Analysis

### disasm

Disassemble CIL instructions in ildasm-style output.

```
$ dotscope disasm --method "Program::Main" crafted_2.exe
.assembly 'crafted_2' {
  .ver 1:2:3:4
}
.module crafted_2.exe

  .method public hidebysig static void Main() cil managed
  {
    .entrypoint
    .maxstack 3
    .locals init (
      [0] <>c__DisplayClass0_0 V_0,
      [1] DerivedClass V_1,
      [2] array V_2,
      # ...
    )
    IL_0000: newobj       <>c__DisplayClass0_0::.ctor
    IL_0005: stloc.0
    IL_0006: nop
    IL_0007: ldstr        "Hello Metadata World!"
    IL_000c: call         System.Console::WriteLine
    IL_0011: nop
    IL_0012: newobj       DerivedClass::.ctor
    IL_0017: stloc.1
    IL_0018: ldloc.1
    IL_0019: callvirt     BaseClass::VirtualMethod
    # ...
    IL_00fd: ret
  } // end of method Main
```

Options: `--method <TOKEN|NAME>`, `--type <TOKEN|NAME>`, `--bytes`, `--tokens`, `--no-offsets`, `--no-header`, `--raw`, `--deobfuscate`.

### cfg

Display control flow graph for a method.

```
$ dotscope cfg --method "Program::Main" crafted_2.exe
Control flow graph for Main (0x06000039)
Blocks: 12, Entry: B0, Exits: B11

Block  Instructions  Successors  Edge types
B0               49  B4, B1      conditional_true -> B4, conditional_false -> B1
B1                1  B2          unconditional -> B2
B2                3  B5, B3      conditional_true -> B5, conditional_false -> B3
B3                1  B6          unconditional -> B6
B6                3  B7          unconditional -> B7
B5                3  B7          unconditional -> B7
B4                3  B7          unconditional -> B7
B7                6  B9, B8      conditional_true -> B9, conditional_false -> B8
B8                6  B9          unconditional -> B9
B9                4  B11, B10    conditional_true -> B11, conditional_false -> B10
B10               6  B11         unconditional -> B11
B11               4  (exit)      (exit)
```

Formats: `text` (default), `dot` (Graphviz), `json`. Add `--loops` for loop analysis.

### ssa

Display SSA (Static Single Assignment) form of a method.

```
$ dotscope ssa --method "BaseClass::ComplexMethod" crafted_2.exe
SSA for ComplexMethod (0x0600001B)
  Variables: 9
  Blocks: 2

B0:
  nop
  nop
  v16 = 42
  stind.i32 v12, v16
  nop
  v17 = v10
  jump B1
B1:
  nop
  ret v17
```

Options: `--show-phis`, `--show-types`.

### callgraph

Display inter-procedural call graph.

```
$ dotscope callgraph --root "Program::Main" crafted_2.exe
Call graph: 29 methods, 29 edges
Entry points: Program::Main
Recursive methods: none

Method                                                                           Callees
Program::Main (0x06000039)                                                       <>c__DisplayClass0_0::.ctor, System.Console::WriteLine, DerivedClass::.ctor, BaseClass::VirtualMethod, DerivedClass::VirtualMethod, DerivedClass::AsyncMethod, ...
DerivedClass::AsyncMethod (0x0600002D)                                           <AsyncMethod>d__22::.ctor, AsyncTaskMethodBuilder`1::Create, AsyncTaskMethodBuilder`1::Start, AsyncTaskMethodBuilder`1::get_Task
DerivedClass::VirtualMethod (0x06000024)                                         BaseClass::VirtualMethod
DerivedClass::.ctor (0x06000030)                                                 BaseClass::.ctor
BaseClass::.ctor (0x0600001F)                                                    System.Object::.ctor
<>c__DisplayClass0_0::<Main>b__0 (0x0600005A)                                    System.Console::WriteLine
# ...
```

Options: `--format` (`text`, `dot`, `json`), `--root`, `--depth`.

---

## Resources

### resources

List or extract embedded resources.

```
$ dotscope resources crafted_2.exe
No resources found.

$ dotscope resources --extract --output-dir ./out assembly.exe
```

Options: `--extract`, `--output-dir`, `--name`.

---

## Obfuscation Analysis

### detect

Identify obfuscator without modifying the assembly.

```
$ dotscope detect crafted_2.exe
crafted_2.exe: no known obfuscator detected

$ dotscope detect mkaring_maximum.exe
mkaring_maximum.exe: ConfuserEx (confidence: very high, score: 205)
  Evidence:
    - attr:System.Runtime.CompilerServices.SuppressIldasmAttribute (confidence: 25)
    - attr:ConfusedByAttribute (confidence: 50)
    - metadata:Constant decryptor methods (5 with signature string(int32) or T(int32))x5 (confidence: 30)
    - bytecode:ConfuserEx anti-tamper (Normal mode, 2 methods)x2 (confidence: 50)
    - encrypted:64 methods (confidence: 50)
    - artifact sections:2 (confidence: 5)
    - constant data:2 fields, 2 types (confidence: 15)
    - Found 9 types as protection infrastructure:9 (confidence: 20)
    - Found 1 fields in <Module> as protection infrastructure:1 (confidence: 15)
```

Supports `--recursive` for scanning directories.

### deobfuscate

Deobfuscate a .NET assembly. Decrypts strings, restores control flow, removes anti-tamper, and cleans up obfuscator artifacts.

```
$ dotscope deobfuscate --stats -o cleaned.exe obfuscated.exe
Deobfuscation complete: obfuscated.exe -> cleaned.exe
  Obfuscator:  ConfuserEx (score: 205)
  Constants:   152 folded, 40 decrypted
  Methods:     98 transformed, 94 regenerated
  Dead code:   6199 instructions, 919 blocks removed
  Artifacts:   77 removed
  Iterations:  6
  Time:        10.1s
```

Options: `-o`, `--suffix`, `--recursive`, `--max-iterations`, `--max-instructions`, `--no-cleanup`, `--aggressive`, `--stats`, `--report`.

---

## ConfuserEx Deobfuscation Showcase

End-to-end demonstration using a ConfuserEx "Maximum" protection sample. This assembly has anti-tamper, constant encryption, control flow obfuscation, and name mangling all applied simultaneously.

### Before: Obfuscated State

**Detection** identifies ConfuserEx with high confidence:

```
$ dotscope detect mkaring_maximum.exe
mkaring_maximum.exe: ConfuserEx (confidence: very high, score: 205)
  Evidence:
    - attr:ConfusedByAttribute (confidence: 50)
    - bytecode:ConfuserEx anti-tamper (Normal mode, 2 methods)x2 (confidence: 50)
    - encrypted:64 methods (confidence: 50)
    # ...
```

**Assembly overview** shows inflated type/method counts from injected obfuscator infrastructure:

```
$ dotscope info mkaring_maximum.exe
Assembly:        TestApp
Version:         0.0.0.0
Module:          TestApp.exe
Types:           122
Methods:         98
```

**Types** are renamed to invisible Unicode characters:

```
$ dotscope types mkaring_maximum.exe
Token       Vis       Kind         Name
0x02000001  internal  class        <Module>
0x02000002  internal  valuetype    ‪‬⁭‬‫⁪‮⁮‍⁪⁫⁫⁪⁫⁯‬⁯‍‏⁯‎‭‬‌‭‌‬‭⁮‫‌⁭‭‎‭‭‫⁪‏‮‮
0x02000003  internal  valuetype    ⁪⁫‌‌‍‍‍⁬‎‭⁮⁯‍‬⁮‪⁮‍‬‮‪⁭⁯⁯‬‌⁮‏‌⁮‪⁭⁮⁪⁯​⁪‭‭‮
0x02000004  internal  class        ⁬‫‮‍‬⁭‬⁫‬⁮‫​‍‍‪⁮⁬‫⁬⁭⁪⁭‍⁬‎⁮‌⁯‎⁯‬‍‪​⁪⁪‌‏‪‭‮
# ...
0x02000012  internal  class        ConfusedByAttribute
```

**Entry point** has an encrypted body — only the shell remains:

```
$ dotscope disasm --method 0x0600003f mkaring_maximum.exe
  .method private hidebysig static void ‮‌‭⁯‌‍‍⁪⁬⁬⁪‎‎‏‌‪‭‮‌⁫‭‌‍‪‏‍⁭‮⁪⁯⁭⁯‮⁪⁫⁭‭⁮‎‪‮(string[]) cil managed
  {
    .entrypoint
    .maxstack 8
  } // end of method ‮‌‭⁯‌‍‍⁪⁬⁬⁪‎‎‏‌‪‭‮‌⁫‭‌‍‪‏‍⁭‮⁪⁯⁭⁯‮⁪⁫⁭‭⁮‎‪‮
```

### Deobfuscation

```
$ dotscope deobfuscate --stats -o mkaring_clean.exe mkaring_maximum.exe
Deobfuscation complete: mkaring_maximum.exe -> mkaring_clean.exe
  Obfuscator:  ConfuserEx (score: 205)
  Constants:   152 folded, 40 decrypted
  Methods:     98 transformed, 94 regenerated
  Dead code:   6199 instructions, 919 blocks removed
  Artifacts:   77 removed
  Iterations:  6
  Time:        10.1s
```

### After: Deobfuscated Output

**Assembly overview** shows reduced counts after obfuscator infrastructure removal:

```
$ dotscope info mkaring_clean.exe
Assembly:        TestApp
Version:         0.0.0.0
Module:          TestApp.exe
Types:           47
Methods:         37
```

**Types** are clean — obfuscator scaffolding is gone:

```
$ dotscope types mkaring_clean.exe
Token       Vis       Kind         Name
0x02000001  internal  class        <Module>
0x02000002  internal  class        L
0x02000003  internal  class        M
0x02000004  internal  class        N
0x02000005  internal  class        O
0x02000006  internal  class        P
```

**Methods** show readable names and proper structure:

```
$ dotscope methods mkaring_clean.exe
Token       Access              Type      Method
0x06000001  private             <Module>  .cctor
0x06000002  public              L         .ctor
0x06000003  private             L         bc
0x06000004  compilercontrolled  L         bd
0x06000005  compilercontrolled  L         be
0x06000006  compilercontrolled  L         bf
0x06000007  public              M         .ctor
0x06000008  public              M         bg
0x06000009  public              M         bh
# ...

37 method(s) listed.
```

**Entry point** now has fully restored IL with decrypted strings and clean control flow:

```
$ dotscope disasm --method 0x06000003 mkaring_clean.exe
  .method private hidebysig static void bc(string[]) cil managed
  {
    .entrypoint
    .maxstack 4
    .locals init (
      [0] M V_0,
      [1] N V_1,
      [2] O V_2,
      [3] P V_3
    )
    IL_0000: ldstr        "=== ConfuserEx Test App ==="
    IL_0005: call         L::bd
    IL_000a: call         L::be
    IL_000f: ldstr        "World"
    IL_0014: newobj       M::.ctor
    IL_0019: stloc.0
    IL_001a: ldloc.0
    IL_001b: callvirt     M::bg
    IL_0020: ldloc.0
    IL_0021: callvirt     M::bh
    IL_0026: newobj       N::.ctor
    IL_002b: stloc.1
    IL_002c: call         L::be
    IL_0031: ldstr        "--- Math Operations ---"
    IL_0036: call         L::bd
    # ...
    IL_016f: ldstr        "=== Done ==="
    IL_0174: call         L::bd
    IL_0179: ret
  } // end of method bc
```

### Comparison

| Metric | Before | After |
|--------|--------|-------|
| Types | 122 | 47 |
| Methods | 98 | 37 |
| Encrypted methods | 64 | 0 |
| Dead instructions removed | — | 6,199 |
| Dead blocks removed | — | 919 |
| Artifacts removed | — | 77 |
| Constants decrypted | — | 40 |
| String literals visible | no | yes |
| Readable type/method names | no | yes |
