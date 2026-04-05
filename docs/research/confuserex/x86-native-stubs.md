# ConfuserEx x86 Native Stubs

> See also: [DynCipher](dynciper.md) for how stubs are generated, [Control Flow](control-flow.md) for x86 predicates, [Constants](constants.md) for x86 encoding mode.

Extracted from test samples. All stubs share these properties:
- **Declaring type**: `<Module>`
- **Signature**: `int(int)` (single i32 argument, returns i32)
- **Prologue**: DynCipher (20 bytes) calling convention adapter
- **Structure**: Single basic block, no branches
- **SSA**: All translate to SSA successfully (1 block)

## DynCipher Prologue

All stubs share this 20-byte prologue:
```
89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10 50 eb 01 51
```

---

## Sample 1: mkaring_constants_x86.exe

Constants encryption with x86 native cipher. 5 stubs.

### Stub 1 — Token 0x06000005

| Field | Value |
|---|---|
| Token | `0x06000005` |
| RVA | `0x000045c0` |
| File offset | `0x000027c0` |
| Body size | 20 bytes |
| Total size | 40 bytes |
| Instructions | 11 |

Full bytes (40 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 06 13 a4 66 f7 d1 29 c8 f7 d8
0020: f7 d0 f7 d8 5e 5f 5b c3
```

Body bytes (20 bytes, without prologue):
```
0000: 58 b9 06 13 a4 66 f7 d1 29 c8 f7 d8 f7 d0 f7 d8
0010: 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b90613a466           Mov { dst: Register(Ecx), src: Immediate(1722028806) }
0006: f7d1                 Not { dst: Register(Ecx) }
0008: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
000a: f7d8                 Neg { dst: Register(Eax) }
000c: f7d0                 Not { dst: Register(Eax) }
000e: f7d8                 Neg { dst: Register(Eax) }
0010: 5e                   Pop { dst: Esi }
0011: 5f                   Pop { dst: Edi }
0012: 5b                   Pop { dst: Ebx }
0013: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v7, value: I32(1722028806) }
Block 0: Not { dest: v8, operand: v7 }
Block 0: Sub { dest: v9, left: v0, right: v8 }
Block 0: Clt { dest: v10, left: v0, right: v8, unsigned: true }
Block 0: Neg { dest: v11, operand: v9 }
Block 0: Const { dest: v12, value: I32(0) }
Block 0: Ceq { dest: v13, left: v9, right: v12 }
Block 0: Const { dest: v14, value: I32(1) }
Block 0: Xor { dest: v15, left: v13, right: v14 }
Block 0: Not { dest: v16, operand: v11 }
Block 0: Neg { dest: v17, operand: v16 }
Block 0: Const { dest: v18, value: I32(0) }
Block 0: Ceq { dest: v19, left: v16, right: v18 }
Block 0: Const { dest: v20, value: I32(1) }
Block 0: Xor { dest: v21, left: v19, right: v20 }
Block 0: Return { value: Some(v17) }
```

### Stub 2 — Token 0x06000007

| Field | Value |
|---|---|
| Token | `0x06000007` |
| RVA | `0x000045e8` |
| File offset | `0x000027e8` |
| Body size | 19 bytes |
| Total size | 39 bytes |
| Instructions | 8 |

Full bytes (39 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 69 c0 0b 5c 1c b1 69 c0 27 dc ae
0020: 1a f7 d0 5e 5f 5b c3
```

Body bytes (19 bytes, without prologue):
```
0000: 58 69 c0 0b 5c 1c b1 69 c0 27 dc ae 1a f7 d0 5e
0010: 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: 69c00b5c1cb1         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-1323541493)) }
0007: 69c027dcae1a         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(447667239)) }
000d: f7d0                 Not { dst: Register(Eax) }
000f: 5e                   Pop { dst: Esi }
0010: 5f                   Pop { dst: Edi }
0011: 5b                   Pop { dst: Ebx }
0012: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v32, value: I32(-1323541493) }
Block 0: Mul { dest: v33, left: v25, right: v32 }
Block 0: Const { dest: v34, value: I32(447667239) }
Block 0: Mul { dest: v35, left: v33, right: v34 }
Block 0: Not { dest: v36, operand: v35 }
Block 0: Return { value: Some(v36) }
```

### Stub 3 — Token 0x06000009

| Field | Value |
|---|---|
| Token | `0x06000009` |
| RVA | `0x00004610` |
| File offset | `0x00002810` |
| Body size | 52 bytes |
| Total size | 72 bytes |
| Instructions | 18 |

Full bytes (72 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 b8 65 11 90 52 81 f0 ab 5d fc f5 f7
0020: d0 b9 10 3c 13 f3 f7 d1 ba 8c e0 c2 76 81 f2 b7
0030: 0a 54 5b 31 d1 31 c8 59 29 c8 f7 d0 69 c0 85 46
0040: 7b d6 f7 d8 5e 5f 5b c3
```

Body bytes (52 bytes, without prologue):
```
0000: b8 65 11 90 52 81 f0 ab 5d fc f5 f7 d0 b9 10 3c
0010: 13 f3 f7 d1 ba 8c e0 c2 76 81 f2 b7 0a 54 5b 31
0020: d1 31 c8 59 29 c8 f7 d0 69 c0 85 46 7b d6 f7 d8
0030: 5e 5f 5b c3
```

Disassembly:
```
0000: b865119052           Mov { dst: Register(Eax), src: Immediate(1385173349) }
0005: 81f0ab5dfcf5         Xor { dst: Register(Eax), src: Immediate(-168010325) }
000b: f7d0                 Not { dst: Register(Eax) }
000d: b9103c13f3           Mov { dst: Register(Ecx), src: Immediate(-216843248) }
0012: f7d1                 Not { dst: Register(Ecx) }
0014: ba8ce0c276           Mov { dst: Register(Edx), src: Immediate(1992482956) }
0019: 81f2b70a545b         Xor { dst: Register(Edx), src: Immediate(1532234423) }
001f: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0021: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0023: 59                   Pop { dst: Ecx }
0024: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0026: f7d0                 Not { dst: Register(Eax) }
0028: 69c085467bd6         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-696564091)) }
002e: f7d8                 Neg { dst: Register(Eax) }
0030: 5e                   Pop { dst: Esi }
0031: 5f                   Pop { dst: Edi }
0032: 5b                   Pop { dst: Ebx }
0033: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v47, value: I32(1385173349) }
Block 0: Const { dest: v48, value: I32(-168010325) }
Block 0: Xor { dest: v49, left: v47, right: v48 }
Block 0: Const { dest: v50, value: I32(0) }
Block 0: Not { dest: v51, operand: v49 }
Block 0: Const { dest: v52, value: I32(-216843248) }
Block 0: Not { dest: v53, operand: v52 }
Block 0: Const { dest: v54, value: I32(1992482956) }
Block 0: Const { dest: v55, value: I32(1532234423) }
Block 0: Xor { dest: v56, left: v54, right: v55 }
Block 0: Const { dest: v57, value: I32(0) }
Block 0: Xor { dest: v58, left: v53, right: v56 }
Block 0: Const { dest: v59, value: I32(0) }
Block 0: Xor { dest: v60, left: v51, right: v58 }
Block 0: Const { dest: v61, value: I32(0) }
Block 0: Sub { dest: v62, left: v60, right: v40 }
Block 0: Clt { dest: v63, left: v60, right: v40, unsigned: true }
Block 0: Not { dest: v64, operand: v62 }
Block 0: Const { dest: v65, value: I32(-696564091) }
Block 0: Mul { dest: v66, left: v64, right: v65 }
Block 0: Neg { dest: v67, operand: v66 }
Block 0: Const { dest: v68, value: I32(0) }
Block 0: Ceq { dest: v69, left: v66, right: v68 }
Block 0: Const { dest: v70, value: I32(1) }
Block 0: Xor { dest: v71, left: v69, right: v70 }
Block 0: Return { value: Some(v67) }
```

### Stub 4 — Token 0x0600000b

| Field | Value |
|---|---|
| Token | `0x0600000b` |
| RVA | `0x00004658` |
| File offset | `0x00002858` |
| Body size | 65 bytes |
| Total size | 85 bytes |
| Instructions | 21 |

Full bytes (85 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 0b 93 fa 54 69 c9 c2 db 0b 86
0020: ba 2a 4d b9 08 f7 d2 29 d1 ba 60 ba 13 6b 81 c2
0030: 3b 3c 0a a8 bb 0f 21 1d 20 81 eb 1a be fe bf 31
0040: da 01 d1 31 c8 f7 d8 f7 d8 f7 d8 81 c0 2a 31 25
0050: 77 5e 5f 5b c3
```

Body bytes (65 bytes, without prologue):
```
0000: 58 b9 0b 93 fa 54 69 c9 c2 db 0b 86 ba 2a 4d b9
0010: 08 f7 d2 29 d1 ba 60 ba 13 6b 81 c2 3b 3c 0a a8
0020: bb 0f 21 1d 20 81 eb 1a be fe bf 31 da 01 d1 31
0030: c8 f7 d8 f7 d8 f7 d8 81 c0 2a 31 25 77 5e 5f 5b
0040: c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b90b93fa54           Mov { dst: Register(Ecx), src: Immediate(1425707787) }
0006: 69c9c2db0b86         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-2046043198)) }
000c: ba2a4db908           Mov { dst: Register(Edx), src: Immediate(146361642) }
0011: f7d2                 Not { dst: Register(Edx) }
0013: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0015: ba60ba136b           Mov { dst: Register(Edx), src: Immediate(1796455008) }
001a: 81c23b3c0aa8         Add { dst: Register(Edx), src: Immediate(-1475724229) }
0020: bb0f211d20           Mov { dst: Register(Ebx), src: Immediate(538779919) }
0025: 81eb1abefebf         Sub { dst: Register(Ebx), src: Immediate(-1073824230) }
002b: 31da                 Xor { dst: Register(Edx), src: Register(Ebx) }
002d: 01d1                 Add { dst: Register(Ecx), src: Register(Edx) }
002f: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0031: f7d8                 Neg { dst: Register(Eax) }
0033: f7d8                 Neg { dst: Register(Eax) }
0035: f7d8                 Neg { dst: Register(Eax) }
0037: 81c02a312577         Add { dst: Register(Eax), src: Immediate(1998926122) }
003d: 5e                   Pop { dst: Esi }
003e: 5f                   Pop { dst: Edi }
003f: 5b                   Pop { dst: Ebx }
0040: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v82, value: I32(1425707787) }
Block 0: Const { dest: v83, value: I32(-2046043198) }
Block 0: Mul { dest: v84, left: v82, right: v83 }
Block 0: Const { dest: v85, value: I32(146361642) }
Block 0: Not { dest: v86, operand: v85 }
Block 0: Sub { dest: v87, left: v84, right: v86 }
Block 0: Clt { dest: v88, left: v84, right: v86, unsigned: true }
Block 0: Const { dest: v89, value: I32(1796455008) }
Block 0: Const { dest: v90, value: I32(-1475724229) }
Block 0: Add { dest: v91, left: v89, right: v90 }
Block 0: Clt { dest: v92, left: v91, right: v89, unsigned: true }
Block 0: Const { dest: v93, value: I32(538779919) }
Block 0: Const { dest: v94, value: I32(-1073824230) }
Block 0: Sub { dest: v95, left: v93, right: v94 }
Block 0: Clt { dest: v96, left: v93, right: v94, unsigned: true }
Block 0: Xor { dest: v97, left: v91, right: v95 }
Block 0: Const { dest: v98, value: I32(0) }
Block 0: Add { dest: v99, left: v87, right: v97 }
Block 0: Clt { dest: v100, left: v99, right: v87, unsigned: true }
Block 0: Xor { dest: v101, left: v75, right: v99 }
Block 0: Const { dest: v102, value: I32(0) }
Block 0: Neg { dest: v103, operand: v101 }
Block 0: Const { dest: v104, value: I32(0) }
Block 0: Ceq { dest: v105, left: v101, right: v104 }
Block 0: Const { dest: v106, value: I32(1) }
Block 0: Xor { dest: v107, left: v105, right: v106 }
Block 0: Neg { dest: v108, operand: v103 }
Block 0: Const { dest: v109, value: I32(0) }
Block 0: Ceq { dest: v110, left: v103, right: v109 }
Block 0: Const { dest: v111, value: I32(1) }
Block 0: Xor { dest: v112, left: v110, right: v111 }
Block 0: Neg { dest: v113, operand: v108 }
Block 0: Const { dest: v114, value: I32(0) }
Block 0: Ceq { dest: v115, left: v108, right: v114 }
Block 0: Const { dest: v116, value: I32(1) }
Block 0: Xor { dest: v117, left: v115, right: v116 }
Block 0: Const { dest: v118, value: I32(1998926122) }
Block 0: Add { dest: v119, left: v113, right: v118 }
Block 0: Clt { dest: v120, left: v119, right: v113, unsigned: true }
Block 0: Return { value: Some(v119) }
```

### Stub 5 — Token 0x0600000d

| Field | Value |
|---|---|
| Token | `0x0600000d` |
| RVA | `0x000046b0` |
| File offset | `0x000028b0` |
| Body size | 68 bytes |
| Total size | 88 bytes |
| Instructions | 21 |

Full bytes (88 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 3c 00 4b 1c f7 d9 ba 95 e8 42
0020: a3 81 c2 1f 9a b2 98 01 d1 ba 07 26 c8 f2 81 ea
0030: 94 73 30 06 bb 54 86 01 cf 81 f3 1a ff 27 be 29
0040: da 01 d1 29 c8 f7 d0 b9 bf 53 e5 fb 69 c9 ec 60
0050: 56 0c 29 c8 5e 5f 5b c3
```

Body bytes (68 bytes, without prologue):
```
0000: 58 b9 3c 00 4b 1c f7 d9 ba 95 e8 42 a3 81 c2 1f
0010: 9a b2 98 01 d1 ba 07 26 c8 f2 81 ea 94 73 30 06
0020: bb 54 86 01 cf 81 f3 1a ff 27 be 29 da 01 d1 29
0030: c8 f7 d0 b9 bf 53 e5 fb 69 c9 ec 60 56 0c 29 c8
0040: 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b93c004b1c           Mov { dst: Register(Ecx), src: Immediate(474677308) }
0006: f7d9                 Neg { dst: Register(Ecx) }
0008: ba95e842a3           Mov { dst: Register(Edx), src: Immediate(-1555896171) }
000d: 81c21f9ab298         Add { dst: Register(Edx), src: Immediate(-1733125601) }
0013: 01d1                 Add { dst: Register(Ecx), src: Register(Edx) }
0015: ba0726c8f2           Mov { dst: Register(Edx), src: Immediate(-221764089) }
001a: 81ea94733006         Sub { dst: Register(Edx), src: Immediate(103838612) }
0020: bb548601cf           Mov { dst: Register(Ebx), src: Immediate(-821983660) }
0025: 81f31aff27be         Xor { dst: Register(Ebx), src: Immediate(-1104675046) }
002b: 29da                 Sub { dst: Register(Edx), src: Register(Ebx) }
002d: 01d1                 Add { dst: Register(Ecx), src: Register(Edx) }
002f: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0031: f7d0                 Not { dst: Register(Eax) }
0033: b9bf53e5fb           Mov { dst: Register(Ecx), src: Immediate(-68856897) }
0038: 69c9ec60560c         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(206987500)) }
003e: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0040: 5e                   Pop { dst: Esi }
0041: 5f                   Pop { dst: Edi }
0042: 5b                   Pop { dst: Ebx }
0043: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v131, value: I32(474677308) }
Block 0: Neg { dest: v132, operand: v131 }
Block 0: Const { dest: v133, value: I32(0) }
Block 0: Ceq { dest: v134, left: v131, right: v133 }
Block 0: Const { dest: v135, value: I32(1) }
Block 0: Xor { dest: v136, left: v134, right: v135 }
Block 0: Const { dest: v137, value: I32(-1555896171) }
Block 0: Const { dest: v138, value: I32(-1733125601) }
Block 0: Add { dest: v139, left: v137, right: v138 }
Block 0: Clt { dest: v140, left: v139, right: v137, unsigned: true }
Block 0: Add { dest: v141, left: v132, right: v139 }
Block 0: Clt { dest: v142, left: v141, right: v132, unsigned: true }
Block 0: Const { dest: v143, value: I32(-221764089) }
Block 0: Const { dest: v144, value: I32(103838612) }
Block 0: Sub { dest: v145, left: v143, right: v144 }
Block 0: Clt { dest: v146, left: v143, right: v144, unsigned: true }
Block 0: Const { dest: v147, value: I32(-821983660) }
Block 0: Const { dest: v148, value: I32(-1104675046) }
Block 0: Xor { dest: v149, left: v147, right: v148 }
Block 0: Const { dest: v150, value: I32(0) }
Block 0: Sub { dest: v151, left: v145, right: v149 }
Block 0: Clt { dest: v152, left: v145, right: v149, unsigned: true }
Block 0: Add { dest: v153, left: v141, right: v151 }
Block 0: Clt { dest: v154, left: v153, right: v141, unsigned: true }
Block 0: Sub { dest: v155, left: v124, right: v153 }
Block 0: Clt { dest: v156, left: v124, right: v153, unsigned: true }
Block 0: Not { dest: v157, operand: v155 }
Block 0: Const { dest: v158, value: I32(-68856897) }
Block 0: Const { dest: v159, value: I32(206987500) }
Block 0: Mul { dest: v160, left: v158, right: v159 }
Block 0: Sub { dest: v161, left: v157, right: v160 }
Block 0: Clt { dest: v162, left: v157, right: v160, unsigned: true }
Block 0: Return { value: Some(v161) }
```

---

## Sample 2: mkaring_controlflow_x86.exe

Control flow obfuscation with x86 native predicate. 4 stubs.

### Stub 6 — Token 0x06000002

| Field | Value |
|---|---|
| Token | `0x06000002` |
| RVA | `0x00002a10` |
| File offset | `0x00000c10` |
| Body size | 34 bytes |
| Total size | 54 bytes |
| Instructions | 12 |

Full bytes (54 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 70 92 47 1d 69 c9 db 75 70 90
0020: f7 d9 31 c8 f7 d0 69 c0 e7 21 f0 0a 81 f0 df 98
0030: 2b 69 5e 5f 5b c3
```

Body bytes (34 bytes, without prologue):
```
0000: 58 b9 70 92 47 1d 69 c9 db 75 70 90 f7 d9 31 c8
0010: f7 d0 69 c0 e7 21 f0 0a 81 f0 df 98 2b 69 5e 5f
0020: 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b97092471d           Mov { dst: Register(Ecx), src: Immediate(491229808) }
0006: 69c9db757090         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-1871677989)) }
000c: f7d9                 Neg { dst: Register(Ecx) }
000e: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0010: f7d0                 Not { dst: Register(Eax) }
0012: 69c0e721f00a         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(183509479)) }
0018: 81f0df982b69         Xor { dst: Register(Eax), src: Immediate(1764464863) }
001e: 5e                   Pop { dst: Esi }
001f: 5f                   Pop { dst: Edi }
0020: 5b                   Pop { dst: Ebx }
0021: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v173, value: I32(491229808) }
Block 0: Const { dest: v174, value: I32(-1871677989) }
Block 0: Mul { dest: v175, left: v173, right: v174 }
Block 0: Neg { dest: v176, operand: v175 }
Block 0: Const { dest: v177, value: I32(0) }
Block 0: Ceq { dest: v178, left: v175, right: v177 }
Block 0: Const { dest: v179, value: I32(1) }
Block 0: Xor { dest: v180, left: v178, right: v179 }
Block 0: Xor { dest: v181, left: v166, right: v176 }
Block 0: Const { dest: v182, value: I32(0) }
Block 0: Not { dest: v183, operand: v181 }
Block 0: Const { dest: v184, value: I32(183509479) }
Block 0: Mul { dest: v185, left: v183, right: v184 }
Block 0: Const { dest: v186, value: I32(1764464863) }
Block 0: Xor { dest: v187, left: v185, right: v186 }
Block 0: Const { dest: v188, value: I32(0) }
Block 0: Return { value: Some(v187) }
```

### Stub 7 — Token 0x06000003

| Field | Value |
|---|---|
| Token | `0x06000003` |
| RVA | `0x00002a48` |
| File offset | `0x00000c48` |
| Body size | 50 bytes |
| Total size | 70 bytes |
| Instructions | 17 |

Full bytes (70 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d8 b9 c9 0e ab d8 69 c9 7f b6
0020: f6 97 ba bf 02 bb e1 f7 da 29 d1 31 c8 b9 1d 12
0030: 7e a3 81 f1 c3 13 ec cf 01 c8 f7 d8 81 c0 12 52
0040: 44 18 5e 5f 5b c3
```

Body bytes (50 bytes, without prologue):
```
0000: 58 f7 d8 b9 c9 0e ab d8 69 c9 7f b6 f6 97 ba bf
0010: 02 bb e1 f7 da 29 d1 31 c8 b9 1d 12 7e a3 81 f1
0020: c3 13 ec cf 01 c8 f7 d8 81 c0 12 52 44 18 5e 5f
0030: 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d8                 Neg { dst: Register(Eax) }
0003: b9c90eabd8           Mov { dst: Register(Ecx), src: Immediate(-659878199) }
0008: 69c97fb6f697         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-1745439105)) }
000e: babf02bbe1           Mov { dst: Register(Edx), src: Immediate(-507837761) }
0013: f7da                 Neg { dst: Register(Edx) }
0015: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0017: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0019: b91d127ea3           Mov { dst: Register(Ecx), src: Immediate(-1552018915) }
001e: 81f1c313eccf         Xor { dst: Register(Ecx), src: Immediate(-806612029) }
0024: 01c8                 Add { dst: Register(Eax), src: Register(Ecx) }
0026: f7d8                 Neg { dst: Register(Eax) }
0028: 81c012524418         Add { dst: Register(Eax), src: Immediate(407130642) }
002e: 5e                   Pop { dst: Esi }
002f: 5f                   Pop { dst: Edi }
0030: 5b                   Pop { dst: Ebx }
0031: c3                   Ret
```

SSA translation:
```
Block 0: Neg { dest: v199, operand: v192 }
Block 0: Const { dest: v200, value: I32(0) }
Block 0: Ceq { dest: v201, left: v192, right: v200 }
Block 0: Const { dest: v202, value: I32(1) }
Block 0: Xor { dest: v203, left: v201, right: v202 }
Block 0: Const { dest: v204, value: I32(-659878199) }
Block 0: Const { dest: v205, value: I32(-1745439105) }
Block 0: Mul { dest: v206, left: v204, right: v205 }
Block 0: Const { dest: v207, value: I32(-507837761) }
Block 0: Neg { dest: v208, operand: v207 }
Block 0: Const { dest: v209, value: I32(0) }
Block 0: Ceq { dest: v210, left: v207, right: v209 }
Block 0: Const { dest: v211, value: I32(1) }
Block 0: Xor { dest: v212, left: v210, right: v211 }
Block 0: Sub { dest: v213, left: v206, right: v208 }
Block 0: Clt { dest: v214, left: v206, right: v208, unsigned: true }
Block 0: Xor { dest: v215, left: v199, right: v213 }
Block 0: Const { dest: v216, value: I32(0) }
Block 0: Const { dest: v217, value: I32(-1552018915) }
Block 0: Const { dest: v218, value: I32(-806612029) }
Block 0: Xor { dest: v219, left: v217, right: v218 }
Block 0: Const { dest: v220, value: I32(0) }
Block 0: Add { dest: v221, left: v215, right: v219 }
Block 0: Clt { dest: v222, left: v221, right: v215, unsigned: true }
Block 0: Neg { dest: v223, operand: v221 }
Block 0: Const { dest: v224, value: I32(0) }
Block 0: Ceq { dest: v225, left: v221, right: v224 }
Block 0: Const { dest: v226, value: I32(1) }
Block 0: Xor { dest: v227, left: v225, right: v226 }
Block 0: Const { dest: v228, value: I32(407130642) }
Block 0: Add { dest: v229, left: v223, right: v228 }
Block 0: Clt { dest: v230, left: v229, right: v223, unsigned: true }
Block 0: Return { value: Some(v229) }
```

### Stub 8 — Token 0x06000004

| Field | Value |
|---|---|
| Token | `0x06000004` |
| RVA | `0x00002a90` |
| File offset | `0x00000c90` |
| Body size | 25 bytes |
| Total size | 45 bytes |
| Instructions | 12 |

Full bytes (45 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d0 b9 de 1b b2 4e f7 d1 ba 0d
0020: 29 a7 24 f7 da 31 d1 31 c8 5e 5f 5b c3
```

Body bytes (25 bytes, without prologue):
```
0000: 58 f7 d0 b9 de 1b b2 4e f7 d1 ba 0d 29 a7 24 f7
0010: da 31 d1 31 c8 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d0                 Not { dst: Register(Eax) }
0003: b9de1bb24e           Mov { dst: Register(Ecx), src: Immediate(1320295390) }
0008: f7d1                 Not { dst: Register(Ecx) }
000a: ba0d29a724           Mov { dst: Register(Edx), src: Immediate(614934797) }
000f: f7da                 Neg { dst: Register(Edx) }
0011: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0013: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0015: 5e                   Pop { dst: Esi }
0016: 5f                   Pop { dst: Edi }
0017: 5b                   Pop { dst: Ebx }
0018: c3                   Ret
```

SSA translation:
```
Block 0: Not { dest: v241, operand: v234 }
Block 0: Const { dest: v242, value: I32(1320295390) }
Block 0: Not { dest: v243, operand: v242 }
Block 0: Const { dest: v244, value: I32(614934797) }
Block 0: Neg { dest: v245, operand: v244 }
Block 0: Const { dest: v246, value: I32(0) }
Block 0: Ceq { dest: v247, left: v244, right: v246 }
Block 0: Const { dest: v248, value: I32(1) }
Block 0: Xor { dest: v249, left: v247, right: v248 }
Block 0: Xor { dest: v250, left: v243, right: v245 }
Block 0: Const { dest: v251, value: I32(0) }
Block 0: Xor { dest: v252, left: v241, right: v250 }
Block 0: Const { dest: v253, value: I32(0) }
Block 0: Return { value: Some(v252) }
```

### Stub 9 — Token 0x06000005

| Field | Value |
|---|---|
| Token | `0x06000005` |
| RVA | `0x00002ac0` |
| File offset | `0x00000cc0` |
| Body size | 24 bytes |
| Total size | 44 bytes |
| Instructions | 11 |

Full bytes (44 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 e6 55 61 74 f7 d1 81 f1 02 81
0020: 5b 39 f7 d9 31 c8 f7 d0 5e 5f 5b c3
```

Body bytes (24 bytes, without prologue):
```
0000: 58 b9 e6 55 61 74 f7 d1 81 f1 02 81 5b 39 f7 d9
0010: 31 c8 f7 d0 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b9e6556174           Mov { dst: Register(Ecx), src: Immediate(1952536038) }
0006: f7d1                 Not { dst: Register(Ecx) }
0008: 81f102815b39         Xor { dst: Register(Ecx), src: Immediate(962298114) }
000e: f7d9                 Neg { dst: Register(Ecx) }
0010: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0012: f7d0                 Not { dst: Register(Eax) }
0014: 5e                   Pop { dst: Esi }
0015: 5f                   Pop { dst: Edi }
0016: 5b                   Pop { dst: Ebx }
0017: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v264, value: I32(1952536038) }
Block 0: Not { dest: v265, operand: v264 }
Block 0: Const { dest: v266, value: I32(962298114) }
Block 0: Xor { dest: v267, left: v265, right: v266 }
Block 0: Const { dest: v268, value: I32(0) }
Block 0: Neg { dest: v269, operand: v267 }
Block 0: Const { dest: v270, value: I32(0) }
Block 0: Ceq { dest: v271, left: v267, right: v270 }
Block 0: Const { dest: v272, value: I32(1) }
Block 0: Xor { dest: v273, left: v271, right: v272 }
Block 0: Xor { dest: v274, left: v257, right: v269 }
Block 0: Const { dest: v275, value: I32(0) }
Block 0: Not { dest: v276, operand: v274 }
Block 0: Return { value: Some(v276) }
```

---

## Sample 3: mkaring_constants_x86_controlflow.exe

Constants x86 cipher + control flow normal predicate. 5 stubs.

### Stub 10 — Token 0x06000005

| Field | Value |
|---|---|
| Token | `0x06000005` |
| RVA | `0x00008154` |
| File offset | `0x00006354` |
| Body size | 47 bytes |
| Total size | 67 bytes |
| Instructions | 15 |

Full bytes (67 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 bd 45 6f e8 81 f1 97 a9 6c 5e
0020: ba e0 00 74 90 81 ea 04 00 f7 0e 31 d1 f7 d1 31
0030: c8 69 c0 95 b1 fa e8 f7 d0 81 f0 9b 36 4e 46 5e
0040: 5f 5b c3
```

Body bytes (47 bytes, without prologue):
```
0000: 58 b9 bd 45 6f e8 81 f1 97 a9 6c 5e ba e0 00 74
0010: 90 81 ea 04 00 f7 0e 31 d1 f7 d1 31 c8 69 c0 95
0020: b1 fa e8 f7 d0 81 f0 9b 36 4e 46 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b9bd456fe8           Mov { dst: Register(Ecx), src: Immediate(-395360835) }
0006: 81f197a96c5e         Xor { dst: Register(Ecx), src: Immediate(1584179607) }
000c: bae0007490           Mov { dst: Register(Edx), src: Immediate(-1871445792) }
0011: 81ea0400f70e         Sub { dst: Register(Edx), src: Immediate(251068420) }
0017: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0019: f7d1                 Not { dst: Register(Ecx) }
001b: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
001d: 69c095b1fae8         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-386223723)) }
0023: f7d0                 Not { dst: Register(Eax) }
0025: 81f09b364e46         Xor { dst: Register(Eax), src: Immediate(1179530907) }
002b: 5e                   Pop { dst: Esi }
002c: 5f                   Pop { dst: Edi }
002d: 5b                   Pop { dst: Ebx }
002e: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v287, value: I32(-395360835) }
Block 0: Const { dest: v288, value: I32(1584179607) }
Block 0: Xor { dest: v289, left: v287, right: v288 }
Block 0: Const { dest: v290, value: I32(0) }
Block 0: Const { dest: v291, value: I32(-1871445792) }
Block 0: Const { dest: v292, value: I32(251068420) }
Block 0: Sub { dest: v293, left: v291, right: v292 }
Block 0: Clt { dest: v294, left: v291, right: v292, unsigned: true }
Block 0: Xor { dest: v295, left: v289, right: v293 }
Block 0: Const { dest: v296, value: I32(0) }
Block 0: Not { dest: v297, operand: v295 }
Block 0: Xor { dest: v298, left: v280, right: v297 }
Block 0: Const { dest: v299, value: I32(0) }
Block 0: Const { dest: v300, value: I32(-386223723) }
Block 0: Mul { dest: v301, left: v298, right: v300 }
Block 0: Not { dest: v302, operand: v301 }
Block 0: Const { dest: v303, value: I32(1179530907) }
Block 0: Xor { dest: v304, left: v302, right: v303 }
Block 0: Const { dest: v305, value: I32(0) }
Block 0: Return { value: Some(v304) }
```

### Stub 11 — Token 0x06000007

| Field | Value |
|---|---|
| Token | `0x06000007` |
| RVA | `0x00008198` |
| File offset | `0x00006398` |
| Body size | 30 bytes |
| Total size | 50 bytes |
| Instructions | 12 |

Full bytes (50 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 c1 df 13 c2 f7 d1 f7 d9 01 c8
0020: 81 f0 33 b7 36 83 f7 d8 69 c0 91 9c 5d 59 5e 5f
0030: 5b c3
```

Body bytes (30 bytes, without prologue):
```
0000: 58 b9 c1 df 13 c2 f7 d1 f7 d9 01 c8 81 f0 33 b7
0010: 36 83 f7 d8 69 c0 91 9c 5d 59 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b9c1df13c2           Mov { dst: Register(Ecx), src: Immediate(-1038884927) }
0006: f7d1                 Not { dst: Register(Ecx) }
0008: f7d9                 Neg { dst: Register(Ecx) }
000a: 01c8                 Add { dst: Register(Eax), src: Register(Ecx) }
000c: 81f033b73683         Xor { dst: Register(Eax), src: Immediate(-2093566157) }
0012: f7d8                 Neg { dst: Register(Eax) }
0014: 69c0919c5d59         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(1499307153)) }
001a: 5e                   Pop { dst: Esi }
001b: 5f                   Pop { dst: Edi }
001c: 5b                   Pop { dst: Ebx }
001d: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v316, value: I32(-1038884927) }
Block 0: Not { dest: v317, operand: v316 }
Block 0: Neg { dest: v318, operand: v317 }
Block 0: Const { dest: v319, value: I32(0) }
Block 0: Ceq { dest: v320, left: v317, right: v319 }
Block 0: Const { dest: v321, value: I32(1) }
Block 0: Xor { dest: v322, left: v320, right: v321 }
Block 0: Add { dest: v323, left: v309, right: v318 }
Block 0: Clt { dest: v324, left: v323, right: v309, unsigned: true }
Block 0: Const { dest: v325, value: I32(-2093566157) }
Block 0: Xor { dest: v326, left: v323, right: v325 }
Block 0: Const { dest: v327, value: I32(0) }
Block 0: Neg { dest: v328, operand: v326 }
Block 0: Const { dest: v329, value: I32(0) }
Block 0: Ceq { dest: v330, left: v326, right: v329 }
Block 0: Const { dest: v331, value: I32(1) }
Block 0: Xor { dest: v332, left: v330, right: v331 }
Block 0: Const { dest: v333, value: I32(1499307153) }
Block 0: Mul { dest: v334, left: v328, right: v333 }
Block 0: Return { value: Some(v334) }
```

### Stub 12 — Token 0x06000009

| Field | Value |
|---|---|
| Token | `0x06000009` |
| RVA | `0x000081cc` |
| File offset | `0x000063cc` |
| Body size | 90 bytes |
| Total size | 110 bytes |
| Instructions | 27 |

Full bytes (110 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 74 31 fd be 81 e9 61 36 a9 b7
0020: ba 78 72 2c 05 f7 d2 29 d1 ba d1 77 af bf 81 ea
0030: 95 9b 9a 1a bb f9 50 2b 65 f7 d3 01 da 29 d1 29
0040: c8 b9 35 4e 06 6a 69 c9 ca 1c cf 82 ba cf cf c6
0050: ab 81 ea 53 a5 a5 83 31 d1 31 c8 b9 62 65 e8 81
0060: f7 d9 31 c8 81 e8 8d 94 43 59 5e 5f 5b c3
```

Body bytes (90 bytes, without prologue):
```
0000: 58 b9 74 31 fd be 81 e9 61 36 a9 b7 ba 78 72 2c
0010: 05 f7 d2 29 d1 ba d1 77 af bf 81 ea 95 9b 9a 1a
0020: bb f9 50 2b 65 f7 d3 01 da 29 d1 29 c8 b9 35 4e
0030: 06 6a 69 c9 ca 1c cf 82 ba cf cf c6 ab 81 ea 53
0040: a5 a5 83 31 d1 31 c8 b9 62 65 e8 81 f7 d9 31 c8
0050: 81 e8 8d 94 43 59 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b97431fdbe           Mov { dst: Register(Ecx), src: Immediate(-1090702988) }
0006: 81e96136a9b7         Sub { dst: Register(Ecx), src: Immediate(-1213647263) }
000c: ba78722c05           Mov { dst: Register(Edx), src: Immediate(86798968) }
0011: f7d2                 Not { dst: Register(Edx) }
0013: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0015: bad177afbf           Mov { dst: Register(Edx), src: Immediate(-1079019567) }
001a: 81ea959b9a1a         Sub { dst: Register(Edx), src: Immediate(446339989) }
0020: bbf9502b65           Mov { dst: Register(Ebx), src: Immediate(1697337593) }
0025: f7d3                 Not { dst: Register(Ebx) }
0027: 01da                 Add { dst: Register(Edx), src: Register(Ebx) }
0029: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
002b: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
002d: b9354e066a           Mov { dst: Register(Ecx), src: Immediate(1778798133) }
0032: 69c9ca1ccf82         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-2100355894)) }
0038: bacfcfc6ab           Mov { dst: Register(Edx), src: Immediate(-1413034033) }
003d: 81ea53a5a583         Sub { dst: Register(Edx), src: Immediate(-2086296237) }
0043: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0045: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0047: b96265e881           Mov { dst: Register(Ecx), src: Immediate(-2115476126) }
004c: f7d9                 Neg { dst: Register(Ecx) }
004e: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0050: 81e88d944359         Sub { dst: Register(Eax), src: Immediate(1497601165) }
0056: 5e                   Pop { dst: Esi }
0057: 5f                   Pop { dst: Edi }
0058: 5b                   Pop { dst: Ebx }
0059: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v345, value: I32(-1090702988) }
Block 0: Const { dest: v346, value: I32(-1213647263) }
Block 0: Sub { dest: v347, left: v345, right: v346 }
Block 0: Clt { dest: v348, left: v345, right: v346, unsigned: true }
Block 0: Const { dest: v349, value: I32(86798968) }
Block 0: Not { dest: v350, operand: v349 }
Block 0: Sub { dest: v351, left: v347, right: v350 }
Block 0: Clt { dest: v352, left: v347, right: v350, unsigned: true }
Block 0: Const { dest: v353, value: I32(-1079019567) }
Block 0: Const { dest: v354, value: I32(446339989) }
Block 0: Sub { dest: v355, left: v353, right: v354 }
Block 0: Clt { dest: v356, left: v353, right: v354, unsigned: true }
Block 0: Const { dest: v357, value: I32(1697337593) }
Block 0: Not { dest: v358, operand: v357 }
Block 0: Add { dest: v359, left: v355, right: v358 }
Block 0: Clt { dest: v360, left: v359, right: v355, unsigned: true }
Block 0: Sub { dest: v361, left: v351, right: v359 }
Block 0: Clt { dest: v362, left: v351, right: v359, unsigned: true }
Block 0: Sub { dest: v363, left: v338, right: v361 }
Block 0: Clt { dest: v364, left: v338, right: v361, unsigned: true }
Block 0: Const { dest: v365, value: I32(1778798133) }
Block 0: Const { dest: v366, value: I32(-2100355894) }
Block 0: Mul { dest: v367, left: v365, right: v366 }
Block 0: Const { dest: v368, value: I32(-1413034033) }
Block 0: Const { dest: v369, value: I32(-2086296237) }
Block 0: Sub { dest: v370, left: v368, right: v369 }
Block 0: Clt { dest: v371, left: v368, right: v369, unsigned: true }
Block 0: Xor { dest: v372, left: v367, right: v370 }
Block 0: Const { dest: v373, value: I32(0) }
Block 0: Xor { dest: v374, left: v363, right: v372 }
Block 0: Const { dest: v375, value: I32(0) }
Block 0: Const { dest: v376, value: I32(-2115476126) }
Block 0: Neg { dest: v377, operand: v376 }
Block 0: Const { dest: v378, value: I32(0) }
Block 0: Ceq { dest: v379, left: v376, right: v378 }
Block 0: Const { dest: v380, value: I32(1) }
Block 0: Xor { dest: v381, left: v379, right: v380 }
Block 0: Xor { dest: v382, left: v374, right: v377 }
Block 0: Const { dest: v383, value: I32(0) }
Block 0: Const { dest: v384, value: I32(1497601165) }
Block 0: Sub { dest: v385, left: v382, right: v384 }
Block 0: Clt { dest: v386, left: v382, right: v384, unsigned: true }
Block 0: Return { value: Some(v385) }
```

### Stub 13 — Token 0x0600000b

| Field | Value |
|---|---|
| Token | `0x0600000b` |
| RVA | `0x0000823c` |
| File offset | `0x0000643c` |
| Body size | 13 bytes |
| Total size | 33 bytes |
| Instructions | 7 |

Full bytes (33 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 69 c0 11 de e5 4a f7 d8 5e 5f 5b
0020: c3
```

Body bytes (13 bytes, without prologue):
```
0000: 58 69 c0 11 de e5 4a f7 d8 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: 69c011dee54a         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(1256578577)) }
0007: f7d8                 Neg { dst: Register(Eax) }
0009: 5e                   Pop { dst: Esi }
000a: 5f                   Pop { dst: Edi }
000b: 5b                   Pop { dst: Ebx }
000c: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v397, value: I32(1256578577) }
Block 0: Mul { dest: v398, left: v390, right: v397 }
Block 0: Neg { dest: v399, operand: v398 }
Block 0: Const { dest: v400, value: I32(0) }
Block 0: Ceq { dest: v401, left: v398, right: v400 }
Block 0: Const { dest: v402, value: I32(1) }
Block 0: Xor { dest: v403, left: v401, right: v402 }
Block 0: Return { value: Some(v399) }
```

### Stub 14 — Token 0x0600000d

| Field | Value |
|---|---|
| Token | `0x0600000d` |
| RVA | `0x00008260` |
| File offset | `0x00006460` |
| Body size | 25 bytes |
| Total size | 45 bytes |
| Instructions | 9 |

Full bytes (45 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d0 69 c0 53 44 4f fc 69 c0 b5
0020: 5f 0b c6 81 c0 33 7c 49 df 5e 5f 5b c3
```

Body bytes (25 bytes, without prologue):
```
0000: 58 f7 d0 69 c0 53 44 4f fc 69 c0 b5 5f 0b c6 81
0010: c0 33 7c 49 df 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d0                 Not { dst: Register(Eax) }
0003: 69c053444ffc         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-61914029)) }
0009: 69c0b55f0bc6         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-972333131)) }
000f: 81c0337c49df         Add { dst: Register(Eax), src: Immediate(-548832205) }
0015: 5e                   Pop { dst: Esi }
0016: 5f                   Pop { dst: Edi }
0017: 5b                   Pop { dst: Ebx }
0018: c3                   Ret
```

SSA translation:
```
Block 0: Not { dest: v414, operand: v407 }
Block 0: Const { dest: v415, value: I32(-61914029) }
Block 0: Mul { dest: v416, left: v414, right: v415 }
Block 0: Const { dest: v417, value: I32(-972333131) }
Block 0: Mul { dest: v418, left: v416, right: v417 }
Block 0: Const { dest: v419, value: I32(-548832205) }
Block 0: Add { dest: v420, left: v418, right: v419 }
Block 0: Clt { dest: v421, left: v420, right: v418, unsigned: true }
Block 0: Return { value: Some(v420) }
```

---

## Sample 4: mkaring_constants_x86_controlflow_x86.exe

Constants x86 cipher + control flow x86 predicate. 19 stubs.

### Stub 15 — Token 0x06000005

| Field | Value |
|---|---|
| Token | `0x06000005` |
| RVA | `0x000078c0` |
| File offset | `0x00005ac0` |
| Body size | 32 bytes |
| Total size | 52 bytes |
| Instructions | 13 |

Full bytes (52 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 f4 ed 90 36 81 f1 8c 76 a3 72
0020: f7 d1 69 c9 3b fb 62 da 31 c8 f7 d0 f7 d0 f7 d0
0030: 5e 5f 5b c3
```

Body bytes (32 bytes, without prologue):
```
0000: 58 b9 f4 ed 90 36 81 f1 8c 76 a3 72 f7 d1 69 c9
0010: 3b fb 62 da 31 c8 f7 d0 f7 d0 f7 d0 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b9f4ed9036           Mov { dst: Register(Ecx), src: Immediate(915467764) }
0006: 81f18c76a372         Xor { dst: Register(Ecx), src: Immediate(1923315340) }
000c: f7d1                 Not { dst: Register(Ecx) }
000e: 69c93bfb62da         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-631047365)) }
0014: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0016: f7d0                 Not { dst: Register(Eax) }
0018: f7d0                 Not { dst: Register(Eax) }
001a: f7d0                 Not { dst: Register(Eax) }
001c: 5e                   Pop { dst: Esi }
001d: 5f                   Pop { dst: Edi }
001e: 5b                   Pop { dst: Ebx }
001f: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v432, value: I32(915467764) }
Block 0: Const { dest: v433, value: I32(1923315340) }
Block 0: Xor { dest: v434, left: v432, right: v433 }
Block 0: Const { dest: v435, value: I32(0) }
Block 0: Not { dest: v436, operand: v434 }
Block 0: Const { dest: v437, value: I32(-631047365) }
Block 0: Mul { dest: v438, left: v436, right: v437 }
Block 0: Xor { dest: v439, left: v425, right: v438 }
Block 0: Const { dest: v440, value: I32(0) }
Block 0: Not { dest: v441, operand: v439 }
Block 0: Not { dest: v442, operand: v441 }
Block 0: Not { dest: v443, operand: v442 }
Block 0: Return { value: Some(v443) }
```

### Stub 16 — Token 0x06000007

| Field | Value |
|---|---|
| Token | `0x06000007` |
| RVA | `0x000078f4` |
| File offset | `0x00005af4` |
| Body size | 31 bytes |
| Total size | 51 bytes |
| Instructions | 13 |

Full bytes (51 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 b8 f4 d9 38 51 f7 d8 59 ba d1 84 10
0020: 2c f7 d2 29 d1 f7 d9 29 c8 81 f0 76 8e 58 13 5e
0030: 5f 5b c3
```

Body bytes (31 bytes, without prologue):
```
0000: b8 f4 d9 38 51 f7 d8 59 ba d1 84 10 2c f7 d2 29
0010: d1 f7 d9 29 c8 81 f0 76 8e 58 13 5e 5f 5b c3
```

Disassembly:
```
0000: b8f4d93851           Mov { dst: Register(Eax), src: Immediate(1362680308) }
0005: f7d8                 Neg { dst: Register(Eax) }
0007: 59                   Pop { dst: Ecx }
0008: bad184102c           Mov { dst: Register(Edx), src: Immediate(739280081) }
000d: f7d2                 Not { dst: Register(Edx) }
000f: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0011: f7d9                 Neg { dst: Register(Ecx) }
0013: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0015: 81f0768e5813         Xor { dst: Register(Eax), src: Immediate(324570742) }
001b: 5e                   Pop { dst: Esi }
001c: 5f                   Pop { dst: Edi }
001d: 5b                   Pop { dst: Ebx }
001e: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v454, value: I32(1362680308) }
Block 0: Neg { dest: v455, operand: v454 }
Block 0: Const { dest: v456, value: I32(0) }
Block 0: Ceq { dest: v457, left: v454, right: v456 }
Block 0: Const { dest: v458, value: I32(1) }
Block 0: Xor { dest: v459, left: v457, right: v458 }
Block 0: Const { dest: v460, value: I32(739280081) }
Block 0: Not { dest: v461, operand: v460 }
Block 0: Sub { dest: v462, left: v447, right: v461 }
Block 0: Clt { dest: v463, left: v447, right: v461, unsigned: true }
Block 0: Neg { dest: v464, operand: v462 }
Block 0: Const { dest: v465, value: I32(0) }
Block 0: Ceq { dest: v466, left: v462, right: v465 }
Block 0: Const { dest: v467, value: I32(1) }
Block 0: Xor { dest: v468, left: v466, right: v467 }
Block 0: Sub { dest: v469, left: v455, right: v464 }
Block 0: Clt { dest: v470, left: v455, right: v464, unsigned: true }
Block 0: Const { dest: v471, value: I32(324570742) }
Block 0: Xor { dest: v472, left: v469, right: v471 }
Block 0: Const { dest: v473, value: I32(0) }
Block 0: Return { value: Some(v472) }
```

### Stub 17 — Token 0x06000009

| Field | Value |
|---|---|
| Token | `0x06000009` |
| RVA | `0x00007928` |
| File offset | `0x00005b28` |
| Body size | 78 bytes |
| Total size | 98 bytes |
| Instructions | 22 |

Full bytes (98 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 8e c7 f5 ea 81 f1 e0 da 23 b2
0020: ba 2d d8 92 bd 81 c2 7e 4c 90 1e 29 d1 ba ed 36
0030: 75 fe 69 d2 dc c3 ba 94 bb 35 02 87 78 81 c3 e1
0040: 87 3d 37 29 da 29 d1 31 c8 b9 f8 3a 1b 5e 69 c9
0050: 8f 6c 80 73 31 c8 f7 d8 81 e8 72 28 f6 53 5e 5f
0060: 5b c3
```

Body bytes (78 bytes, without prologue):
```
0000: 58 b9 8e c7 f5 ea 81 f1 e0 da 23 b2 ba 2d d8 92
0010: bd 81 c2 7e 4c 90 1e 29 d1 ba ed 36 75 fe 69 d2
0020: dc c3 ba 94 bb 35 02 87 78 81 c3 e1 87 3d 37 29
0030: da 29 d1 31 c8 b9 f8 3a 1b 5e 69 c9 8f 6c 80 73
0040: 31 c8 f7 d8 81 e8 72 28 f6 53 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b98ec7f5ea           Mov { dst: Register(Ecx), src: Immediate(-352991346) }
0006: 81f1e0da23b2         Xor { dst: Register(Ecx), src: Immediate(-1306273056) }
000c: ba2dd892bd           Mov { dst: Register(Edx), src: Immediate(-1114449875) }
0011: 81c27e4c901e         Add { dst: Register(Edx), src: Immediate(512773246) }
0017: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0019: baed3675fe           Mov { dst: Register(Edx), src: Immediate(-25872659) }
001e: 69d2dcc3ba94         Imul { dst: Edx, src: Register(Edx), src2: Some(Immediate(-1799699492)) }
0024: bb35028778           Mov { dst: Register(Ebx), src: Immediate(2022113845) }
0029: 81c3e1873d37         Add { dst: Register(Ebx), src: Immediate(926779361) }
002f: 29da                 Sub { dst: Register(Edx), src: Register(Ebx) }
0031: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0033: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0035: b9f83a1b5e           Mov { dst: Register(Ecx), src: Immediate(1578842872) }
003a: 69c98f6c8073         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(1937796239)) }
0040: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0042: f7d8                 Neg { dst: Register(Eax) }
0044: 81e87228f653         Sub { dst: Register(Eax), src: Immediate(1408641138) }
004a: 5e                   Pop { dst: Esi }
004b: 5f                   Pop { dst: Edi }
004c: 5b                   Pop { dst: Ebx }
004d: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v484, value: I32(-352991346) }
Block 0: Const { dest: v485, value: I32(-1306273056) }
Block 0: Xor { dest: v486, left: v484, right: v485 }
Block 0: Const { dest: v487, value: I32(0) }
Block 0: Const { dest: v488, value: I32(-1114449875) }
Block 0: Const { dest: v489, value: I32(512773246) }
Block 0: Add { dest: v490, left: v488, right: v489 }
Block 0: Clt { dest: v491, left: v490, right: v488, unsigned: true }
Block 0: Sub { dest: v492, left: v486, right: v490 }
Block 0: Clt { dest: v493, left: v486, right: v490, unsigned: true }
Block 0: Const { dest: v494, value: I32(-25872659) }
Block 0: Const { dest: v495, value: I32(-1799699492) }
Block 0: Mul { dest: v496, left: v494, right: v495 }
Block 0: Const { dest: v497, value: I32(2022113845) }
Block 0: Const { dest: v498, value: I32(926779361) }
Block 0: Add { dest: v499, left: v497, right: v498 }
Block 0: Clt { dest: v500, left: v499, right: v497, unsigned: true }
Block 0: Sub { dest: v501, left: v496, right: v499 }
Block 0: Clt { dest: v502, left: v496, right: v499, unsigned: true }
Block 0: Sub { dest: v503, left: v492, right: v501 }
Block 0: Clt { dest: v504, left: v492, right: v501, unsigned: true }
Block 0: Xor { dest: v505, left: v477, right: v503 }
Block 0: Const { dest: v506, value: I32(0) }
Block 0: Const { dest: v507, value: I32(1578842872) }
Block 0: Const { dest: v508, value: I32(1937796239) }
Block 0: Mul { dest: v509, left: v507, right: v508 }
Block 0: Xor { dest: v510, left: v505, right: v509 }
Block 0: Const { dest: v511, value: I32(0) }
Block 0: Neg { dest: v512, operand: v510 }
Block 0: Const { dest: v513, value: I32(0) }
Block 0: Ceq { dest: v514, left: v510, right: v513 }
Block 0: Const { dest: v515, value: I32(1) }
Block 0: Xor { dest: v516, left: v514, right: v515 }
Block 0: Const { dest: v517, value: I32(1408641138) }
Block 0: Sub { dest: v518, left: v512, right: v517 }
Block 0: Clt { dest: v519, left: v512, right: v517, unsigned: true }
Block 0: Return { value: Some(v518) }
```

### Stub 18 — Token 0x0600000b

| Field | Value |
|---|---|
| Token | `0x0600000b` |
| RVA | `0x0000798c` |
| File offset | `0x00005b8c` |
| Body size | 9 bytes |
| Total size | 29 bytes |
| Instructions | 7 |

Full bytes (29 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d8 f7 d8 5e 5f 5b c3
```

Body bytes (9 bytes, without prologue):
```
0000: 58 f7 d8 f7 d8 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d8                 Neg { dst: Register(Eax) }
0003: f7d8                 Neg { dst: Register(Eax) }
0005: 5e                   Pop { dst: Esi }
0006: 5f                   Pop { dst: Edi }
0007: 5b                   Pop { dst: Ebx }
0008: c3                   Ret
```

SSA translation:
```
Block 0: Neg { dest: v530, operand: v523 }
Block 0: Const { dest: v531, value: I32(0) }
Block 0: Ceq { dest: v532, left: v523, right: v531 }
Block 0: Const { dest: v533, value: I32(1) }
Block 0: Xor { dest: v534, left: v532, right: v533 }
Block 0: Neg { dest: v535, operand: v530 }
Block 0: Const { dest: v536, value: I32(0) }
Block 0: Ceq { dest: v537, left: v530, right: v536 }
Block 0: Const { dest: v538, value: I32(1) }
Block 0: Xor { dest: v539, left: v537, right: v538 }
Block 0: Return { value: Some(v535) }
```

### Stub 19 — Token 0x0600000d

| Field | Value |
|---|---|
| Token | `0x0600000d` |
| RVA | `0x000079ac` |
| File offset | `0x00005bac` |
| Body size | 94 bytes |
| Total size | 114 bytes |
| Instructions | 27 |

Full bytes (114 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 9c e0 3c 3a 81 c1 bf 9c 8f ac
0020: ba 73 a2 ad ee 81 ea 69 ad 28 fb 31 d1 ba c4 cc
0030: b2 d5 69 d2 05 1d c8 55 bb 11 49 0f 2a 69 db f3
0040: 9c ce cc 29 da 31 d1 01 c8 b9 10 9e 73 ca 81 e9
0050: d2 03 3e d2 ba ab c5 17 5d f7 d2 31 d1 01 c8 b9
0060: 39 42 5c ab 69 c9 c0 b6 6e a0 29 c8 f7 d0 5e 5f
0070: 5b c3
```

Body bytes (94 bytes, without prologue):
```
0000: 58 b9 9c e0 3c 3a 81 c1 bf 9c 8f ac ba 73 a2 ad
0010: ee 81 ea 69 ad 28 fb 31 d1 ba c4 cc b2 d5 69 d2
0020: 05 1d c8 55 bb 11 49 0f 2a 69 db f3 9c ce cc 29
0030: da 31 d1 01 c8 b9 10 9e 73 ca 81 e9 d2 03 3e d2
0040: ba ab c5 17 5d f7 d2 31 d1 01 c8 b9 39 42 5c ab
0050: 69 c9 c0 b6 6e a0 29 c8 f7 d0 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b99ce03c3a           Mov { dst: Register(Ecx), src: Immediate(977068188) }
0006: 81c1bf9c8fac         Add { dst: Register(Ecx), src: Immediate(-1399874369) }
000c: ba73a2adee           Mov { dst: Register(Edx), src: Immediate(-290610573) }
0011: 81ea69ad28fb         Sub { dst: Register(Edx), src: Immediate(-81220247) }
0017: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0019: bac4ccb2d5           Mov { dst: Register(Edx), src: Immediate(-709702460) }
001e: 69d2051dc855         Imul { dst: Edx, src: Register(Edx), src2: Some(Immediate(1439177989)) }
0024: bb11490f2a           Mov { dst: Register(Ebx), src: Immediate(705644817) }
0029: 69dbf39ccecc         Imul { dst: Ebx, src: Register(Ebx), src2: Some(Immediate(-858874637)) }
002f: 29da                 Sub { dst: Register(Edx), src: Register(Ebx) }
0031: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0033: 01c8                 Add { dst: Register(Eax), src: Register(Ecx) }
0035: b9109e73ca           Mov { dst: Register(Ecx), src: Immediate(-898392560) }
003a: 81e9d2033ed2         Sub { dst: Register(Ecx), src: Immediate(-767687726) }
0040: baabc5175d           Mov { dst: Register(Edx), src: Immediate(1561839019) }
0045: f7d2                 Not { dst: Register(Edx) }
0047: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0049: 01c8                 Add { dst: Register(Eax), src: Register(Ecx) }
004b: b939425cab           Mov { dst: Register(Ecx), src: Immediate(-1420017095) }
0050: 69c9c0b66ea0         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-1603356992)) }
0056: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0058: f7d0                 Not { dst: Register(Eax) }
005a: 5e                   Pop { dst: Esi }
005b: 5f                   Pop { dst: Edi }
005c: 5b                   Pop { dst: Ebx }
005d: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v550, value: I32(977068188) }
Block 0: Const { dest: v551, value: I32(-1399874369) }
Block 0: Add { dest: v552, left: v550, right: v551 }
Block 0: Clt { dest: v553, left: v552, right: v550, unsigned: true }
Block 0: Const { dest: v554, value: I32(-290610573) }
Block 0: Const { dest: v555, value: I32(-81220247) }
Block 0: Sub { dest: v556, left: v554, right: v555 }
Block 0: Clt { dest: v557, left: v554, right: v555, unsigned: true }
Block 0: Xor { dest: v558, left: v552, right: v556 }
Block 0: Const { dest: v559, value: I32(0) }
Block 0: Const { dest: v560, value: I32(-709702460) }
Block 0: Const { dest: v561, value: I32(1439177989) }
Block 0: Mul { dest: v562, left: v560, right: v561 }
Block 0: Const { dest: v563, value: I32(705644817) }
Block 0: Const { dest: v564, value: I32(-858874637) }
Block 0: Mul { dest: v565, left: v563, right: v564 }
Block 0: Sub { dest: v566, left: v562, right: v565 }
Block 0: Clt { dest: v567, left: v562, right: v565, unsigned: true }
Block 0: Xor { dest: v568, left: v558, right: v566 }
Block 0: Const { dest: v569, value: I32(0) }
Block 0: Add { dest: v570, left: v543, right: v568 }
Block 0: Clt { dest: v571, left: v570, right: v543, unsigned: true }
Block 0: Const { dest: v572, value: I32(-898392560) }
Block 0: Const { dest: v573, value: I32(-767687726) }
Block 0: Sub { dest: v574, left: v572, right: v573 }
Block 0: Clt { dest: v575, left: v572, right: v573, unsigned: true }
Block 0: Const { dest: v576, value: I32(1561839019) }
Block 0: Not { dest: v577, operand: v576 }
Block 0: Xor { dest: v578, left: v574, right: v577 }
Block 0: Const { dest: v579, value: I32(0) }
Block 0: Add { dest: v580, left: v570, right: v578 }
Block 0: Clt { dest: v581, left: v580, right: v570, unsigned: true }
Block 0: Const { dest: v582, value: I32(-1420017095) }
Block 0: Const { dest: v583, value: I32(-1603356992) }
Block 0: Mul { dest: v584, left: v582, right: v583 }
Block 0: Sub { dest: v585, left: v580, right: v584 }
Block 0: Clt { dest: v586, left: v580, right: v584, unsigned: true }
Block 0: Not { dest: v587, operand: v585 }
Block 0: Return { value: Some(v587) }
```

### Stub 20 — Token 0x0600000e

| Field | Value |
|---|---|
| Token | `0x0600000e` |
| RVA | `0x00007a20` |
| File offset | `0x00005c20` |
| Body size | 32 bytes |
| Total size | 52 bytes |
| Instructions | 11 |

Full bytes (52 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 b8 9f 90 af 11 81 f0 56 79 cd d8 59
0020: f7 d1 69 c9 25 f3 f2 90 29 c8 81 f0 bc e5 47 21
0030: 5e 5f 5b c3
```

Body bytes (32 bytes, without prologue):
```
0000: b8 9f 90 af 11 81 f0 56 79 cd d8 59 f7 d1 69 c9
0010: 25 f3 f2 90 29 c8 81 f0 bc e5 47 21 5e 5f 5b c3
```

Disassembly:
```
0000: b89f90af11           Mov { dst: Register(Eax), src: Immediate(296718495) }
0005: 81f05679cdd8         Xor { dst: Register(Eax), src: Immediate(-657622698) }
000b: 59                   Pop { dst: Ecx }
000c: f7d1                 Not { dst: Register(Ecx) }
000e: 69c925f3f290         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-1863126235)) }
0014: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0016: 81f0bce54721         Xor { dst: Register(Eax), src: Immediate(558359996) }
001c: 5e                   Pop { dst: Esi }
001d: 5f                   Pop { dst: Edi }
001e: 5b                   Pop { dst: Ebx }
001f: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v598, value: I32(296718495) }
Block 0: Const { dest: v599, value: I32(-657622698) }
Block 0: Xor { dest: v600, left: v598, right: v599 }
Block 0: Const { dest: v601, value: I32(0) }
Block 0: Not { dest: v602, operand: v591 }
Block 0: Const { dest: v603, value: I32(-1863126235) }
Block 0: Mul { dest: v604, left: v602, right: v603 }
Block 0: Sub { dest: v605, left: v600, right: v604 }
Block 0: Clt { dest: v606, left: v600, right: v604, unsigned: true }
Block 0: Const { dest: v607, value: I32(558359996) }
Block 0: Xor { dest: v608, left: v605, right: v607 }
Block 0: Const { dest: v609, value: I32(0) }
Block 0: Return { value: Some(v608) }
```

### Stub 21 — Token 0x0600000f

| Field | Value |
|---|---|
| Token | `0x0600000f` |
| RVA | `0x00007a54` |
| File offset | `0x00005c54` |
| Body size | 21 bytes |
| Total size | 41 bytes |
| Instructions | 9 |

Full bytes (41 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d0 f7 d8 69 c0 87 fa 10 b0 69
0020: c0 39 25 7d ee 5e 5f 5b c3
```

Body bytes (21 bytes, without prologue):
```
0000: 58 f7 d0 f7 d8 69 c0 87 fa 10 b0 69 c0 39 25 7d
0010: ee 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d0                 Not { dst: Register(Eax) }
0003: f7d8                 Neg { dst: Register(Eax) }
0005: 69c087fa10b0         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-1341064569)) }
000b: 69c039257dee         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-293788359)) }
0011: 5e                   Pop { dst: Esi }
0012: 5f                   Pop { dst: Edi }
0013: 5b                   Pop { dst: Ebx }
0014: c3                   Ret
```

SSA translation:
```
Block 0: Not { dest: v620, operand: v613 }
Block 0: Neg { dest: v621, operand: v620 }
Block 0: Const { dest: v622, value: I32(0) }
Block 0: Ceq { dest: v623, left: v620, right: v622 }
Block 0: Const { dest: v624, value: I32(1) }
Block 0: Xor { dest: v625, left: v623, right: v624 }
Block 0: Const { dest: v626, value: I32(-1341064569) }
Block 0: Mul { dest: v627, left: v621, right: v626 }
Block 0: Const { dest: v628, value: I32(-293788359) }
Block 0: Mul { dest: v629, left: v627, right: v628 }
Block 0: Return { value: Some(v629) }
```

### Stub 22 — Token 0x06000010

| Field | Value |
|---|---|
| Token | `0x06000010` |
| RVA | `0x00007a80` |
| File offset | `0x00005c80` |
| Body size | 71 bytes |
| Total size | 91 bytes |
| Instructions | 25 |

Full bytes (91 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 45 d0 83 73 f7 d1 ba 73 50 97
0020: 3a f7 d2 29 d1 ba ec c6 df 74 f7 da 69 d2 0f ff
0030: 51 36 01 d1 29 c8 b9 21 2d 91 cd f7 d1 ba b2 ec
0040: 80 10 f7 da 29 d1 31 c8 b9 9d 3e c2 48 81 f1 e9
0050: 02 f0 07 31 c8 f7 d0 5e 5f 5b c3
```

Body bytes (71 bytes, without prologue):
```
0000: 58 b9 45 d0 83 73 f7 d1 ba 73 50 97 3a f7 d2 29
0010: d1 ba ec c6 df 74 f7 da 69 d2 0f ff 51 36 01 d1
0020: 29 c8 b9 21 2d 91 cd f7 d1 ba b2 ec 80 10 f7 da
0030: 29 d1 31 c8 b9 9d 3e c2 48 81 f1 e9 02 f0 07 31
0040: c8 f7 d0 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b945d08373           Mov { dst: Register(Ecx), src: Immediate(1938018373) }
0006: f7d1                 Not { dst: Register(Ecx) }
0008: ba7350973a           Mov { dst: Register(Edx), src: Immediate(982995059) }
000d: f7d2                 Not { dst: Register(Edx) }
000f: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0011: baecc6df74           Mov { dst: Register(Edx), src: Immediate(1960822508) }
0016: f7da                 Neg { dst: Register(Edx) }
0018: 69d20fff5136         Imul { dst: Edx, src: Register(Edx), src2: Some(Immediate(911343375)) }
001e: 01d1                 Add { dst: Register(Ecx), src: Register(Edx) }
0020: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0022: b9212d91cd           Mov { dst: Register(Ecx), src: Immediate(-846123743) }
0027: f7d1                 Not { dst: Register(Ecx) }
0029: bab2ec8010           Mov { dst: Register(Edx), src: Immediate(276884658) }
002e: f7da                 Neg { dst: Register(Edx) }
0030: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0032: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0034: b99d3ec248           Mov { dst: Register(Ecx), src: Immediate(1220689565) }
0039: 81f1e902f007         Xor { dst: Register(Ecx), src: Immediate(133169897) }
003f: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0041: f7d0                 Not { dst: Register(Eax) }
0043: 5e                   Pop { dst: Esi }
0044: 5f                   Pop { dst: Edi }
0045: 5b                   Pop { dst: Ebx }
0046: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v640, value: I32(1938018373) }
Block 0: Not { dest: v641, operand: v640 }
Block 0: Const { dest: v642, value: I32(982995059) }
Block 0: Not { dest: v643, operand: v642 }
Block 0: Sub { dest: v644, left: v641, right: v643 }
Block 0: Clt { dest: v645, left: v641, right: v643, unsigned: true }
Block 0: Const { dest: v646, value: I32(1960822508) }
Block 0: Neg { dest: v647, operand: v646 }
Block 0: Const { dest: v648, value: I32(0) }
Block 0: Ceq { dest: v649, left: v646, right: v648 }
Block 0: Const { dest: v650, value: I32(1) }
Block 0: Xor { dest: v651, left: v649, right: v650 }
Block 0: Const { dest: v652, value: I32(911343375) }
Block 0: Mul { dest: v653, left: v647, right: v652 }
Block 0: Add { dest: v654, left: v644, right: v653 }
Block 0: Clt { dest: v655, left: v654, right: v644, unsigned: true }
Block 0: Sub { dest: v656, left: v633, right: v654 }
Block 0: Clt { dest: v657, left: v633, right: v654, unsigned: true }
Block 0: Const { dest: v658, value: I32(-846123743) }
Block 0: Not { dest: v659, operand: v658 }
Block 0: Const { dest: v660, value: I32(276884658) }
Block 0: Neg { dest: v661, operand: v660 }
Block 0: Const { dest: v662, value: I32(0) }
Block 0: Ceq { dest: v663, left: v660, right: v662 }
Block 0: Const { dest: v664, value: I32(1) }
Block 0: Xor { dest: v665, left: v663, right: v664 }
Block 0: Sub { dest: v666, left: v659, right: v661 }
Block 0: Clt { dest: v667, left: v659, right: v661, unsigned: true }
Block 0: Xor { dest: v668, left: v656, right: v666 }
Block 0: Const { dest: v669, value: I32(0) }
Block 0: Const { dest: v670, value: I32(1220689565) }
Block 0: Const { dest: v671, value: I32(133169897) }
Block 0: Xor { dest: v672, left: v670, right: v671 }
Block 0: Const { dest: v673, value: I32(0) }
Block 0: Xor { dest: v674, left: v668, right: v672 }
Block 0: Const { dest: v675, value: I32(0) }
Block 0: Not { dest: v676, operand: v674 }
Block 0: Return { value: Some(v676) }
```

### Stub 23 — Token 0x06000011

| Field | Value |
|---|---|
| Token | `0x06000011` |
| RVA | `0x00007adc` |
| File offset | `0x00005cdc` |
| Body size | 50 bytes |
| Total size | 70 bytes |
| Instructions | 17 |

Full bytes (70 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 41 42 9d d0 69 c9 ff cd 1a 0c
0020: ba 93 ce d3 1b f7 d2 bb fd 63 48 83 81 c3 8c 3d
0030: c5 37 01 da 31 d1 31 c8 f7 d8 f7 d0 81 e8 86 da
0040: 5f cc 5e 5f 5b c3
```

Body bytes (50 bytes, without prologue):
```
0000: 58 b9 41 42 9d d0 69 c9 ff cd 1a 0c ba 93 ce d3
0010: 1b f7 d2 bb fd 63 48 83 81 c3 8c 3d c5 37 01 da
0020: 31 d1 31 c8 f7 d8 f7 d0 81 e8 86 da 5f cc 5e 5f
0030: 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b941429dd0           Mov { dst: Register(Ecx), src: Immediate(-795000255) }
0006: 69c9ffcd1a0c         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(203083263)) }
000c: ba93ced31b           Mov { dst: Register(Edx), src: Immediate(466865811) }
0011: f7d2                 Not { dst: Register(Edx) }
0013: bbfd634883           Mov { dst: Register(Ebx), src: Immediate(-2092407811) }
0018: 81c38c3dc537         Add { dst: Register(Ebx), src: Immediate(935673228) }
001e: 01da                 Add { dst: Register(Edx), src: Register(Ebx) }
0020: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0022: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0024: f7d8                 Neg { dst: Register(Eax) }
0026: f7d0                 Not { dst: Register(Eax) }
0028: 81e886da5fcc         Sub { dst: Register(Eax), src: Immediate(-866133370) }
002e: 5e                   Pop { dst: Esi }
002f: 5f                   Pop { dst: Edi }
0030: 5b                   Pop { dst: Ebx }
0031: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v687, value: I32(-795000255) }
Block 0: Const { dest: v688, value: I32(203083263) }
Block 0: Mul { dest: v689, left: v687, right: v688 }
Block 0: Const { dest: v690, value: I32(466865811) }
Block 0: Not { dest: v691, operand: v690 }
Block 0: Const { dest: v692, value: I32(-2092407811) }
Block 0: Const { dest: v693, value: I32(935673228) }
Block 0: Add { dest: v694, left: v692, right: v693 }
Block 0: Clt { dest: v695, left: v694, right: v692, unsigned: true }
Block 0: Add { dest: v696, left: v691, right: v694 }
Block 0: Clt { dest: v697, left: v696, right: v691, unsigned: true }
Block 0: Xor { dest: v698, left: v689, right: v696 }
Block 0: Const { dest: v699, value: I32(0) }
Block 0: Xor { dest: v700, left: v680, right: v698 }
Block 0: Const { dest: v701, value: I32(0) }
Block 0: Neg { dest: v702, operand: v700 }
Block 0: Const { dest: v703, value: I32(0) }
Block 0: Ceq { dest: v704, left: v700, right: v703 }
Block 0: Const { dest: v705, value: I32(1) }
Block 0: Xor { dest: v706, left: v704, right: v705 }
Block 0: Not { dest: v707, operand: v702 }
Block 0: Const { dest: v708, value: I32(-866133370) }
Block 0: Sub { dest: v709, left: v707, right: v708 }
Block 0: Clt { dest: v710, left: v707, right: v708, unsigned: true }
Block 0: Return { value: Some(v709) }
```

### Stub 24 — Token 0x06000012

| Field | Value |
|---|---|
| Token | `0x06000012` |
| RVA | `0x00007b24` |
| File offset | `0x00005d24` |
| Body size | 35 bytes |
| Total size | 55 bytes |
| Instructions | 13 |

Full bytes (55 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 69 c0 2f fd 88 75 b9 6c 56 f2 2a
0020: 81 f1 b7 7a bf cb f7 d1 31 c8 b9 6c a7 9d 74 f7
0030: d1 01 c8 5e 5f 5b c3
```

Body bytes (35 bytes, without prologue):
```
0000: 58 69 c0 2f fd 88 75 b9 6c 56 f2 2a 81 f1 b7 7a
0010: bf cb f7 d1 31 c8 b9 6c a7 9d 74 f7 d1 01 c8 5e
0020: 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: 69c02ffd8875         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(1971911983)) }
0007: b96c56f22a           Mov { dst: Register(Ecx), src: Immediate(720524908) }
000c: 81f1b77abfcb         Xor { dst: Register(Ecx), src: Immediate(-876643657) }
0012: f7d1                 Not { dst: Register(Ecx) }
0014: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0016: b96ca79d74           Mov { dst: Register(Ecx), src: Immediate(1956489068) }
001b: f7d1                 Not { dst: Register(Ecx) }
001d: 01c8                 Add { dst: Register(Eax), src: Register(Ecx) }
001f: 5e                   Pop { dst: Esi }
0020: 5f                   Pop { dst: Edi }
0021: 5b                   Pop { dst: Ebx }
0022: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v721, value: I32(1971911983) }
Block 0: Mul { dest: v722, left: v714, right: v721 }
Block 0: Const { dest: v723, value: I32(720524908) }
Block 0: Const { dest: v724, value: I32(-876643657) }
Block 0: Xor { dest: v725, left: v723, right: v724 }
Block 0: Const { dest: v726, value: I32(0) }
Block 0: Not { dest: v727, operand: v725 }
Block 0: Xor { dest: v728, left: v722, right: v727 }
Block 0: Const { dest: v729, value: I32(0) }
Block 0: Const { dest: v730, value: I32(1956489068) }
Block 0: Not { dest: v731, operand: v730 }
Block 0: Add { dest: v732, left: v728, right: v731 }
Block 0: Clt { dest: v733, left: v732, right: v728, unsigned: true }
Block 0: Return { value: Some(v732) }
```

### Stub 25 — Token 0x06000013

| Field | Value |
|---|---|
| Token | `0x06000013` |
| RVA | `0x00007b5c` |
| File offset | `0x00005d5c` |
| Body size | 19 bytes |
| Total size | 39 bytes |
| Instructions | 8 |

Full bytes (39 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d8 69 c0 4b e2 f1 77 69 c0 6d
0020: ad 6e c6 5e 5f 5b c3
```

Body bytes (19 bytes, without prologue):
```
0000: 58 f7 d8 69 c0 4b e2 f1 77 69 c0 6d ad 6e c6 5e
0010: 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d8                 Neg { dst: Register(Eax) }
0003: 69c04be2f177         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(2012340811)) }
0009: 69c06dad6ec6         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-965825171)) }
000f: 5e                   Pop { dst: Esi }
0010: 5f                   Pop { dst: Edi }
0011: 5b                   Pop { dst: Ebx }
0012: c3                   Ret
```

SSA translation:
```
Block 0: Neg { dest: v744, operand: v737 }
Block 0: Const { dest: v745, value: I32(0) }
Block 0: Ceq { dest: v746, left: v737, right: v745 }
Block 0: Const { dest: v747, value: I32(1) }
Block 0: Xor { dest: v748, left: v746, right: v747 }
Block 0: Const { dest: v749, value: I32(2012340811) }
Block 0: Mul { dest: v750, left: v744, right: v749 }
Block 0: Const { dest: v751, value: I32(-965825171) }
Block 0: Mul { dest: v752, left: v750, right: v751 }
Block 0: Return { value: Some(v752) }
```

### Stub 26 — Token 0x06000014

| Field | Value |
|---|---|
| Token | `0x06000014` |
| RVA | `0x00007b84` |
| File offset | `0x00005d84` |
| Body size | 30 bytes |
| Total size | 50 bytes |
| Instructions | 12 |

Full bytes (50 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d0 f7 d8 b9 63 58 3c 00 69 c9
0020: 95 78 35 e3 31 c8 f7 d8 81 c0 ab 79 f2 a6 5e 5f
0030: 5b c3
```

Body bytes (30 bytes, without prologue):
```
0000: 58 f7 d0 f7 d8 b9 63 58 3c 00 69 c9 95 78 35 e3
0010: 31 c8 f7 d8 81 c0 ab 79 f2 a6 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d0                 Not { dst: Register(Eax) }
0003: f7d8                 Neg { dst: Register(Eax) }
0005: b963583c00           Mov { dst: Register(Ecx), src: Immediate(3954787) }
000a: 69c9957835e3         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(-483034987)) }
0010: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
0012: f7d8                 Neg { dst: Register(Eax) }
0014: 81c0ab79f2a6         Add { dst: Register(Eax), src: Immediate(-1494058581) }
001a: 5e                   Pop { dst: Esi }
001b: 5f                   Pop { dst: Edi }
001c: 5b                   Pop { dst: Ebx }
001d: c3                   Ret
```

SSA translation:
```
Block 0: Not { dest: v763, operand: v756 }
Block 0: Neg { dest: v764, operand: v763 }
Block 0: Const { dest: v765, value: I32(0) }
Block 0: Ceq { dest: v766, left: v763, right: v765 }
Block 0: Const { dest: v767, value: I32(1) }
Block 0: Xor { dest: v768, left: v766, right: v767 }
Block 0: Const { dest: v769, value: I32(3954787) }
Block 0: Const { dest: v770, value: I32(-483034987) }
Block 0: Mul { dest: v771, left: v769, right: v770 }
Block 0: Xor { dest: v772, left: v764, right: v771 }
Block 0: Const { dest: v773, value: I32(0) }
Block 0: Neg { dest: v774, operand: v772 }
Block 0: Const { dest: v775, value: I32(0) }
Block 0: Ceq { dest: v776, left: v772, right: v775 }
Block 0: Const { dest: v777, value: I32(1) }
Block 0: Xor { dest: v778, left: v776, right: v777 }
Block 0: Const { dest: v779, value: I32(-1494058581) }
Block 0: Add { dest: v780, left: v774, right: v779 }
Block 0: Clt { dest: v781, left: v780, right: v774, unsigned: true }
Block 0: Return { value: Some(v780) }
```

### Stub 27 — Token 0x06000015

| Field | Value |
|---|---|
| Token | `0x06000015` |
| RVA | `0x00007bb8` |
| File offset | `0x00005db8` |
| Body size | 28 bytes |
| Total size | 48 bytes |
| Instructions | 11 |

Full bytes (48 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 f7 d8 69 c0 f9 3f 5b 67 b9 fc e6
0020: 80 cd f7 d9 29 c8 81 e8 0f 76 37 2b 5e 5f 5b c3
```

Body bytes (28 bytes, without prologue):
```
0000: 58 f7 d8 69 c0 f9 3f 5b 67 b9 fc e6 80 cd f7 d9
0010: 29 c8 81 e8 0f 76 37 2b 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: f7d8                 Neg { dst: Register(Eax) }
0003: 69c0f93f5b67         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(1734033401)) }
0009: b9fce680cd           Mov { dst: Register(Ecx), src: Immediate(-847190276) }
000e: f7d9                 Neg { dst: Register(Ecx) }
0010: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0012: 81e80f76372b         Sub { dst: Register(Eax), src: Immediate(725054991) }
0018: 5e                   Pop { dst: Esi }
0019: 5f                   Pop { dst: Edi }
001a: 5b                   Pop { dst: Ebx }
001b: c3                   Ret
```

SSA translation:
```
Block 0: Neg { dest: v792, operand: v785 }
Block 0: Const { dest: v793, value: I32(0) }
Block 0: Ceq { dest: v794, left: v785, right: v793 }
Block 0: Const { dest: v795, value: I32(1) }
Block 0: Xor { dest: v796, left: v794, right: v795 }
Block 0: Const { dest: v797, value: I32(1734033401) }
Block 0: Mul { dest: v798, left: v792, right: v797 }
Block 0: Const { dest: v799, value: I32(-847190276) }
Block 0: Neg { dest: v800, operand: v799 }
Block 0: Const { dest: v801, value: I32(0) }
Block 0: Ceq { dest: v802, left: v799, right: v801 }
Block 0: Const { dest: v803, value: I32(1) }
Block 0: Xor { dest: v804, left: v802, right: v803 }
Block 0: Sub { dest: v805, left: v798, right: v800 }
Block 0: Clt { dest: v806, left: v798, right: v800, unsigned: true }
Block 0: Const { dest: v807, value: I32(725054991) }
Block 0: Sub { dest: v808, left: v805, right: v807 }
Block 0: Clt { dest: v809, left: v805, right: v807, unsigned: true }
Block 0: Return { value: Some(v808) }
```

### Stub 28 — Token 0x06000016

| Field | Value |
|---|---|
| Token | `0x06000016` |
| RVA | `0x00007be8` |
| File offset | `0x00005de8` |
| Body size | 62 bytes |
| Total size | 82 bytes |
| Instructions | 17 |

Full bytes (82 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 b8 77 2f ad c8 81 e8 c8 d5 89 04 59
0020: ba da 3a fd a6 81 f2 d2 2f 26 fd bb 97 5f 5b 47
0030: 81 c3 73 74 20 b3 29 da 81 c2 ed 12 90 b2 31 d1
0040: 81 e9 73 a1 37 ba 29 c8 81 c0 17 3e 1b 33 5e 5f
0050: 5b c3
```

Body bytes (62 bytes, without prologue):
```
0000: b8 77 2f ad c8 81 e8 c8 d5 89 04 59 ba da 3a fd
0010: a6 81 f2 d2 2f 26 fd bb 97 5f 5b 47 81 c3 73 74
0020: 20 b3 29 da 81 c2 ed 12 90 b2 31 d1 81 e9 73 a1
0030: 37 ba 29 c8 81 c0 17 3e 1b 33 5e 5f 5b c3
```

Disassembly:
```
0000: b8772fadc8           Mov { dst: Register(Eax), src: Immediate(-928174217) }
0005: 81e8c8d58904         Sub { dst: Register(Eax), src: Immediate(76142024) }
000b: 59                   Pop { dst: Ecx }
000c: bada3afda6           Mov { dst: Register(Edx), src: Immediate(-1493353766) }
0011: 81f2d22f26fd         Xor { dst: Register(Edx), src: Immediate(-47829038) }
0017: bb975f5b47           Mov { dst: Register(Ebx), src: Immediate(1197170583) }
001c: 81c3737420b3         Add { dst: Register(Ebx), src: Immediate(-1289718669) }
0022: 29da                 Sub { dst: Register(Edx), src: Register(Ebx) }
0024: 81c2ed1290b2         Add { dst: Register(Edx), src: Immediate(-1299180819) }
002a: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
002c: 81e973a137ba         Sub { dst: Register(Ecx), src: Immediate(-1170759309) }
0032: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0034: 81c0173e1b33         Add { dst: Register(Eax), src: Immediate(857423383) }
003a: 5e                   Pop { dst: Esi }
003b: 5f                   Pop { dst: Edi }
003c: 5b                   Pop { dst: Ebx }
003d: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v820, value: I32(-928174217) }
Block 0: Const { dest: v821, value: I32(76142024) }
Block 0: Sub { dest: v822, left: v820, right: v821 }
Block 0: Clt { dest: v823, left: v820, right: v821, unsigned: true }
Block 0: Const { dest: v824, value: I32(-1493353766) }
Block 0: Const { dest: v825, value: I32(-47829038) }
Block 0: Xor { dest: v826, left: v824, right: v825 }
Block 0: Const { dest: v827, value: I32(0) }
Block 0: Const { dest: v828, value: I32(1197170583) }
Block 0: Const { dest: v829, value: I32(-1289718669) }
Block 0: Add { dest: v830, left: v828, right: v829 }
Block 0: Clt { dest: v831, left: v830, right: v828, unsigned: true }
Block 0: Sub { dest: v832, left: v826, right: v830 }
Block 0: Clt { dest: v833, left: v826, right: v830, unsigned: true }
Block 0: Const { dest: v834, value: I32(-1299180819) }
Block 0: Add { dest: v835, left: v832, right: v834 }
Block 0: Clt { dest: v836, left: v835, right: v832, unsigned: true }
Block 0: Xor { dest: v837, left: v813, right: v835 }
Block 0: Const { dest: v838, value: I32(0) }
Block 0: Const { dest: v839, value: I32(-1170759309) }
Block 0: Sub { dest: v840, left: v837, right: v839 }
Block 0: Clt { dest: v841, left: v837, right: v839, unsigned: true }
Block 0: Sub { dest: v842, left: v822, right: v840 }
Block 0: Clt { dest: v843, left: v822, right: v840, unsigned: true }
Block 0: Const { dest: v844, value: I32(857423383) }
Block 0: Add { dest: v845, left: v842, right: v844 }
Block 0: Clt { dest: v846, left: v845, right: v842, unsigned: true }
Block 0: Return { value: Some(v845) }
```

### Stub 29 — Token 0x06000017

| Field | Value |
|---|---|
| Token | `0x06000017` |
| RVA | `0x00007c3c` |
| File offset | `0x00005e3c` |
| Body size | 34 bytes |
| Total size | 54 bytes |
| Instructions | 12 |

Full bytes (54 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 69 c0 ef e0 11 18 b9 e4 73 99 58
0020: 81 e9 79 7a 29 1b f7 d1 29 c8 f7 d0 81 e8 05 c2
0030: ca 55 5e 5f 5b c3
```

Body bytes (34 bytes, without prologue):
```
0000: 58 69 c0 ef e0 11 18 b9 e4 73 99 58 81 e9 79 7a
0010: 29 1b f7 d1 29 c8 f7 d0 81 e8 05 c2 ca 55 5e 5f
0020: 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: 69c0efe01118         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(403824879)) }
0007: b9e4739958           Mov { dst: Register(Ecx), src: Immediate(1486451684) }
000c: 81e9797a291b         Sub { dst: Register(Ecx), src: Immediate(455703161) }
0012: f7d1                 Not { dst: Register(Ecx) }
0014: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0016: f7d0                 Not { dst: Register(Eax) }
0018: 81e805c2ca55         Sub { dst: Register(Eax), src: Immediate(1439351301) }
001e: 5e                   Pop { dst: Esi }
001f: 5f                   Pop { dst: Edi }
0020: 5b                   Pop { dst: Ebx }
0021: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v857, value: I32(403824879) }
Block 0: Mul { dest: v858, left: v850, right: v857 }
Block 0: Const { dest: v859, value: I32(1486451684) }
Block 0: Const { dest: v860, value: I32(455703161) }
Block 0: Sub { dest: v861, left: v859, right: v860 }
Block 0: Clt { dest: v862, left: v859, right: v860, unsigned: true }
Block 0: Not { dest: v863, operand: v861 }
Block 0: Sub { dest: v864, left: v858, right: v863 }
Block 0: Clt { dest: v865, left: v858, right: v863, unsigned: true }
Block 0: Not { dest: v866, operand: v864 }
Block 0: Const { dest: v867, value: I32(1439351301) }
Block 0: Sub { dest: v868, left: v866, right: v867 }
Block 0: Clt { dest: v869, left: v866, right: v867, unsigned: true }
Block 0: Return { value: Some(v868) }
```

### Stub 30 — Token 0x06000018

| Field | Value |
|---|---|
| Token | `0x06000018` |
| RVA | `0x00007c74` |
| File offset | `0x00005e74` |
| Body size | 59 bytes |
| Total size | 79 bytes |
| Instructions | 20 |

Full bytes (79 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 b8 a2 af 03 f9 f7 d8 81 f0 09 ce c4
0020: f5 59 ba 88 e4 55 1c 81 c2 38 a2 85 da bb 54 48
0030: b5 97 f7 d3 be 5e 78 ec 77 69 f6 85 53 ed 8c 01
0040: f3 29 da 29 d1 29 c8 f7 d8 f7 d0 5e 5f 5b c3
```

Body bytes (59 bytes, without prologue):
```
0000: b8 a2 af 03 f9 f7 d8 81 f0 09 ce c4 f5 59 ba 88
0010: e4 55 1c 81 c2 38 a2 85 da bb 54 48 b5 97 f7 d3
0020: be 5e 78 ec 77 69 f6 85 53 ed 8c 01 f3 29 da 29
0030: d1 29 c8 f7 d8 f7 d0 5e 5f 5b c3
```

Disassembly:
```
0000: b8a2af03f9           Mov { dst: Register(Eax), src: Immediate(-117198942) }
0005: f7d8                 Neg { dst: Register(Eax) }
0007: 81f009cec4f5         Xor { dst: Register(Eax), src: Immediate(-171651575) }
000d: 59                   Pop { dst: Ecx }
000e: ba88e4551c           Mov { dst: Register(Edx), src: Immediate(475391112) }
0013: 81c238a285da         Add { dst: Register(Edx), src: Immediate(-628776392) }
0019: bb5448b597           Mov { dst: Register(Ebx), src: Immediate(-1749727148) }
001e: f7d3                 Not { dst: Register(Ebx) }
0020: be5e78ec77           Mov { dst: Register(Esi), src: Immediate(2011986014) }
0025: 69f68553ed8c         Imul { dst: Esi, src: Register(Esi), src2: Some(Immediate(-1930603643)) }
002b: 01f3                 Add { dst: Register(Ebx), src: Register(Esi) }
002d: 29da                 Sub { dst: Register(Edx), src: Register(Ebx) }
002f: 29d1                 Sub { dst: Register(Ecx), src: Register(Edx) }
0031: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0033: f7d8                 Neg { dst: Register(Eax) }
0035: f7d0                 Not { dst: Register(Eax) }
0037: 5e                   Pop { dst: Esi }
0038: 5f                   Pop { dst: Edi }
0039: 5b                   Pop { dst: Ebx }
003a: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v880, value: I32(-117198942) }
Block 0: Neg { dest: v881, operand: v880 }
Block 0: Const { dest: v882, value: I32(0) }
Block 0: Ceq { dest: v883, left: v880, right: v882 }
Block 0: Const { dest: v884, value: I32(1) }
Block 0: Xor { dest: v885, left: v883, right: v884 }
Block 0: Const { dest: v886, value: I32(-171651575) }
Block 0: Xor { dest: v887, left: v881, right: v886 }
Block 0: Const { dest: v888, value: I32(0) }
Block 0: Const { dest: v889, value: I32(475391112) }
Block 0: Const { dest: v890, value: I32(-628776392) }
Block 0: Add { dest: v891, left: v889, right: v890 }
Block 0: Clt { dest: v892, left: v891, right: v889, unsigned: true }
Block 0: Const { dest: v893, value: I32(-1749727148) }
Block 0: Not { dest: v894, operand: v893 }
Block 0: Const { dest: v895, value: I32(2011986014) }
Block 0: Const { dest: v896, value: I32(-1930603643) }
Block 0: Mul { dest: v897, left: v895, right: v896 }
Block 0: Add { dest: v898, left: v894, right: v897 }
Block 0: Clt { dest: v899, left: v898, right: v894, unsigned: true }
Block 0: Sub { dest: v900, left: v891, right: v898 }
Block 0: Clt { dest: v901, left: v891, right: v898, unsigned: true }
Block 0: Sub { dest: v902, left: v873, right: v900 }
Block 0: Clt { dest: v903, left: v873, right: v900, unsigned: true }
Block 0: Sub { dest: v904, left: v887, right: v902 }
Block 0: Clt { dest: v905, left: v887, right: v902, unsigned: true }
Block 0: Neg { dest: v906, operand: v904 }
Block 0: Const { dest: v907, value: I32(0) }
Block 0: Ceq { dest: v908, left: v904, right: v907 }
Block 0: Const { dest: v909, value: I32(1) }
Block 0: Xor { dest: v910, left: v908, right: v909 }
Block 0: Not { dest: v911, operand: v906 }
Block 0: Return { value: Some(v911) }
```

### Stub 31 — Token 0x06000019

| Field | Value |
|---|---|
| Token | `0x06000019` |
| RVA | `0x00007cc4` |
| File offset | `0x00005ec4` |
| Body size | 49 bytes |
| Total size | 69 bytes |
| Instructions | 16 |

Full bytes (69 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 b9 e9 93 3f a3 f7 d9 ba 40 4e 6c
0020: 5e f7 d2 01 d1 69 c9 63 f2 98 4d 29 c8 f7 d8 81
0030: c0 1c 7d f9 1a 69 c0 59 79 89 62 81 f0 5c 82 6c
0040: 0e 5e 5f 5b c3
```

Body bytes (49 bytes, without prologue):
```
0000: 58 b9 e9 93 3f a3 f7 d9 ba 40 4e 6c 5e f7 d2 01
0010: d1 69 c9 63 f2 98 4d 29 c8 f7 d8 81 c0 1c 7d f9
0020: 1a 69 c0 59 79 89 62 81 f0 5c 82 6c 0e 5e 5f 5b
0030: c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: b9e9933fa3           Mov { dst: Register(Ecx), src: Immediate(-1556114455) }
0006: f7d9                 Neg { dst: Register(Ecx) }
0008: ba404e6c5e           Mov { dst: Register(Edx), src: Immediate(1584156224) }
000d: f7d2                 Not { dst: Register(Edx) }
000f: 01d1                 Add { dst: Register(Ecx), src: Register(Edx) }
0011: 69c963f2984d         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(1301869155)) }
0017: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
0019: f7d8                 Neg { dst: Register(Eax) }
001b: 81c01c7df91a         Add { dst: Register(Eax), src: Immediate(452558108) }
0021: 69c059798962         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(1653176665)) }
0027: 81f05c826c0e         Xor { dst: Register(Eax), src: Immediate(241992284) }
002d: 5e                   Pop { dst: Esi }
002e: 5f                   Pop { dst: Edi }
002f: 5b                   Pop { dst: Ebx }
0030: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v922, value: I32(-1556114455) }
Block 0: Neg { dest: v923, operand: v922 }
Block 0: Const { dest: v924, value: I32(0) }
Block 0: Ceq { dest: v925, left: v922, right: v924 }
Block 0: Const { dest: v926, value: I32(1) }
Block 0: Xor { dest: v927, left: v925, right: v926 }
Block 0: Const { dest: v928, value: I32(1584156224) }
Block 0: Not { dest: v929, operand: v928 }
Block 0: Add { dest: v930, left: v923, right: v929 }
Block 0: Clt { dest: v931, left: v930, right: v923, unsigned: true }
Block 0: Const { dest: v932, value: I32(1301869155) }
Block 0: Mul { dest: v933, left: v930, right: v932 }
Block 0: Sub { dest: v934, left: v915, right: v933 }
Block 0: Clt { dest: v935, left: v915, right: v933, unsigned: true }
Block 0: Neg { dest: v936, operand: v934 }
Block 0: Const { dest: v937, value: I32(0) }
Block 0: Ceq { dest: v938, left: v934, right: v937 }
Block 0: Const { dest: v939, value: I32(1) }
Block 0: Xor { dest: v940, left: v938, right: v939 }
Block 0: Const { dest: v941, value: I32(452558108) }
Block 0: Add { dest: v942, left: v936, right: v941 }
Block 0: Clt { dest: v943, left: v942, right: v936, unsigned: true }
Block 0: Const { dest: v944, value: I32(1653176665) }
Block 0: Mul { dest: v945, left: v942, right: v944 }
Block 0: Const { dest: v946, value: I32(241992284) }
Block 0: Xor { dest: v947, left: v945, right: v946 }
Block 0: Const { dest: v948, value: I32(0) }
Block 0: Return { value: Some(v947) }
```

### Stub 32 — Token 0x0600001a

| Field | Value |
|---|---|
| Token | `0x0600001a` |
| RVA | `0x00007d0c` |
| File offset | `0x00005f0c` |
| Body size | 54 bytes |
| Total size | 74 bytes |
| Instructions | 17 |

Full bytes (74 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 b8 37 bc 9c 23 f7 d8 59 ba 71 a9 ba
0020: 6d 81 ea cd 40 22 55 69 d2 b1 43 f1 55 bb 5f ff
0030: b9 16 f7 d3 01 da 31 d1 69 c9 9b 47 7d 02 29 c8
0040: 81 f0 7a b5 45 81 5e 5f 5b c3
```

Body bytes (54 bytes, without prologue):
```
0000: b8 37 bc 9c 23 f7 d8 59 ba 71 a9 ba 6d 81 ea cd
0010: 40 22 55 69 d2 b1 43 f1 55 bb 5f ff b9 16 f7 d3
0020: 01 da 31 d1 69 c9 9b 47 7d 02 29 c8 81 f0 7a b5
0030: 45 81 5e 5f 5b c3
```

Disassembly:
```
0000: b837bc9c23           Mov { dst: Register(Eax), src: Immediate(597474359) }
0005: f7d8                 Neg { dst: Register(Eax) }
0007: 59                   Pop { dst: Ecx }
0008: ba71a9ba6d           Mov { dst: Register(Edx), src: Immediate(1840949617) }
000d: 81eacd402255         Sub { dst: Register(Edx), src: Immediate(1428308173) }
0013: 69d2b143f155         Imul { dst: Edx, src: Register(Edx), src2: Some(Immediate(1441874865)) }
0019: bb5fffb916           Mov { dst: Register(Ebx), src: Immediate(381288287) }
001e: f7d3                 Not { dst: Register(Ebx) }
0020: 01da                 Add { dst: Register(Edx), src: Register(Ebx) }
0022: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
0024: 69c99b477d02         Imul { dst: Ecx, src: Register(Ecx), src2: Some(Immediate(41764763)) }
002a: 29c8                 Sub { dst: Register(Eax), src: Register(Ecx) }
002c: 81f07ab54581         Xor { dst: Register(Eax), src: Immediate(-2126137990) }
0032: 5e                   Pop { dst: Esi }
0033: 5f                   Pop { dst: Edi }
0034: 5b                   Pop { dst: Ebx }
0035: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v959, value: I32(597474359) }
Block 0: Neg { dest: v960, operand: v959 }
Block 0: Const { dest: v961, value: I32(0) }
Block 0: Ceq { dest: v962, left: v959, right: v961 }
Block 0: Const { dest: v963, value: I32(1) }
Block 0: Xor { dest: v964, left: v962, right: v963 }
Block 0: Const { dest: v965, value: I32(1840949617) }
Block 0: Const { dest: v966, value: I32(1428308173) }
Block 0: Sub { dest: v967, left: v965, right: v966 }
Block 0: Clt { dest: v968, left: v965, right: v966, unsigned: true }
Block 0: Const { dest: v969, value: I32(1441874865) }
Block 0: Mul { dest: v970, left: v967, right: v969 }
Block 0: Const { dest: v971, value: I32(381288287) }
Block 0: Not { dest: v972, operand: v971 }
Block 0: Add { dest: v973, left: v970, right: v972 }
Block 0: Clt { dest: v974, left: v973, right: v970, unsigned: true }
Block 0: Xor { dest: v975, left: v952, right: v973 }
Block 0: Const { dest: v976, value: I32(0) }
Block 0: Const { dest: v977, value: I32(41764763) }
Block 0: Mul { dest: v978, left: v975, right: v977 }
Block 0: Sub { dest: v979, left: v960, right: v978 }
Block 0: Clt { dest: v980, left: v960, right: v978, unsigned: true }
Block 0: Const { dest: v981, value: I32(-2126137990) }
Block 0: Xor { dest: v982, left: v979, right: v981 }
Block 0: Const { dest: v983, value: I32(0) }
Block 0: Return { value: Some(v982) }
```

### Stub 33 — Token 0x0600001b

| Field | Value |
|---|---|
| Token | `0x0600001b` |
| RVA | `0x00007d58` |
| File offset | `0x00005f58` |
| Body size | 52 bytes |
| Total size | 72 bytes |
| Instructions | 16 |

Full bytes (72 bytes, with prologue):
```
0000: 89 e0 53 57 56 29 e0 83 f8 18 74 07 8b 44 24 10
0010: 50 eb 01 51 58 69 c0 d9 26 ed 65 b9 ba 97 6e 61
0020: f7 d9 ba ed 1a 1a cd 81 ea 38 72 59 1d 31 d1 01
0030: c8 b9 48 84 93 bc 81 f1 4c ab 34 b2 31 c8 69 c0
0040: 57 d9 a6 b5 5e 5f 5b c3
```

Body bytes (52 bytes, without prologue):
```
0000: 58 69 c0 d9 26 ed 65 b9 ba 97 6e 61 f7 d9 ba ed
0010: 1a 1a cd 81 ea 38 72 59 1d 31 d1 01 c8 b9 48 84
0020: 93 bc 81 f1 4c ab 34 b2 31 c8 69 c0 57 d9 a6 b5
0030: 5e 5f 5b c3
```

Disassembly:
```
0000: 58                   Pop { dst: Eax }
0001: 69c0d926ed65         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(1710040793)) }
0007: b9ba976e61           Mov { dst: Register(Ecx), src: Immediate(1634637754) }
000c: f7d9                 Neg { dst: Register(Ecx) }
000e: baed1a1acd           Mov { dst: Register(Edx), src: Immediate(-853927187) }
0013: 81ea3872591d         Sub { dst: Register(Edx), src: Immediate(492401208) }
0019: 31d1                 Xor { dst: Register(Ecx), src: Register(Edx) }
001b: 01c8                 Add { dst: Register(Eax), src: Register(Ecx) }
001d: b9488493bc           Mov { dst: Register(Ecx), src: Immediate(-1131183032) }
0022: 81f14cab34b2         Xor { dst: Register(Ecx), src: Immediate(-1305171124) }
0028: 31c8                 Xor { dst: Register(Eax), src: Register(Ecx) }
002a: 69c057d9a6b5         Imul { dst: Eax, src: Register(Eax), src2: Some(Immediate(-1247356585)) }
0030: 5e                   Pop { dst: Esi }
0031: 5f                   Pop { dst: Edi }
0032: 5b                   Pop { dst: Ebx }
0033: c3                   Ret
```

SSA translation:
```
Block 0: Const { dest: v994, value: I32(1710040793) }
Block 0: Mul { dest: v995, left: v987, right: v994 }
Block 0: Const { dest: v996, value: I32(1634637754) }
Block 0: Neg { dest: v997, operand: v996 }
Block 0: Const { dest: v998, value: I32(0) }
Block 0: Ceq { dest: v999, left: v996, right: v998 }
Block 0: Const { dest: v1000, value: I32(1) }
Block 0: Xor { dest: v1001, left: v999, right: v1000 }
Block 0: Const { dest: v1002, value: I32(-853927187) }
Block 0: Const { dest: v1003, value: I32(492401208) }
Block 0: Sub { dest: v1004, left: v1002, right: v1003 }
Block 0: Clt { dest: v1005, left: v1002, right: v1003, unsigned: true }
Block 0: Xor { dest: v1006, left: v997, right: v1004 }
Block 0: Const { dest: v1007, value: I32(0) }
Block 0: Add { dest: v1008, left: v995, right: v1006 }
Block 0: Clt { dest: v1009, left: v1008, right: v995, unsigned: true }
Block 0: Const { dest: v1010, value: I32(-1131183032) }
Block 0: Const { dest: v1011, value: I32(-1305171124) }
Block 0: Xor { dest: v1012, left: v1010, right: v1011 }
Block 0: Const { dest: v1013, value: I32(0) }
Block 0: Xor { dest: v1014, left: v1008, right: v1012 }
Block 0: Const { dest: v1015, value: I32(0) }
Block 0: Const { dest: v1016, value: I32(-1247356585) }
Block 0: Mul { dest: v1017, left: v1014, right: v1016 }
Block 0: Return { value: Some(v1017) }
```
