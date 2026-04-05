# Anti Debug Protection

| Property | Value |
|----------|-------|
| **ID** | `Ki.AntiDebug` |
| **Short ID** | `anti debug` |
| **Preset** | Minimum |
| **Targets** | Modules |
| **Pipeline Stage** | PreStage of ProcessModule |
| **Dependencies** | Must run before `Ki.ControlFlow` |

## Overview

Prevents the assembly from being debugged or profiled at runtime. The protection injects runtime detection code into the module's static constructor (`.cctor`), which executes before any user code. Three modes provide escalating levels of sophistication, from pure managed API checks to direct CLR memory manipulation.

## Configuration

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `mode` | `Safe`, `Win32`, `Antinet` | `Safe` | Detection technique complexity |

## Injection Mechanism

1. Retrieves the runtime type for the selected mode from `Confuser.Runtime`
2. Uses `InjectHelper.Inject()` to copy the runtime type into the module's global type (`<Module>`)
3. Extracts the `Initialize()` method from the injected type
4. Inserts a `call Initialize` instruction at position 0 of the module `.cctor`
5. All injected members are:
   - Renamed to Unicode gibberish via `RenameMode.Unicode`
   - Changed from `public` to `Assembly` (internal) visibility
   - Marked as non-renameable to prevent further renaming passes
   - Have special name flags cleared (except constructors)
   - Have literal fields removed

For Antinet mode specifically, `HandleProcessCorruptedStateExceptionsAttribute` is also injected to allow unsafe exception handling.

## Mode: Safe

**Runtime type**: `Confuser.Runtime.AntiDebugSafe`

**Platform**: Cross-platform (pure managed .NET)

Uses only managed .NET APIs with no P/Invoke calls.

### Detection Techniques

1. **Profiler environment variable**: Checks `Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING")` for value `"1"`
2. **Managed debugger detection**: Checks `Debugger.IsAttached` and `Debugger.IsLogging()`

### Monitoring Architecture

Uses a **dual-thread watchdog pattern**:

- `Initialize()` creates a background worker thread, passing the current thread reference
- The worker thread creates a **second** worker thread (recursive pattern), then enters an infinite monitoring loop
- Every 1000ms, the worker checks:
  - `Debugger.IsAttached`
  - `Debugger.IsLogging()`
  - Whether the monitored thread is still alive (`th.IsAlive`)
- If any check fails: `Environment.FailFast(null)`

The recursive dual-thread design means Thread A monitors Thread B and vice versa. Killing one monitoring thread causes the other to detect the death and terminate the process.

## Mode: Win32

**Runtime type**: `Confuser.Runtime.AntiDebugWin32`

**Platform**: Windows only (uses P/Invoke)

### P/Invoke Declarations

```csharp
[DllImport("kernel32.dll")] static extern bool IsDebuggerPresent();
[DllImport("kernel32.dll")] static extern int OutputDebugString(string str);
[DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);
[DllImport("ntdll.dll")]    static extern int NtQueryInformationProcess(...);
```

### Detection Techniques

1. **Profiler environment variables**: Checks both `COR_PROFILER` and `COR_ENABLE_PROFILING`
2. **Parent process detection (anti-dnSpy)**: Uses `NtQueryInformationProcess` with `ProcessBasicInformation` (class 0) to extract parent PID from PEB, then checks if parent process name contains `"dnspy"` (case-insensitive)
3. **Managed debugger**: `Debugger.IsAttached` and `Debugger.IsLogging()`
4. **Native debugger**: `IsDebuggerPresent()` Win32 API
5. **Invalid handle detection**: Checks if `Process.GetCurrentProcess().Handle` is `IntPtr.Zero`
6. **OutputDebugString trick**: Calls `OutputDebugString("")` — when a debugger is attached, the return value exceeds `IntPtr.Size`; without a debugger, it returns 0

### Monitoring Architecture

Same dual-thread watchdog as Safe mode, but the worker loop includes all six detection checks every 1000ms. Additionally checks `CloseHandle(IntPtr.Zero)` exception behavior (different under debugger).

### Parent Process Resolution

Uses `PROCESS_BASIC_INFORMATION` structure layout:

```csharp
[StructLayout(LayoutKind.Sequential)]
struct ParentProcessUtilities {
    IntPtr Reserved1;
    IntPtr PebBaseAddress;
    IntPtr Reserved2_0, Reserved2_1;
    IntPtr UniqueProcessId;
    IntPtr InheritedFromUniqueProcessId;  // Parent PID
}
```

## Mode: Antinet

**Runtime type**: `Confuser.Runtime.AntiDebugAntinet`

**Platform**: Windows only (direct CLR memory manipulation)

**Origin**: Derived from [de4dot's antinet project](https://github.com/0xd4d/antinet)

The most aggressive mode. Rather than detecting debuggers, it **kills the debugger thread** and **prevents profiler attachment** by directly manipulating CLR internal data structures.

### Initialization Flow

```
Initialize()
├── InitializeAntiDebugger()
│   ├── Get CLR version/architecture-specific struct offsets
│   ├── Scan CLR .data section for Debugger singleton
│   ├── Corrupt IPC control block (set size to 0)
│   └── Signal debugger thread to exit (shouldKeepLooping = false)
├── InitializeAntiProfiler()
│   ├── Scan CLR .text section for profiler status patterns
│   ├── Create named pipe to block profiler attachment
│   ├── Patch profiler attach thread to return immediately
│   └── Corrupt ProfAPIMaxWaitForTriggerMs config
└── Check IsProfilerAttached
    ├── If true: FailFast()
    └── PreventActiveProfilerFromReceivingProfilingMessages()
```

### Anti-Managed Debugger

**Step 1: Get CLR-specific offsets**

Hardcoded struct field offsets vary by CLR version and architecture:

```csharp
// CLR 4.0 x86 example
Debugger_pDebuggerRCThread        = 0x08
Debugger_pid                      = 0x0C
DebuggerRCThread_pDebugger        = 0x34
DebuggerRCThread_pDebuggerIPCControlBlock = 0x38
DebuggerRCThread_shouldKeepLooping = 0x40
DebuggerRCThread_hEvent1          = 0x44
```

Supported CLR versions: 2.0 (x86/x64), 4.0 (x86 rev1/rev2, x64).

**Step 2: Locate Debugger instance**

Scans the CLR DLL's `.data` section for the `Debugger` singleton:

1. Iterate all pointer-aligned addresses in `.data`
2. Read candidate pointer as `pDebugger`
3. Verify `Debugger.pid` field matches current process ID
4. Read `Debugger.pDebuggerRCThread` to get the RC thread pointer
5. Cross-validate: `DebuggerRCThread.pDebugger` must point back to `pDebugger`

**Step 3: Corrupt IPC control block**

```csharp
// Set DebuggerIPCControlBlock size to 0
// Causes mscordbi!CordbProcess::VerifyControlBlock() to fail
*(uint*)pDebuggerIPCControlBlock = 0;
```

**Step 4: Signal debugger thread to exit**

```csharp
// Tell debugger RC thread to stop looping
*((byte*)pDebuggerRCThread + shouldKeepLooping) = 0;

// Wake the thread so it sees the flag
IntPtr hEvent = *(IntPtr*)(pDebuggerRCThread + hEvent1);
SetEvent(hEvent);
```

### Anti-Managed Profiler

#### CLR 2.0: Profiler Status Flag

Scans CLR `.text` section for the instruction pattern:

```asm
F6 05 XX XX XX XX 06    ; test byte ptr [profilerStatusFlag], 6
```

If bits 1 or 2 are set, a profiler is attached. Prevention: clear those bits:

```csharp
*(uint*)profilerStatusFlag &= ~6U;
```

#### CLR 4.0: Multiple Strategies

**Strategy 1 — Profiler control block detection**

Scans `.text` for instruction patterns that check profiler attachment status:

```asm
; 32-bit
A1 XX XX XX XX        ; mov eax, [profilerStatus]
83 F8 04              ; cmp eax, 4   (4 = attached)

; 64-bit
8B 05 XX XX XX XX     ; mov eax, [rip+profilerStatus]
83 F8 04              ; cmp eax, 4
```

Sets `profilerStatus = 0` to report no profiler.

**Strategy 2 — Named pipe ownership**

CLR 4.0 uses a named pipe for runtime profiler attachment:

```
\\.\pipe\CPFATP_{PID}_v{CLR_VERSION}
```

Antinet creates and **owns** this pipe with `nMaxInstances: 1`, preventing CLR from creating its own. Profilers cannot connect.

**Strategy 3 — Patch attach thread proc**

Locates `CreateThread` calls in CLR `.text` by scanning for the call pattern, then overwrites the thread procedure's prologue:

```asm
; 32-bit: xor eax,eax; retn 4
33 C0 C2 04 00
; 64-bit: xor eax,eax; retn
33 C0 C3
```

**Strategy 4 — Corrupt timeout config**

Finds the `ProfAPIMaxWaitForTriggerMs` config option in CLR memory:

1. Scans `.rdata`/`.text` for `ConfigDWORDInfo` structure containing the string pointer
2. Sets default value to 0 (immediate timeout)
3. Overwrites config name characters with random values to prevent user override

### PE Helper (PEInfo)

Utility class for navigating PE structures in memory:

- Reads DOS header at offset `0x3C` for PE signature location
- Parses section count, optional header size
- Provides `FindSection(name)` to locate sections by name
- Validates addresses against PE image bounds
- Handles both 32-bit and 64-bit optional headers (`0x010B` vs `0x020B` magic)

## Comparison Table

| Aspect | Safe | Win32 | Antinet |
|--------|------|-------|---------|
| Platform | Cross-platform | Windows | Windows |
| P/Invoke | None | 5 APIs | 8+ APIs |
| Memory patching | No | No | Yes (CLR internals) |
| Detection methods | 2 managed | 6+ mixed | Direct kill + prevention |
| Debugger response | Monitor & FailFast | Monitor & FailFast | Kill debugger thread |
| Profiler prevention | Env var only | Env var only | Pipe + patching + config |
| Bypass difficulty | Easy | Medium | Hard |

## dotscope Handling

Handled by `NeutralizationPass` — the injected `.cctor` call and associated types are identified and removed during cleanup.
