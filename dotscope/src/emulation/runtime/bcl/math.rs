//! `System.Math` and `System.Numerics.BitOperations` method hooks.
//!
//! This module provides hook implementations for mathematical operations commonly used
//! in obfuscation for numeric transformations, control flow flattening state machines,
//! and hash computations.
//!
//! # Overview
//!
//! Mathematical operations are fundamental to many obfuscation techniques:
//! - **Control flow flattening**: Uses arithmetic to compute switch cases
//! - **Opaque predicates**: Complex math expressions that always evaluate to known values
//! - **Bit manipulation**: `BitOperations` for XOR-based encryption state
//!
//! # Hooked .NET Methods
//!
//! ## Basic Math
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Abs(x)` | Absolute value |
//! | `Math.Min(a, b)` | Minimum of two values |
//! | `Math.Max(a, b)` | Maximum of two values |
//! | `Math.Sign(x)` | Returns -1, 0, or 1 |
//! | `Math.Clamp(val, min, max)` | Constrains value to range |
//! | `Math.DivRem(a, b)` | Division with remainder |
//!
//! ## Rounding
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Floor(x)` | Round down |
//! | `Math.Ceiling(x)` | Round up |
//! | `Math.Round(x, [decimals])` | Round to nearest |
//! | `Math.Truncate(x)` | Remove fractional part |
//!
//! ## Power and Logarithms
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Pow(x, y)` | x raised to power y |
//! | `Math.Sqrt(x)` | Square root |
//! | `Math.Log(x, [base])` | Natural or custom base log |
//! | `Math.Log10(x)` | Base-10 logarithm |
//! | `Math.Exp(x)` | e raised to power x |
//!
//! ## Trigonometry
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Math.Sin`, `Cos`, `Tan` | Basic trigonometric functions |
//! | `Math.Asin`, `Acos`, `Atan` | Inverse trigonometric functions |
//! | `Math.Atan2(y, x)` | Two-argument arctangent |
//!
//! ## BitOperations (System.Numerics)
//!
//! | Method | Description |
//! |--------|-------------|
//! | `PopCount(x)` | Count set bits |
//! | `LeadingZeroCount(x)` | Leading zero bits |
//! | `TrailingZeroCount(x)` | Trailing zero bits |
//! | `RotateLeft(x, n)` | Rotate bits left |
//! | `RotateRight(x, n)` | Rotate bits right |
//!
//! # Deobfuscation Use Cases
//!
//! ## Control Flow Flattening
//!
//! ```csharp
//! int state = initialState;
//! while (true) {
//!     switch (state) {
//!         case 0: state = Math.Abs(x - 5); break;  // Computed dispatch
//!         // ...
//!     }
//! }
//! ```
//!
//! ## XOR Key Derivation
//!
//! ```csharp
//! int key = BitOperations.RotateLeft(seed, 13);
//! key ^= BitOperations.PopCount(magic);
//! ```

use crate::emulation::{
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all `System.Math` and `BitOperations` method hooks.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Methods
///
/// - **Basic**: `Abs`, `Min`, `Max`, `Sign`, `Clamp`, `DivRem`
/// - **Rounding**: `Floor`, `Ceiling`, `Round`, `Truncate`
/// - **Power/Log**: `Pow`, `Sqrt`, `Log`, `Log10`, `Exp`
/// - **Trig**: `Sin`, `Cos`, `Tan`, `Asin`, `Acos`, `Atan`, `Atan2`
/// - **BitOps**: `PopCount`, `LeadingZeroCount`, `TrailingZeroCount`, `RotateLeft`, `RotateRight`
pub fn register(manager: &mut HookManager) {
    // Basic math
    manager.register(
        Hook::new("System.Math.Abs")
            .match_name("System", "Math", "Abs")
            .pre(system_math_abs_pre),
    );
    manager.register(
        Hook::new("System.Math.Min")
            .match_name("System", "Math", "Min")
            .pre(system_math_min_pre),
    );
    manager.register(
        Hook::new("System.Math.Max")
            .match_name("System", "Math", "Max")
            .pre(system_math_max_pre),
    );
    manager.register(
        Hook::new("System.Math.Sign")
            .match_name("System", "Math", "Sign")
            .pre(system_math_sign_pre),
    );
    manager.register(
        Hook::new("System.Math.Clamp")
            .match_name("System", "Math", "Clamp")
            .pre(system_math_clamp_pre),
    );
    manager.register(
        Hook::new("System.Math.DivRem")
            .match_name("System", "Math", "DivRem")
            .pre(system_math_divrem_pre),
    );

    // Rounding
    manager.register(
        Hook::new("System.Math.Floor")
            .match_name("System", "Math", "Floor")
            .pre(system_math_floor_pre),
    );
    manager.register(
        Hook::new("System.Math.Ceiling")
            .match_name("System", "Math", "Ceiling")
            .pre(system_math_ceiling_pre),
    );
    manager.register(
        Hook::new("System.Math.Round")
            .match_name("System", "Math", "Round")
            .pre(system_math_round_pre),
    );
    manager.register(
        Hook::new("System.Math.Truncate")
            .match_name("System", "Math", "Truncate")
            .pre(system_math_truncate_pre),
    );

    // Power/Log
    manager.register(
        Hook::new("System.Math.Pow")
            .match_name("System", "Math", "Pow")
            .pre(system_math_pow_pre),
    );
    manager.register(
        Hook::new("System.Math.Sqrt")
            .match_name("System", "Math", "Sqrt")
            .pre(system_math_sqrt_pre),
    );
    manager.register(
        Hook::new("System.Math.Log")
            .match_name("System", "Math", "Log")
            .pre(system_math_log_pre),
    );
    manager.register(
        Hook::new("System.Math.Log10")
            .match_name("System", "Math", "Log10")
            .pre(system_math_log10_pre),
    );
    manager.register(
        Hook::new("System.Math.Exp")
            .match_name("System", "Math", "Exp")
            .pre(system_math_exp_pre),
    );

    // Trigonometry
    manager.register(
        Hook::new("System.Math.Sin")
            .match_name("System", "Math", "Sin")
            .pre(system_math_sin_pre),
    );
    manager.register(
        Hook::new("System.Math.Cos")
            .match_name("System", "Math", "Cos")
            .pre(system_math_cos_pre),
    );
    manager.register(
        Hook::new("System.Math.Tan")
            .match_name("System", "Math", "Tan")
            .pre(system_math_tan_pre),
    );
    manager.register(
        Hook::new("System.Math.Asin")
            .match_name("System", "Math", "Asin")
            .pre(system_math_asin_pre),
    );
    manager.register(
        Hook::new("System.Math.Acos")
            .match_name("System", "Math", "Acos")
            .pre(system_math_acos_pre),
    );
    manager.register(
        Hook::new("System.Math.Atan")
            .match_name("System", "Math", "Atan")
            .pre(system_math_atan_pre),
    );
    manager.register(
        Hook::new("System.Math.Atan2")
            .match_name("System", "Math", "Atan2")
            .pre(system_math_atan2_pre),
    );

    // BitOperations
    manager.register(
        Hook::new("System.Numerics.BitOperations.PopCount")
            .match_name("System.Numerics", "BitOperations", "PopCount")
            .pre(system_numerics_bitoperations_popcount_pre),
    );
    manager.register(
        Hook::new("System.Numerics.BitOperations.LeadingZeroCount")
            .match_name("System.Numerics", "BitOperations", "LeadingZeroCount")
            .pre(system_numerics_bitoperations_leadingzerocount_pre),
    );
    manager.register(
        Hook::new("System.Numerics.BitOperations.TrailingZeroCount")
            .match_name("System.Numerics", "BitOperations", "TrailingZeroCount")
            .pre(system_numerics_bitoperations_trailingzerocount_pre),
    );
    manager.register(
        Hook::new("System.Numerics.BitOperations.RotateLeft")
            .match_name("System.Numerics", "BitOperations", "RotateLeft")
            .pre(system_numerics_bitoperations_rotateleft_pre),
    );
    manager.register(
        Hook::new("System.Numerics.BitOperations.RotateRight")
            .match_name("System.Numerics", "BitOperations", "RotateRight")
            .pre(system_numerics_bitoperations_rotateright_pre),
    );
}

/// Hook for `System.Math.Abs` method.
///
/// Returns the absolute value of a number.
///
/// # Handled Overloads
///
/// - `Math.Abs(SByte) -> SByte`
/// - `Math.Abs(Int16) -> Int16`
/// - `Math.Abs(Int32) -> Int32`
/// - `Math.Abs(Int64) -> Int64`
/// - `Math.Abs(Single) -> Single`
/// - `Math.Abs(Double) -> Double`
/// - `Math.Abs(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `value`: The number whose absolute value is to be found
fn system_math_abs_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i32.into()));
    }

    let result = match &ctx.args[0] {
        EmValue::I32(n) => n.abs().into(),
        EmValue::I64(n) => n.abs().into(),
        EmValue::F32(f) => f.abs().into(),
        EmValue::F64(f) => f.abs().into(),
        _ => 0_i32.into(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Min` method.
///
/// Returns the smaller of two numbers.
///
/// # Handled Overloads
///
/// - `Math.Min(SByte, SByte) -> SByte`
/// - `Math.Min(Byte, Byte) -> Byte`
/// - `Math.Min(Int16, Int16) -> Int16`
/// - `Math.Min(UInt16, UInt16) -> UInt16`
/// - `Math.Min(Int32, Int32) -> Int32`
/// - `Math.Min(UInt32, UInt32) -> UInt32`
/// - `Math.Min(Int64, Int64) -> Int64`
/// - `Math.Min(UInt64, UInt64) -> UInt64`
/// - `Math.Min(Single, Single) -> Single`
/// - `Math.Min(Double, Double) -> Double`
/// - `Math.Min(Decimal, Decimal) -> Decimal`
///
/// # Parameters
///
/// - `val1`: The first of two values to compare
/// - `val2`: The second of two values to compare
fn system_math_min_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    }

    let result = match (&ctx.args[0], &ctx.args[1]) {
        (EmValue::I32(a), EmValue::I32(b)) => (*a.min(b)).into(),
        (EmValue::I64(a), EmValue::I64(b)) => (*a.min(b)).into(),
        (EmValue::F32(a), EmValue::F32(b)) => a.min(*b).into(),
        (EmValue::F64(a), EmValue::F64(b)) => a.min(*b).into(),
        _ => ctx.args[0].clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Max` method.
///
/// Returns the larger of two numbers.
///
/// # Handled Overloads
///
/// - `Math.Max(SByte, SByte) -> SByte`
/// - `Math.Max(Byte, Byte) -> Byte`
/// - `Math.Max(Int16, Int16) -> Int16`
/// - `Math.Max(UInt16, UInt16) -> UInt16`
/// - `Math.Max(Int32, Int32) -> Int32`
/// - `Math.Max(UInt32, UInt32) -> UInt32`
/// - `Math.Max(Int64, Int64) -> Int64`
/// - `Math.Max(UInt64, UInt64) -> UInt64`
/// - `Math.Max(Single, Single) -> Single`
/// - `Math.Max(Double, Double) -> Double`
/// - `Math.Max(Decimal, Decimal) -> Decimal`
///
/// # Parameters
///
/// - `val1`: The first of two values to compare
/// - `val2`: The second of two values to compare
fn system_math_max_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    }

    let result = match (&ctx.args[0], &ctx.args[1]) {
        (EmValue::I32(a), EmValue::I32(b)) => EmValue::I32(*a.max(b)),
        (EmValue::I64(a), EmValue::I64(b)) => EmValue::I64(*a.max(b)),
        (EmValue::F32(a), EmValue::F32(b)) => EmValue::F32(a.max(*b)),
        (EmValue::F64(a), EmValue::F64(b)) => EmValue::F64(a.max(*b)),
        _ => ctx.args[0].clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Sign` method.
///
/// Returns -1, 0, or 1 indicating the sign of a number.
///
/// # Handled Overloads
///
/// - `Math.Sign(SByte) -> Int32`
/// - `Math.Sign(Int16) -> Int32`
/// - `Math.Sign(Int32) -> Int32`
/// - `Math.Sign(Int64) -> Int32`
/// - `Math.Sign(Single) -> Int32`
/// - `Math.Sign(Double) -> Int32`
/// - `Math.Sign(Decimal) -> Int32`
///
/// # Parameters
///
/// - `value`: A signed number
fn system_math_sign_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let result = match &ctx.args[0] {
        EmValue::I32(n) => n.signum(),
        EmValue::I64(n) => n.signum() as i32,
        EmValue::F32(f) => {
            if f.is_nan() {
                0
            } else if *f > 0.0 {
                1
            } else if *f < 0.0 {
                -1
            } else {
                0
            }
        }
        EmValue::F64(f) => {
            if f.is_nan() {
                0
            } else if *f > 0.0 {
                1
            } else if *f < 0.0 {
                -1
            } else {
                0
            }
        }
        _ => 0,
    };

    PreHookResult::Bypass(Some(EmValue::I32(result)))
}

/// Hook for `System.Math.Clamp` method.
///
/// Returns `value` clamped to the inclusive range of `min` and `max`.
///
/// # Handled Overloads
///
/// - `Math.Clamp(SByte, SByte, SByte) -> SByte`
/// - `Math.Clamp(Byte, Byte, Byte) -> Byte`
/// - `Math.Clamp(Int16, Int16, Int16) -> Int16`
/// - `Math.Clamp(UInt16, UInt16, UInt16) -> UInt16`
/// - `Math.Clamp(Int32, Int32, Int32) -> Int32`
/// - `Math.Clamp(UInt32, UInt32, UInt32) -> UInt32`
/// - `Math.Clamp(Int64, Int64, Int64) -> Int64`
/// - `Math.Clamp(UInt64, UInt64, UInt64) -> UInt64`
/// - `Math.Clamp(Single, Single, Single) -> Single`
/// - `Math.Clamp(Double, Double, Double) -> Double`
/// - `Math.Clamp(Decimal, Decimal, Decimal) -> Decimal`
///
/// # Parameters
///
/// - `value`: The value to be clamped
/// - `min`: The lower bound of the result
/// - `max`: The upper bound of the result
fn system_math_clamp_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 3 {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    }

    let result = match (&ctx.args[0], &ctx.args[1], &ctx.args[2]) {
        (EmValue::I32(val), EmValue::I32(min), EmValue::I32(max)) => {
            EmValue::I32(*val.max(min).min(max))
        }
        (EmValue::I64(val), EmValue::I64(min), EmValue::I64(max)) => {
            EmValue::I64(*val.max(min).min(max))
        }
        (EmValue::F32(val), EmValue::F32(min), EmValue::F32(max)) => {
            EmValue::F32(val.max(*min).min(*max))
        }
        (EmValue::F64(val), EmValue::F64(min), EmValue::F64(max)) => {
            EmValue::F64(val.max(*min).min(*max))
        }
        _ => ctx.args[0].clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.DivRem` method.
///
/// Calculates the quotient and remainder of two numbers.
///
/// # Handled Overloads
///
/// - `Math.DivRem(Int32, Int32, out Int32) -> Int32`
/// - `Math.DivRem(Int64, Int64, out Int64) -> Int64`
/// - `Math.DivRem(Int32, Int32) -> (Int32, Int32)` (.NET 6+)
/// - `Math.DivRem(Int64, Int64) -> (Int64, Int64)` (.NET 6+)
///
/// # Parameters
///
/// - `a`: The dividend
/// - `b`: The divisor
/// - `result` (out): The remainder (for legacy overloads)
fn system_math_divrem_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let (quotient, remainder) = match (&ctx.args[0], &ctx.args[1]) {
        (EmValue::I32(a), EmValue::I32(b)) => {
            if *b == 0 {
                (EmValue::I32(0), EmValue::I32(0))
            } else {
                (EmValue::I32(a / b), EmValue::I32(a % b))
            }
        }
        (EmValue::I64(a), EmValue::I64(b)) => {
            if *b == 0 {
                (EmValue::I64(0), EmValue::I64(0))
            } else {
                (EmValue::I64(a / b), EmValue::I64(a % b))
            }
        }
        _ => (EmValue::I32(0), EmValue::I32(0)),
    };

    // Store remainder through the out parameter if provided
    if ctx.args.len() >= 3 {
        if let Some(ptr) = ctx.args[2].as_managed_ptr() {
            let _ = thread.store_through_pointer(ptr, remainder);
        }
    }

    PreHookResult::Bypass(Some(quotient))
}

/// Hook for `System.Math.Floor` method.
///
/// Returns the largest integral value less than or equal to the specified number.
///
/// # Handled Overloads
///
/// - `Math.Floor(Double) -> Double`
/// - `Math.Floor(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `d`: A double-precision floating-point number
fn system_math_floor_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let result = match &ctx.args[0] {
        EmValue::F32(f) => EmValue::F64(f64::from(f.floor())),
        EmValue::F64(f) => EmValue::F64(f.floor()),
        _ => EmValue::F64(0.0),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Ceiling` method.
///
/// Returns the smallest integral value greater than or equal to the specified number.
///
/// # Handled Overloads
///
/// - `Math.Ceiling(Double) -> Double`
/// - `Math.Ceiling(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `d`: A double-precision floating-point number
fn system_math_ceiling_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let result = match &ctx.args[0] {
        EmValue::F32(f) => EmValue::F64(f64::from(f.ceil())),
        EmValue::F64(f) => EmValue::F64(f.ceil()),
        _ => EmValue::F64(0.0),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Round` method.
///
/// Rounds a value to the nearest integer or specified number of decimal places.
///
/// # Handled Overloads
///
/// - `Math.Round(Double) -> Double`
/// - `Math.Round(Double, Int32) -> Double`
/// - `Math.Round(Double, MidpointRounding) -> Double`
/// - `Math.Round(Double, Int32, MidpointRounding) -> Double`
/// - `Math.Round(Decimal) -> Decimal`
/// - `Math.Round(Decimal, Int32) -> Decimal`
/// - `Math.Round(Decimal, MidpointRounding) -> Decimal`
/// - `Math.Round(Decimal, Int32, MidpointRounding) -> Decimal`
///
/// # Parameters
///
/// - `value`: A double-precision floating-point number to be rounded
/// - `digits`: The number of fractional digits in the return value (optional)
/// - `mode`: Specification for how to round value if it is midway (optional)
fn system_math_round_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = match &ctx.args[0] {
        EmValue::F32(f) => f64::from(*f),
        EmValue::F64(f) => *f,
        _ => return PreHookResult::Bypass(Some(EmValue::F64(0.0))),
    };

    let decimals = if ctx.args.len() > 1 {
        match &ctx.args[1] {
            EmValue::I32(n) => (*n).clamp(0, 15),
            _ => 0,
        }
    } else {
        0
    };

    let multiplier = 10_f64.powi(decimals);
    let rounded = (value * multiplier).round() / multiplier;

    PreHookResult::Bypass(Some(EmValue::F64(rounded)))
}

/// Hook for `System.Math.Truncate` method.
///
/// Calculates the integral part of a number.
///
/// # Handled Overloads
///
/// - `Math.Truncate(Double) -> Double`
/// - `Math.Truncate(Decimal) -> Decimal`
///
/// # Parameters
///
/// - `d`: A number to truncate
fn system_math_truncate_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let result = match &ctx.args[0] {
        EmValue::F32(f) => EmValue::F64(f64::from(f.trunc())),
        EmValue::F64(f) => EmValue::F64(f.trunc()),
        _ => EmValue::F64(0.0),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Math.Pow` method.
///
/// Returns a specified number raised to the specified power.
///
/// # Handled Overloads
///
/// - `Math.Pow(Double, Double) -> Double`
///
/// # Parameters
///
/// - `x`: A double-precision floating-point number to be raised to a power
/// - `y`: A double-precision floating-point number that specifies a power
fn system_math_pow_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let base = to_f64(&ctx.args[0]);
    let exp = to_f64(&ctx.args[1]);

    PreHookResult::Bypass(Some(EmValue::F64(base.powf(exp))))
}

/// Hook for `System.Math.Sqrt` method.
///
/// Returns the square root of a specified number.
///
/// # Handled Overloads
///
/// - `Math.Sqrt(Double) -> Double`
///
/// # Parameters
///
/// - `d`: The number whose square root is to be found
fn system_math_sqrt_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.sqrt())))
}

/// Hook for `System.Math.Log` method.
///
/// Returns the natural (base e) or specified base logarithm of a number.
///
/// # Handled Overloads
///
/// - `Math.Log(Double) -> Double`
/// - `Math.Log(Double, Double) -> Double`
///
/// # Parameters
///
/// - `d`: The number whose logarithm is to be found
/// - `newBase`: The base of the logarithm (optional, defaults to e)
fn system_math_log_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(f64::NEG_INFINITY)));
    }

    let value = to_f64(&ctx.args[0]);

    let result = if ctx.args.len() > 1 {
        let base = to_f64(&ctx.args[1]);
        value.log(base)
    } else {
        value.ln()
    };

    PreHookResult::Bypass(Some(EmValue::F64(result)))
}

/// Hook for `System.Math.Log10` method.
///
/// Returns the base 10 logarithm of a specified number.
///
/// # Handled Overloads
///
/// - `Math.Log10(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number whose logarithm is to be found
fn system_math_log10_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(f64::NEG_INFINITY)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.log10())))
}

/// Hook for `System.Math.Exp` method.
///
/// Returns e raised to the specified power.
///
/// # Handled Overloads
///
/// - `Math.Exp(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number specifying a power
fn system_math_exp_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(1.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.exp())))
}

/// Hook for `System.Math.Sin` method.
///
/// Returns the sine of the specified angle.
///
/// # Handled Overloads
///
/// - `Math.Sin(Double) -> Double`
///
/// # Parameters
///
/// - `a`: An angle, measured in radians
fn system_math_sin_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.sin())))
}

/// Hook for `System.Math.Cos` method.
///
/// Returns the cosine of the specified angle.
///
/// # Handled Overloads
///
/// - `Math.Cos(Double) -> Double`
///
/// # Parameters
///
/// - `d`: An angle, measured in radians
fn system_math_cos_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(1.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.cos())))
}

/// Hook for `System.Math.Tan` method.
///
/// Returns the tangent of the specified angle.
///
/// # Handled Overloads
///
/// - `Math.Tan(Double) -> Double`
///
/// # Parameters
///
/// - `a`: An angle, measured in radians
fn system_math_tan_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.tan())))
}

/// Hook for `System.Math.Asin` method.
///
/// Returns the angle whose sine is the specified number.
///
/// # Handled Overloads
///
/// - `Math.Asin(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number representing a sine, where d must be >= -1 and <= 1
fn system_math_asin_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.asin())))
}

/// Hook for `System.Math.Acos` method.
///
/// Returns the angle whose cosine is the specified number.
///
/// # Handled Overloads
///
/// - `Math.Acos(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number representing a cosine, where d must be >= -1 and <= 1
fn system_math_acos_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(std::f64::consts::FRAC_PI_2)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.acos())))
}

/// Hook for `System.Math.Atan` method.
///
/// Returns the angle whose tangent is the specified number.
///
/// # Handled Overloads
///
/// - `Math.Atan(Double) -> Double`
///
/// # Parameters
///
/// - `d`: A number representing a tangent
fn system_math_atan_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let value = to_f64(&ctx.args[0]);
    PreHookResult::Bypass(Some(EmValue::F64(value.atan())))
}

/// Hook for `System.Math.Atan2` method.
///
/// Returns the angle whose tangent is the quotient of two specified numbers.
///
/// # Handled Overloads
///
/// - `Math.Atan2(Double, Double) -> Double`
///
/// # Parameters
///
/// - `y`: The y coordinate of a point
/// - `x`: The x coordinate of a point
fn system_math_atan2_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::F64(0.0)));
    }

    let y = to_f64(&ctx.args[0]);
    let x = to_f64(&ctx.args[1]);

    PreHookResult::Bypass(Some(EmValue::F64(y.atan2(x))))
}

/// Hook for `System.Numerics.BitOperations.PopCount` method.
///
/// Returns the population count (number of bits set) of an integer.
///
/// # Handled Overloads
///
/// - `BitOperations.PopCount(UInt32) -> Int32`
/// - `BitOperations.PopCount(UInt64) -> Int32`
/// - `BitOperations.PopCount(UIntPtr) -> Int32`
///
/// # Parameters
///
/// - `value`: The value whose set bits are to be counted
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn system_numerics_bitoperations_popcount_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let count = match &ctx.args[0] {
        EmValue::I32(n) => (*n as u32).count_ones() as i32,
        EmValue::I64(n) => (*n as u64).count_ones() as i32,
        _ => 0,
    };

    PreHookResult::Bypass(Some(EmValue::I32(count)))
}

/// Hook for `System.Numerics.BitOperations.LeadingZeroCount` method.
///
/// Counts the number of leading zero bits in an integer.
///
/// # Handled Overloads
///
/// - `BitOperations.LeadingZeroCount(UInt32) -> Int32`
/// - `BitOperations.LeadingZeroCount(UInt64) -> Int32`
/// - `BitOperations.LeadingZeroCount(UIntPtr) -> Int32`
///
/// # Parameters
///
/// - `value`: The value whose leading zeros are to be counted
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn system_numerics_bitoperations_leadingzerocount_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(32)));
    }

    let count = match &ctx.args[0] {
        EmValue::I32(n) => (*n as u32).leading_zeros() as i32,
        EmValue::I64(n) => (*n as u64).leading_zeros() as i32,
        _ => 32,
    };

    PreHookResult::Bypass(Some(EmValue::I32(count)))
}

/// Hook for `System.Numerics.BitOperations.TrailingZeroCount` method.
///
/// Counts the number of trailing zero bits in an integer.
///
/// # Handled Overloads
///
/// - `BitOperations.TrailingZeroCount(Int32) -> Int32`
/// - `BitOperations.TrailingZeroCount(Int64) -> Int32`
/// - `BitOperations.TrailingZeroCount(UInt32) -> Int32`
/// - `BitOperations.TrailingZeroCount(UInt64) -> Int32`
/// - `BitOperations.TrailingZeroCount(IntPtr) -> Int32`
/// - `BitOperations.TrailingZeroCount(UIntPtr) -> Int32`
///
/// # Parameters
///
/// - `value`: The value whose trailing zeros are to be counted
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn system_numerics_bitoperations_trailingzerocount_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(32)));
    }

    let count = match &ctx.args[0] {
        EmValue::I32(n) => (*n as u32).trailing_zeros() as i32,
        EmValue::I64(n) => (*n as u64).trailing_zeros() as i32,
        _ => 32,
    };

    PreHookResult::Bypass(Some(EmValue::I32(count)))
}

/// Hook for `System.Numerics.BitOperations.RotateLeft` method.
///
/// Rotates the specified value left by the specified number of bits.
///
/// # Handled Overloads
///
/// - `BitOperations.RotateLeft(UInt32, Int32) -> UInt32`
/// - `BitOperations.RotateLeft(UInt64, Int32) -> UInt64`
/// - `BitOperations.RotateLeft(UIntPtr, Int32) -> UIntPtr`
///
/// # Parameters
///
/// - `value`: The value to rotate
/// - `offset`: The number of bits to rotate by
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn system_numerics_bitoperations_rotateleft_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    }

    let shift = match &ctx.args[1] {
        EmValue::I32(n) => *n as u32,
        _ => return PreHookResult::Bypass(Some(ctx.args[0].clone())),
    };

    let result = match &ctx.args[0] {
        EmValue::I32(n) => EmValue::I32((*n as u32).rotate_left(shift) as i32),
        EmValue::I64(n) => EmValue::I64((*n as u64).rotate_left(shift) as i64),
        _ => ctx.args[0].clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Numerics.BitOperations.RotateRight` method.
///
/// Rotates the specified value right by the specified number of bits.
///
/// # Handled Overloads
///
/// - `BitOperations.RotateRight(UInt32, Int32) -> UInt32`
/// - `BitOperations.RotateRight(UInt64, Int32) -> UInt64`
/// - `BitOperations.RotateRight(UIntPtr, Int32) -> UIntPtr`
///
/// # Parameters
///
/// - `value`: The value to rotate
/// - `offset`: The number of bits to rotate by
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn system_numerics_bitoperations_rotateright_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(ctx.args.first().cloned());
    }

    let shift = match &ctx.args[1] {
        EmValue::I32(n) => *n as u32,
        _ => return PreHookResult::Bypass(Some(ctx.args[0].clone())),
    };

    let result = match &ctx.args[0] {
        EmValue::I32(n) => EmValue::I32((*n as u32).rotate_right(shift) as i32),
        EmValue::I64(n) => EmValue::I64((*n as u64).rotate_right(shift) as i64),
        _ => ctx.args[0].clone(),
    };

    PreHookResult::Bypass(Some(result))
}

/// Helper to convert EmValue to f64.
#[allow(clippy::cast_precision_loss)]
fn to_f64(value: &EmValue) -> f64 {
    match value {
        EmValue::I32(n) => f64::from(*n),
        EmValue::I64(n) => *n as f64,
        EmValue::F32(f) => f64::from(*f),
        EmValue::F64(f) => *f,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::HookManager, metadata::typesystem::PointerSize,
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);

        // Should have registered all math hooks
        assert!(manager.len() > 20);
    }

    #[test]
    fn test_abs_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(-5)]);

        let result = system_math_abs_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(5))) => {}
            _ => panic!("Expected Bypass(Some(I32(5)))"),
        }
    }

    #[test]
    fn test_min_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(3), EmValue::I32(7)]);

        let result = system_math_min_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(3))) => {}
            _ => panic!("Expected Bypass(Some(I32(3)))"),
        }
    }

    #[test]
    fn test_max_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(3), EmValue::I32(7)]);

        let result = system_math_max_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(7))) => {}
            _ => panic!("Expected Bypass(Some(I32(7)))"),
        }
    }

    #[test]
    fn test_pow_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::F64(2.0), EmValue::F64(3.0)]);

        let result = system_math_pow_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::F64(val))) if (val - 8.0).abs() < 0.001 => {}
            _ => panic!("Expected Bypass(Some(F64(8.0)))"),
        }
    }

    #[test]
    fn test_rotate_left_hook() {
        let mut thread = create_test_thread();
        let ctx = create_test_context(&[EmValue::I32(1), EmValue::I32(4)]);

        let result = system_numerics_bitoperations_rotateleft_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(16))) => {}
            _ => panic!("Expected Bypass(Some(I32(16)))"),
        }
    }

    // Helper to create test context with args
    fn create_test_context(args: &[EmValue]) -> HookContext<'_> {
        use crate::metadata::token::Token;

        HookContext::new(
            Token::new(0x06000001),
            "System",
            "Math",
            "Abs",
            PointerSize::Bit64,
        )
        .with_args(args)
    }
}
