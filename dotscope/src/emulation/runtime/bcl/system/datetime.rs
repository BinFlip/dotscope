//! `System.DateTime` and `System.TimeSpan` method hooks.
//!
//! Provides emulation for the core .NET date/time value types used extensively
//! by obfuscator trial guards and timestamp-based integrity checks.
//!
//! # Representation
//!
//! Both `DateTime` and `TimeSpan` are value types wrapping a single `i64` Ticks
//! field (100-nanosecond intervals since 0001-01-01 00:00:00 UTC for DateTime,
//! or a signed duration for TimeSpan). On the CIL evaluation stack they appear
//! as `I64(ticks)`.
//!
//! # DateTime.Now Behavior
//!
//! `DateTime.get_Now()` and `DateTime.get_UtcNow()` return the PE file's build
//! timestamp (COFF header `TimeDateStamp`). This ensures that trial/time-bomb
//! checks in obfuscators always see a date close to when the binary was built,
//! preventing expired-trial exceptions without needing a dedicated bypass hook.
//!
//! # Emulated .NET Methods
//!
//! ## DateTime
//!
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor(long ticks)` | Construct from raw ticks |
//! | `.ctor(int year, int month, int day)` | Construct from date components |
//! | `get_Now()` | PE build timestamp |
//! | `get_UtcNow()` | PE build timestamp (same as Now) |
//! | `get_Ticks` | Extract ticks value |
//! | `get_Year`, `get_Month`, `get_Day` | Date component extraction |
//! | `AddDays`, `AddHours`, `AddMinutes`, `AddSeconds`, `AddTicks` | Date arithmetic |
//! | `op_Subtraction` | DateTime - DateTime = TimeSpan |
//! | `op_GreaterThan`, `op_LessThan`, `op_Equality`, `op_Inequality` | Comparison |
//! | `op_GreaterThanOrEqual`, `op_LessThanOrEqual` | Comparison |
//!
//! ## TimeSpan
//!
//! | Method | Description |
//! |--------|-------------|
//! | `get_Ticks` | Extract ticks value |
//! | `get_Days` | Integer days component |
//! | `get_Hours`, `get_Minutes`, `get_Seconds` | Time components |
//! | `get_TotalDays`, `get_TotalHours`, `get_TotalMinutes`, `get_TotalSeconds` | Total as float |
//! | `FromDays`, `FromHours`, `FromMinutes`, `FromSeconds`, `FromTicks` | Construction |

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Number of 100-nanosecond ticks per second (10 million).
const TICKS_PER_SECOND: i64 = 10_000_000;
/// Number of ticks per minute.
const TICKS_PER_MINUTE: i64 = TICKS_PER_SECOND * 60;
/// Number of ticks per hour.
const TICKS_PER_HOUR: i64 = TICKS_PER_MINUTE * 60;
/// Number of ticks per day.
const TICKS_PER_DAY: i64 = TICKS_PER_HOUR * 24;

/// Cumulative days to the start of each month in a non-leap year (0-indexed, 13 entries).
/// Entry 0 = 0 (before January), entry 12 = 365 (total days).
const DAYS_TO_MONTH_365: [u32; 13] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];
/// Cumulative days to the start of each month in a leap year (0-indexed, 13 entries).
const DAYS_TO_MONTH_366: [u32; 13] = [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366];

/// The .NET epoch (0001-01-01 00:00:00 UTC) for Unix time (1970-01-01), expressed in ticks.
const UNIX_EPOCH_TICKS: i64 = 621_355_968_000_000_000;

/// Fallback timestamp (2024-01-01 00:00:00 UTC) used when no PE timestamp is
/// available. Chosen as a recent date that won't trigger trial expiration checks.
const FALLBACK_TICKS: i64 = 638_396_640_000_000_000;

/// Registers all `System.DateTime` and `System.TimeSpan` hooks with the hook manager.
///
/// This covers constructors, property accessors, arithmetic methods, comparison
/// operators, and factory methods for both value types. See the module-level
/// documentation for the full list of emulated methods.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.DateTime..ctor(Int64)")
            .match_name("System", "DateTime", ".ctor")
            .pre(datetime_ctor_pre),
    )?;

    // DateTime properties
    manager.register(
        Hook::new("System.DateTime.get_Now")
            .match_name("System", "DateTime", "get_Now")
            .pre(datetime_get_now_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.get_UtcNow")
            .match_name("System", "DateTime", "get_UtcNow")
            .pre(datetime_get_now_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.get_Ticks")
            .match_name("System", "DateTime", "get_Ticks")
            .pre(datetime_get_ticks_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.get_Year")
            .match_name("System", "DateTime", "get_Year")
            .pre(datetime_get_year_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.get_Month")
            .match_name("System", "DateTime", "get_Month")
            .pre(datetime_get_month_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.get_Day")
            .match_name("System", "DateTime", "get_Day")
            .pre(datetime_get_day_pre),
    )?;

    // DateTime arithmetic
    manager.register(
        Hook::new("System.DateTime.AddDays")
            .match_name("System", "DateTime", "AddDays")
            .pre(datetime_add_days_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.AddHours")
            .match_name("System", "DateTime", "AddHours")
            .pre(datetime_add_hours_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.AddMinutes")
            .match_name("System", "DateTime", "AddMinutes")
            .pre(datetime_add_minutes_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.AddSeconds")
            .match_name("System", "DateTime", "AddSeconds")
            .pre(datetime_add_seconds_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.AddTicks")
            .match_name("System", "DateTime", "AddTicks")
            .pre(datetime_add_ticks_pre),
    )?;

    // DateTime operators
    manager.register(
        Hook::new("System.DateTime.op_Subtraction")
            .match_name("System", "DateTime", "op_Subtraction")
            .pre(datetime_op_subtraction_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.op_GreaterThan")
            .match_name("System", "DateTime", "op_GreaterThan")
            .pre(datetime_op_gt_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.op_LessThan")
            .match_name("System", "DateTime", "op_LessThan")
            .pre(datetime_op_lt_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.op_Equality")
            .match_name("System", "DateTime", "op_Equality")
            .pre(datetime_op_eq_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.op_Inequality")
            .match_name("System", "DateTime", "op_Inequality")
            .pre(datetime_op_neq_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.op_GreaterThanOrEqual")
            .match_name("System", "DateTime", "op_GreaterThanOrEqual")
            .pre(datetime_op_gte_pre),
    )?;
    manager.register(
        Hook::new("System.DateTime.op_LessThanOrEqual")
            .match_name("System", "DateTime", "op_LessThanOrEqual")
            .pre(datetime_op_lte_pre),
    )?;

    // TimeSpan properties
    manager.register(
        Hook::new("System.TimeSpan.get_Ticks")
            .match_name("System", "TimeSpan", "get_Ticks")
            .pre(timespan_get_ticks_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_Days")
            .match_name("System", "TimeSpan", "get_Days")
            .pre(timespan_get_days_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_Hours")
            .match_name("System", "TimeSpan", "get_Hours")
            .pre(timespan_get_hours_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_Minutes")
            .match_name("System", "TimeSpan", "get_Minutes")
            .pre(timespan_get_minutes_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_Seconds")
            .match_name("System", "TimeSpan", "get_Seconds")
            .pre(timespan_get_seconds_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_TotalDays")
            .match_name("System", "TimeSpan", "get_TotalDays")
            .pre(timespan_get_total_days_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_TotalHours")
            .match_name("System", "TimeSpan", "get_TotalHours")
            .pre(timespan_get_total_hours_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_TotalMinutes")
            .match_name("System", "TimeSpan", "get_TotalMinutes")
            .pre(timespan_get_total_minutes_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.get_TotalSeconds")
            .match_name("System", "TimeSpan", "get_TotalSeconds")
            .pre(timespan_get_total_seconds_pre),
    )?;

    // TimeSpan factory methods
    manager.register(
        Hook::new("System.TimeSpan.FromDays")
            .match_name("System", "TimeSpan", "FromDays")
            .pre(timespan_from_days_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.FromHours")
            .match_name("System", "TimeSpan", "FromHours")
            .pre(timespan_from_hours_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.FromMinutes")
            .match_name("System", "TimeSpan", "FromMinutes")
            .pre(timespan_from_minutes_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.FromSeconds")
            .match_name("System", "TimeSpan", "FromSeconds")
            .pre(timespan_from_seconds_pre),
    )?;
    manager.register(
        Hook::new("System.TimeSpan.FromTicks")
            .match_name("System", "TimeSpan", "FromTicks")
            .pre(timespan_from_ticks_pre),
    )?;

    Ok(())
}

/// Extracts the ticks value from a `DateTime` or `TimeSpan` on the evaluation stack.
///
/// Both types are value types wrapping a single `i64` field. On the CIL stack
/// they appear as `I64(ticks)`, as a `ValueType` with one `I64` field, or
/// (after narrowing conversions) as `I32`.
fn extract_ticks(value: &EmValue) -> Option<i64> {
    match value {
        EmValue::I64(ticks) => Some(*ticks),
        EmValue::I32(v) => Some(i64::from(*v)),
        EmValue::ValueType { fields, .. } => fields.first().and_then(|f| match f {
            EmValue::I64(t) => Some(*t),
            EmValue::I32(v) => Some(i64::from(*v)),
            _ => None,
        }),
        _ => None,
    }
}

/// Extracts ticks from the `this` receiver of an instance property call.
///
/// `DateTime` and `TimeSpan` are value types, so `this` may be either the
/// value itself or a managed pointer to it. Falls back to `args[0]` since
/// some calling conventions pass value-type receivers as the first argument.
fn extract_ticks_from_this(ctx: &HookContext<'_>, _thread: &EmulationThread) -> Option<i64> {
    if let Some(this) = ctx.this {
        if let Some(ticks) = extract_ticks(this) {
            return Some(ticks);
        }
    }
    // Fall back to first arg (instance methods on value types may pass this as arg[0])
    ctx.args.first().and_then(extract_ticks)
}

/// Converts a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) to .NET
/// ticks (100-nanosecond intervals since 0001-01-01 00:00:00 UTC).
fn unix_to_ticks(unix_timestamp: u32) -> i64 {
    UNIX_EPOCH_TICKS + i64::from(unix_timestamp) * TICKS_PER_SECOND
}

/// Returns the PE build timestamp as .NET ticks.
///
/// Reads `TimeDateStamp` from the COFF header of the loaded assembly. If no
/// assembly is loaded or the timestamp is zero, returns [`FALLBACK_TICKS`]
/// (2024-01-01) to provide a safe date that won't trigger trial expiration.
fn pe_build_ticks(thread: &EmulationThread) -> i64 {
    thread
        .assembly()
        .map(|asm| {
            let ts = asm.file().pe().coff_header.time_date_stamp;
            if ts > 0 {
                unix_to_ticks(ts)
            } else {
                FALLBACK_TICKS
            }
        })
        .unwrap_or(FALLBACK_TICKS)
}

/// Returns `true` if the given Gregorian year is a leap year.
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Returns the number of days in the given month (1-based) of the given year.
fn days_in_month(year: i32, month: i32) -> i32 {
    let table = if is_leap_year(year) {
        &DAYS_TO_MONTH_366
    } else {
        &DAYS_TO_MONTH_365
    };
    (table[month as usize] - table[(month - 1) as usize]) as i32
}

/// Computes .NET ticks from a Gregorian date (year, month, day).
///
/// Follows the same algorithm as .NET's internal `DateTime.DateToTicks`:
/// total days since 0001-01-01, multiplied by [`TICKS_PER_DAY`]. Returns 0
/// for out-of-range inputs rather than panicking.
fn date_to_ticks(year: i32, month: i32, day: i32) -> i64 {
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return 0;
    }
    let max_day = days_in_month(year, month);
    if !(1..=max_day).contains(&day) {
        return 0;
    }
    let table = if is_leap_year(year) {
        &DAYS_TO_MONTH_366
    } else {
        &DAYS_TO_MONTH_365
    };
    let y = year - 1;
    let total_days =
        y * 365 + y / 4 - y / 100 + y / 400 + table[(month - 1) as usize] as i32 + day - 1;
    i64::from(total_days) * TICKS_PER_DAY
}

/// Extracts the Gregorian (year, month, day) from a .NET ticks value.
///
/// Strips the `DateTimeKind` flags stored in bits 62-63 and the time-of-day
/// component, then decomposes the remaining day count using the 400-year
/// Gregorian cycle (146,097 days per cycle).
fn ticks_to_date(ticks: i64) -> (i32, i32, i32) {
    let ticks = ticks & 0x3FFF_FFFF_FFFF_FFFF;
    let total_days = (ticks / TICKS_PER_DAY) as i32;

    // Compute year from total days using the 400-year cycle.
    let y400 = total_days / 146_097;
    let mut remaining = total_days - y400 * 146_097;

    let mut y100 = remaining / 36_524;
    if y100 == 4 {
        y100 = 3;
    }
    remaining -= y100 * 36_524;

    let y4 = remaining / 1_461;
    remaining -= y4 * 1_461;

    let mut y1 = remaining / 365;
    if y1 == 4 {
        y1 = 3;
    }

    let year = y400 * 400 + y100 * 100 + y4 * 4 + y1 + 1;
    remaining -= y1 * 365;

    let table = if is_leap_year(year) {
        &DAYS_TO_MONTH_366
    } else {
        &DAYS_TO_MONTH_365
    };

    let mut month = 1;
    while month < 12 && remaining >= table[month] as i32 {
        month += 1;
    }
    let day = remaining - table[month - 1] as i32 + 1;

    (year, month as i32, day)
}

/// Hook for `DateTime..ctor` — constructs a DateTime from ticks or date components.
///
/// Handles three overload families:
/// - `.ctor(long ticks)` — raw ticks passthrough
/// - `.ctor(long ticks, DateTimeKind)` — ticks with kind (kind is ignored)
/// - `.ctor(int year, int month, int day)` — converts date components to ticks
fn datetime_ctor_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    match ctx.args.len() {
        // .ctor(long ticks) — `this` is arg[0] for value type ctors, ticks is arg[1]
        // or ticks is the only arg if this is passed separately
        1 => {
            if let Some(ticks) = extract_ticks(&ctx.args[0]) {
                return PreHookResult::Bypass(Some(EmValue::I64(ticks)));
            }
            PreHookResult::Continue
        }
        2 => {
            // Could be .ctor(this, ticks) or .ctor(ticks, DateTimeKind)
            if let Some(ticks) = extract_ticks(&ctx.args[0]) {
                return PreHookResult::Bypass(Some(EmValue::I64(ticks)));
            }
            if let Some(ticks) = extract_ticks(&ctx.args[1]) {
                return PreHookResult::Bypass(Some(EmValue::I64(ticks)));
            }
            PreHookResult::Continue
        }
        n if n >= 3 => {
            // .ctor(int year, int month, int day) or .ctor(this, year, month, day)
            let (y, m, d) = if n >= 4 {
                // this, year, month, day
                (
                    extract_i32(&ctx.args[1]),
                    extract_i32(&ctx.args[2]),
                    extract_i32(&ctx.args[3]),
                )
            } else {
                (
                    extract_i32(&ctx.args[0]),
                    extract_i32(&ctx.args[1]),
                    extract_i32(&ctx.args[2]),
                )
            };
            if let (Some(year), Some(month), Some(day)) = (y, m, d) {
                let ticks = date_to_ticks(year, month, day);
                return PreHookResult::Bypass(Some(EmValue::I64(ticks)));
            }
            PreHookResult::Continue
        }
        _ => PreHookResult::Continue,
    }
}

/// Extracts an `i32` from an `EmValue`, handling both `I32` and narrowed `I64`.
fn extract_i32(value: &EmValue) -> Option<i32> {
    match value {
        EmValue::I32(v) => Some(*v),
        EmValue::I64(v) => Some(*v as i32),
        _ => None,
    }
}

/// Hook for `DateTime.get_Now` / `DateTime.get_UtcNow`.
///
/// Returns the PE file's build timestamp so that trial/time-bomb checks in
/// obfuscators always see a date close to when the binary was compiled.
fn datetime_get_now_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I64(pe_build_ticks(thread))))
}

/// Hook for `DateTime.get_Ticks` — returns the raw ticks value.
fn datetime_get_ticks_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(ticks) = extract_ticks_from_this(ctx, thread) {
        PreHookResult::Bypass(Some(EmValue::I64(ticks)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I64(0)))
    }
}

/// Hook for `DateTime.get_Year` — extracts the year component from ticks.
fn datetime_get_year_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(ticks) = extract_ticks_from_this(ctx, thread) {
        let (year, _, _) = ticks_to_date(ticks);
        PreHookResult::Bypass(Some(EmValue::I32(year)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(1)))
    }
}

/// Hook for `DateTime.get_Month` — extracts the month component (1-12).
fn datetime_get_month_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(ticks) = extract_ticks_from_this(ctx, thread) {
        let (_, month, _) = ticks_to_date(ticks);
        PreHookResult::Bypass(Some(EmValue::I32(month)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(1)))
    }
}

/// Hook for `DateTime.get_Day` — extracts the day-of-month component (1-31).
fn datetime_get_day_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(ticks) = extract_ticks_from_this(ctx, thread) {
        let (_, _, day) = ticks_to_date(ticks);
        PreHookResult::Bypass(Some(EmValue::I32(day)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(1)))
    }
}

/// Shared implementation for `DateTime.Add*` methods that take a `double` amount.
///
/// Reads the receiver's ticks, multiplies the `double` argument by the given
/// ticks-per-unit constant, and returns a new `DateTime` with the adjusted ticks.
fn datetime_add_f64(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
    ticks_per_unit: i64,
) -> PreHookResult {
    let this_ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    let amount = ctx
        .args
        .last()
        .and_then(|v| match v {
            EmValue::F64(f) => Some(*f),
            EmValue::F32(f) => Some(f64::from(*f)),
            _ => None,
        })
        .unwrap_or(0.0);
    let delta = (amount * ticks_per_unit as f64) as i64;
    PreHookResult::Bypass(Some(EmValue::I64(this_ticks + delta)))
}

/// Hook for `DateTime.AddDays(double)`.
fn datetime_add_days_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    datetime_add_f64(ctx, thread, TICKS_PER_DAY)
}

/// Hook for `DateTime.AddHours(double)`.
fn datetime_add_hours_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    datetime_add_f64(ctx, thread, TICKS_PER_HOUR)
}

/// Hook for `DateTime.AddMinutes(double)`.
fn datetime_add_minutes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    datetime_add_f64(ctx, thread, TICKS_PER_MINUTE)
}

/// Hook for `DateTime.AddSeconds(double)`.
fn datetime_add_seconds_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    datetime_add_f64(ctx, thread, TICKS_PER_SECOND)
}

/// Hook for `DateTime.AddTicks(long)`.
fn datetime_add_ticks_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let this_ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    let delta = ctx.args.last().and_then(extract_ticks).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::I64(this_ticks + delta)))
}

/// Hook for `DateTime.op_Subtraction(DateTime, DateTime) -> TimeSpan`.
///
/// Subtracts two DateTime ticks values and returns the difference as a
/// TimeSpan (also represented as `I64(ticks)` on the stack).
fn datetime_op_subtraction_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.len() >= 2 {
        let a = extract_ticks(&ctx.args[0]).unwrap_or(0);
        let b = extract_ticks(&ctx.args[1]).unwrap_or(0);
        PreHookResult::Bypass(Some(EmValue::I64(a - b)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I64(0)))
    }
}

/// Shared implementation for DateTime comparison operators.
///
/// Extracts ticks from both arguments, applies the given comparison function,
/// and returns `I32(1)` for true or `I32(0)` for false.
fn datetime_cmp(ctx: &HookContext<'_>, op: fn(i64, i64) -> bool) -> PreHookResult {
    if ctx.args.len() >= 2 {
        let a = extract_ticks(&ctx.args[0]).unwrap_or(0);
        let b = extract_ticks(&ctx.args[1]).unwrap_or(0);
        PreHookResult::Bypass(Some(EmValue::I32(i32::from(op(a, b)))))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `DateTime.op_GreaterThan`.
fn datetime_op_gt_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    datetime_cmp(ctx, |a, b| a > b)
}

/// Hook for `DateTime.op_LessThan`.
fn datetime_op_lt_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    datetime_cmp(ctx, |a, b| a < b)
}

/// Hook for `DateTime.op_Equality`.
fn datetime_op_eq_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    datetime_cmp(ctx, |a, b| a == b)
}

/// Hook for `DateTime.op_Inequality`.
fn datetime_op_neq_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    datetime_cmp(ctx, |a, b| a != b)
}

/// Hook for `DateTime.op_GreaterThanOrEqual`.
fn datetime_op_gte_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    datetime_cmp(ctx, |a, b| a >= b)
}

/// Hook for `DateTime.op_LessThanOrEqual`.
fn datetime_op_lte_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    datetime_cmp(ctx, |a, b| a <= b)
}

/// Hook for `TimeSpan.get_Ticks` — returns the raw ticks value.
fn timespan_get_ticks_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::I64(ticks)))
}

/// Hook for `TimeSpan.get_Days` — integer days component (truncated toward zero).
fn timespan_get_days_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let days = (ticks / TICKS_PER_DAY) as i32;
    PreHookResult::Bypass(Some(EmValue::I32(days)))
}

/// Hook for `TimeSpan.get_Hours` — hours component (0-23, after removing full days).
fn timespan_get_hours_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let hours = ((ticks / TICKS_PER_HOUR) % 24) as i32;
    PreHookResult::Bypass(Some(EmValue::I32(hours)))
}

/// Hook for `TimeSpan.get_Minutes` — minutes component (0-59).
fn timespan_get_minutes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let minutes = ((ticks / TICKS_PER_MINUTE) % 60) as i32;
    PreHookResult::Bypass(Some(EmValue::I32(minutes)))
}

/// Hook for `TimeSpan.get_Seconds` — seconds component (0-59).
fn timespan_get_seconds_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let seconds = ((ticks / TICKS_PER_SECOND) % 60) as i32;
    PreHookResult::Bypass(Some(EmValue::I32(seconds)))
}

/// Hook for `TimeSpan.get_TotalDays` — total duration expressed as fractional days.
fn timespan_get_total_days_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::F64(ticks as f64 / TICKS_PER_DAY as f64)))
}

/// Hook for `TimeSpan.get_TotalHours` — total duration expressed as fractional hours.
fn timespan_get_total_hours_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::F64(ticks as f64 / TICKS_PER_HOUR as f64)))
}

/// Hook for `TimeSpan.get_TotalMinutes` — total duration expressed as fractional minutes.
fn timespan_get_total_minutes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::F64(ticks as f64 / TICKS_PER_MINUTE as f64)))
}

/// Hook for `TimeSpan.get_TotalSeconds` — total duration expressed as fractional seconds.
fn timespan_get_total_seconds_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let ticks = extract_ticks_from_this(ctx, thread).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::F64(ticks as f64 / TICKS_PER_SECOND as f64)))
}

/// Shared implementation for `TimeSpan.From*` factory methods.
///
/// Reads a `double` argument, multiplies by the given ticks-per-unit constant,
/// and returns a TimeSpan as `I64(ticks)`.
fn timespan_from_f64(ctx: &HookContext<'_>, ticks_per_unit: i64) -> PreHookResult {
    let amount = ctx
        .args
        .first()
        .and_then(|v| match v {
            EmValue::F64(f) => Some(*f),
            EmValue::F32(f) => Some(f64::from(*f)),
            EmValue::I32(i) => Some(f64::from(*i)),
            EmValue::I64(i) => Some(*i as f64),
            _ => None,
        })
        .unwrap_or(0.0);
    let ticks = (amount * ticks_per_unit as f64) as i64;
    PreHookResult::Bypass(Some(EmValue::I64(ticks)))
}

/// Hook for `TimeSpan.FromDays(double)`.
fn timespan_from_days_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    timespan_from_f64(ctx, TICKS_PER_DAY)
}

/// Hook for `TimeSpan.FromHours(double)`.
fn timespan_from_hours_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    timespan_from_f64(ctx, TICKS_PER_HOUR)
}

/// Hook for `TimeSpan.FromMinutes(double)`.
fn timespan_from_minutes_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    timespan_from_f64(ctx, TICKS_PER_MINUTE)
}

/// Hook for `TimeSpan.FromSeconds(double)`.
fn timespan_from_seconds_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    timespan_from_f64(ctx, TICKS_PER_SECOND)
}

/// Hook for `TimeSpan.FromTicks(long)` — constructs a TimeSpan from raw ticks.
fn timespan_from_ticks_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let ticks = ctx.args.first().and_then(extract_ticks).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::I64(ticks)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_to_ticks_known_dates() {
        // 0001-01-01 = 0 ticks
        assert_eq!(date_to_ticks(1, 1, 1), 0);

        // 1970-01-01 = Unix epoch
        assert_eq!(date_to_ticks(1970, 1, 1), UNIX_EPOCH_TICKS);

        // 2024-01-01
        assert_eq!(date_to_ticks(2024, 1, 1), FALLBACK_TICKS);
    }

    #[test]
    fn test_ticks_to_date_roundtrip() {
        for &(y, m, d) in &[
            (1, 1, 1),
            (1970, 1, 1),
            (2000, 2, 29), // leap year
            (2024, 6, 15),
            (9999, 12, 31),
        ] {
            let ticks = date_to_ticks(y, m, d);
            let (ry, rm, rd) = ticks_to_date(ticks);
            assert_eq!(
                (ry, rm, rd),
                (y, m, d),
                "roundtrip failed for {y}-{m:02}-{d:02}"
            );
        }
    }

    #[test]
    fn test_unix_to_ticks() {
        // Unix epoch itself
        assert_eq!(unix_to_ticks(0), UNIX_EPOCH_TICKS);

        // 2024-01-01 00:00:00 UTC = 1704067200 Unix time
        let ticks_2024 = unix_to_ticks(1_704_067_200);
        let (y, m, d) = ticks_to_date(ticks_2024);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn test_extract_ticks() {
        assert_eq!(extract_ticks(&EmValue::I64(12345)), Some(12345));
        assert_eq!(extract_ticks(&EmValue::I32(42)), Some(42));
        assert_eq!(extract_ticks(&EmValue::Null), None);
    }
}
