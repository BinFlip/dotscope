#![allow(unused_macros)]

/// Helper macro for locking items
///
/// ```rust, ignore
///  let mut data = lock!(my_mutex);
///  data.some_field = 42;
/// ```
macro_rules! lock {
    ($lock:expr) => {
        $lock.lock().expect("Failed to acquire lock")
    };
}

/// Helper macro for reading locked items
///
/// ```rust, ignore
///  let data = read_lock!(my_arc_rwlock);
///  println!("{}", data.some_field);
/// ```
macro_rules! read_lock {
    ($arc_rwlock:expr) => {
        $arc_rwlock.read().expect("Failed to acquire read lock")
    };
}

/// Helper macro for writing to locked items
///
/// ```rust, ignore
///  let mut data = write_lock!(my_arc_rwlock);
///  data.some_field = 42;
/// ```
macro_rules! write_lock {
    ($arc_rwlock:expr) => {
        $arc_rwlock.write().expect("Failed to acquire write lock")
    };
}

/// Helper macro for reading locked items
///
/// ```rust, ignore
///  let name = with_read!(module_ref, |module| module.name.clone());
/// ```
macro_rules! with_read {
    ($arc_rwlock:expr, $closure:expr) => {{
        let guard = $arc_rwlock.read().expect("Failed to acquire read lock");
        $closure(&*guard)
    }};
}

/// Helper macro for writing to locked items
///
/// ```rust, ignore
///  with_write!(module_ref, |module| module.name = "new_name".to_string());
/// ```
macro_rules! with_write {
    ($arc_rwlock:expr, $closure:expr) => {{
        let mut guard = $arc_rwlock.write().expect("Failed to acquire write lock");
        $closure(&mut *guard)
    }};
}

/// Helper macro for reading of maps with locked items
///
/// ```rust, ignore
/// if let Some(module_ref) = map_get_read!(self.refs_module, &token) {
///    // Use module_ref
/// }
/// ```
macro_rules! map_get_read {
    ($map:expr, $key:expr) => {{
        $map.get($key).map(|arc_rwlock| read_lock!(arc_rwlock))
    }};
}

/// Helper macro for iterating over locked collections
///
/// ```rust, ignore
/// for_each_read!(modules, module, {
///    println!("Module name: {}", module.name);
/// });
/// ```
macro_rules! for_each_read {
    ($collection:expr, $var:ident, $body:block) => {
        for item in $collection.iter() {
            let $var = read_lock!(item);
            $body
        }
    };
}
