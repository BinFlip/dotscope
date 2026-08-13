# Security Policy

## Supported Versions

We actively support the following versions of dotscope with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

dotscope is pre-1.0 and ships breaking changes in minor releases. Only the
latest minor version receives security fixes; there are no backports.

## Reporting a Vulnerability

We take security vulnerabilities in dotscope seriously. If you discover a security vulnerability, please follow these steps:

### 1. **Do NOT** create a public GitHub issue

Security vulnerabilities should not be disclosed publicly until they have been addressed.

### 2. Report via Private Channels

Please report security vulnerabilities through one of these methods:

- **Email**: Send details to `admin@binflip.rs`
- **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature

### 3. Include the Following Information

When reporting a vulnerability, please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any proof-of-concept code (if applicable)
- Suggested mitigation or fix (if you have one)

### 4. Response Timeline

We aim to respond to security reports according to the following timeline:

- **Initial Response**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Development**: Within 2-4 weeks (depending on complexity)
- **Public Disclosure**: After fix is released and users have time to update

### 5. Coordinated Disclosure

We follow responsible disclosure practices:

1. We will work with you to understand and reproduce the issue
2. We will develop and test a fix
3. We will prepare a security advisory
4. We will release the fix and publish the advisory
5. We will credit you in the advisory (unless you prefer to remain anonymous)

## Security Considerations

### Parser Security

dotscope parses potentially untrusted .NET assemblies. We take several precautions:

- **Memory Safety**: Built on Rust's memory safety guarantees
- **Bounds Checking**: All array and buffer accesses are bounds-checked  
- **Fuzzing**: `cargo-fuzz` targets covering the object, view, signature,
  custom-attribute, method-body and emulation paths, run on demand via
  `make fuzz`. Crash artifacts are committed and replayed by the test suite
- **Input Validation**: Strict validation of metadata structures and bytecode

Note that `ValidationConfig::disabled()` and the `lenient` presets do not
disable bounds checking -- what they give up is *semantic* rejection, so
incoherent metadata is analysed as if it were coherent.

### Denial of Service Protection

Emulation runs under `EmulationLimits`, enforced during execution rather than
after the fact. Defaults:

| Limit | Default |
| ----- | ------- |
| `max_instructions` | 10,000,000 |
| `max_call_depth` | 1,000 |
| `max_heap_objects` | 100,000 |
| `max_heap_bytes` | 256 MB |
| `max_unmanaged_bytes` | 64 MB |
| `max_loaded_assemblies` | 64 |
| `max_loaded_assembly_bytes` | 32 MB |
| `timeout_ms` | 60,000 |

- **Timeout Handling**: the wall-clock budget is checked between instructions
- **Malformed Input**: Graceful handling of corrupted or crafted files

### Known Security Considerations

1. **Memory-Mapped Files**: We use memory mapping for performance, which requires careful handling
2. **Unsafe Code**: the crate builds under `deny(unsafe_code)`. One block carries
   a targeted allow, for the memory mapping of the writer's output file. The
   primary load path maps input through the `cowfile` dependency
3. **Dependency Chain**: Regular auditing of dependencies for vulnerabilities

## Security Testing

Our security testing includes:

- **Fuzzing**: six `cargo-fuzz` targets, run on demand and in CI, seeded from
  the committed crash corpus
- **Regression Corpus**: every crash artifact found by fuzzing is committed and
  replayed by the test suite
- **Static Analysis**: Clippy with `panic`, `unwrap`, `expect`, `indexing_slicing`,
  `arithmetic_side_effects` and `string_slice` denied in the library crate
- **Dependency Auditing**: Regular `cargo audit` runs

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors will be acknowledged in our security advisories unless they prefer to remain anonymous.
