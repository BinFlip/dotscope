# Security Policy

## Supported Versions

We actively support the following versions of dotscope with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

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
- **Fuzzing**: Continuous fuzzing with cargo-fuzz to find parsing edge cases
- **Input Validation**: Strict validation of metadata structures and bytecode

### Denial of Service Protection

- **Resource Limits**: ToDo
- **Timeout Handling**: ToDo
- **Malformed Input**: Graceful handling of corrupted or crafted files

### Known Security Considerations

1. **Memory-Mapped Files**: We use memory mapping for performance, which requires careful handling
2. **Unsafe Code**: Limited use of `unsafe` code with careful review and testing
3. **Dependency Chain**: Regular auditing of dependencies for vulnerabilities

## Security Testing

Our security testing includes:

- **Continuous Fuzzing**: Automated fuzzing with various input types
- **Static Analysis**: Clippy and other static analysis tools
- **Dependency Auditing**: Regular `cargo audit` runs
- **Memory Safety**: Valgrind testing for memory leaks and corruption

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors will be acknowledged in our security advisories unless they prefer to remain anonymous.
