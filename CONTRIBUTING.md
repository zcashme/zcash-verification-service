# Contributing to ZVS

Thanks for your interest in contributing to ZVS.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [I Have a Question](#i-have-a-question)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Pull Requests](#pull-requests)
- [Coding Style](#coding-style)

## Code of Conduct

This project follows the [Zcash Code of Conduct](https://github.com/zcash/zcash/blob/master/code_of_conduct.md).
Please report unacceptable behavior as documented there.

## I Have a Question

Before asking a question, please read the [README](README.md) and check existing
[Issues](/issues) for answers.

If you still need clarification:
- Open an [Issue](/issues/new) with as much context as possible
- Include project and platform versions where relevant

## Reporting Bugs

### Security Issues

**Do not report security vulnerabilities in public issues.** Security issues
affecting Zcash should be reported as described at
[https://z.cash/support/security/](https://z.cash/support/security/).

### Bug Reports

When filing a bug report:
- Use a clear, descriptive title
- Describe the expected behavior vs. actual behavior
- Provide reproduction steps
- Include OS, platform, and Rust version
- Attach relevant logs or error messages

## Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues:
- Use a clear title prefixed with the relevant component if known
- Describe the current behavior and what you'd like to see instead
- Explain why this enhancement would be useful

## Pull Requests

### Legal Notice

By contributing, you agree that you have authored 100% of the content, have the
necessary rights, and that the content may be provided under the project license.

### Workflow

1. Branch from `main` for new work
2. Keep commits atomic and well-described
3. Update documentation if behavior changes
4. Ensure `cargo build` and `cargo test` pass
5. Open a pull request with a clear description

### Commit Messages

- Use a short title (< 72 characters)
- Include motivation in the body when helpful
- Reference related issues where applicable

## Coding Style

### General

- Follow existing code conventions in the repository
- Run `cargo fmt` before committing
- Address `cargo clippy` warnings

### Type Safety

Following the librustzcash conventions:
- Prefer newtypes over primitive types in public APIs
- Use `Result` and `Option` for fallible operations
- Make invalid states unrepresentable at the type level

### Error Handling

- Use `Result` with descriptive error types
- Implement `std::error::Error` for public error types

## License

Contributions are licensed under MIT. See [LICENSE](LICENSE) for details.
