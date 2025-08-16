# Contributing to QTunnel

Thank you for your interest in contributing to QTunnel! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Detailed description** of the problem
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details** (OS, Go version, etc.)
- **Log output** if relevant

### Suggesting Features

Feature suggestions are welcome! Please provide:

- **Clear description** of the proposed feature
- **Use case** explaining why it would be valuable
- **Implementation ideas** if you have any
- **Potential drawbacks** or considerations

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for new functionality
4. **Update documentation** if needed
5. **Ensure tests pass** with `make test`
6. **Create a pull request** with a clear description

#### Branch Naming

Use descriptive branch names:
- `feature/add-connection-pooling`
- `bugfix/fix-websocket-timeout`
- `docs/update-installation-guide`

#### Commit Messages

Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tool changes

Examples:
```
feat(client): add command line argument support
fix(server): resolve memory leak in tunnel cleanup
docs(readme): update installation instructions
```

## Development Setup

### Prerequisites

- Go 1.21 or later
- Docker (for integration tests)
- Make

### Getting Started

1. **Clone your fork:**
```bash
git clone https://github.com/yourusername/qtunnel.git
cd qtunnel
```

2. **Install dependencies:**
```bash
make deps
```

3. **Run tests:**
```bash
make test
```

4. **Build the project:**
```bash
make build
```

### Development Workflow

1. **Create a feature branch:**
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**

3. **Test your changes:**
```bash
make test
make lint
```

4. **Run the server locally:**
```bash
make run-server
```

5. **Test with client:**
```bash
make run-client
```

## Coding Standards

### Go Style Guide

Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and these additional guidelines:

- **Use gofmt** to format code
- **Add comments** for exported functions
- **Handle errors** explicitly
- **Use meaningful names** for variables and functions
- **Keep functions small** and focused
- **Avoid global variables** when possible

### Error Handling

- Always handle errors explicitly
- Use `fmt.Errorf` for error wrapping
- Log errors at appropriate levels
- Return errors to callers when possible

```go
// Good
resp, err := http.Get(url)
if err != nil {
    return fmt.Errorf("failed to fetch URL %s: %w", url, err)
}

// Bad
resp, _ := http.Get(url)
```

### Testing

- Write tests for new functionality
- Use table-driven tests for multiple scenarios
- Mock external dependencies
- Aim for good test coverage

```go
func TestTunnelManager_CreateTunnel(t *testing.T) {
    tests := []struct {
        name     string
        input    *websocket.Conn
        expected string
    }{
        {"valid connection", mockConn, "tunnel created"},
        // Add more test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Documentation

### Code Documentation

- Add godoc comments for exported functions
- Include examples in documentation
- Update README.md for user-facing changes

### API Documentation

If you add new API endpoints or modify existing ones:
- Update API documentation
- Add request/response examples
- Document error codes

## Testing Guidelines

### Unit Tests

- Test individual functions in isolation
- Mock external dependencies
- Use meaningful test names
- Test both success and error cases

### Integration Tests

- Test component interactions
- Use Docker for testing with real services
- Clean up resources after tests

### Performance Tests

- Add benchmarks for performance-critical code
- Test with realistic data sizes
- Monitor memory usage

## Release Process

Releases are handled by maintainers, but contributors should:

1. **Update version** in relevant files
2. **Update CHANGELOG.md** with changes
3. **Tag releases** following semantic versioning
4. **Build release artifacts** with `make release`

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Code Review**: Ask questions in pull request comments

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- GitHub contributor graph

Thank you for contributing to QTunnel!