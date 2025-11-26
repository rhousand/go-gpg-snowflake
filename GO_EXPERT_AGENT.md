# Go Security Expert Agent

## Overview

This repository is configured with an always-active **Go Security Expert Agent** that provides comprehensive expertise in Go development with a strong security focus. The agent is automatically available when working with Claude Code in this repository.

## What It Provides

### Go Language Expertise
- **Concurrency & Goroutines**: Worker pools, channels, context management, race condition prevention
- **Memory Management**: Allocation optimization, garbage collection, leak prevention
- **Performance**: Profiling, benchmarking, optimization techniques
- **Testing**: Table-driven tests, mocking, coverage analysis, concurrent testing
- **Standard Library**: Best practices for net/http, database/sql, encoding/json, crypto, and more
- **Go Idioms**: Error handling, defer patterns, interface design, resource management

### Security Expertise
- **Cryptography**: Proper use of encryption algorithms, key management, AWS KMS integration
- **Authentication**: JWT security, HMAC validation, role-based access control
- **Database Security**: SQL injection prevention, parameterized queries, secure connections
- **OWASP Top 10**: Prevention of common vulnerabilities (injection, broken auth, XSS, etc.)
- **API Security**: Input validation, rate limiting, secure headers, TLS configuration
- **Go-Specific Security**: Race conditions, goroutine safety, constant-time operations, secure randomness

### Project-Specific Knowledge
The agent has deep understanding of this codebase:
- Hybrid PGP + KMS encryption architecture
- Snowflake database schema and operations
- JWT authentication and RBAC implementation
- TLS/HTTPS configuration
- Audit logging requirements
- Key rotation and versioning mechanisms

## How It Works

The agent is configured in `CLAUDE.md` and is **automatically active** for all Claude Code interactions in this repository. You don't need to invoke special commands—just work naturally with Claude Code.

### Automatic Behaviors

When you interact with Claude Code, the agent will:

1. **Review Code with Security First**: All code reviews prioritize security vulnerabilities
2. **Apply Go Best Practices**: Suggestions follow Go idioms and conventions
3. **Validate Cryptographic Operations**: Ensures proper algorithms, key sizes, and implementations
4. **Check for Common Vulnerabilities**: Automatically checks against OWASP Top 10 and Go-specific issues
5. **Verify Concurrency Safety**: Identifies race conditions and synchronization problems
6. **Ensure Proper Error Handling**: Validates error wrapping and information leakage prevention
7. **Recommend Tests**: Suggests test coverage for security-critical paths

### Example Interactions

**Code Review**:
```
You: "Review the authentication middleware in auth.go"
Agent: [Analyzes with security focus, checks JWT validation, algorithm confusion prevention, expiration handling, etc.]
```

**Implementation**:
```
You: "Add a new endpoint to list all companies"
Agent: [Implements with proper JWT auth, input validation, parameterized queries, error handling, and suggests tests]
```

**Security Question**:
```
You: "How should I handle the KMS data keys?"
Agent: [Provides guidance on keeping plaintext keys only in memory, zeroing after use, storing encrypted keys for audit, etc.]
```

**Bug Fix**:
```
You: "Fix the race condition in handlers.go"
Agent: [Identifies the issue, suggests proper synchronization, explains the security implications]
```

## Key Security Focus Areas

The agent pays special attention to these aspects of the codebase:

1. **PGP Key Validation**: Ensuring imported keys are valid, properly formatted, not expired
2. **KMS Data Key Lifecycle**: Plaintext keys never logged/stored, proper zeroing after use
3. **JWT Authentication**: Algorithm validation, signature verification, expiration checks
4. **SQL Injection Prevention**: All queries use parameterization, never string concatenation
5. **File Upload Security**: Size limits, validation, proper error handling
6. **Audit Trail**: Complete logging of encryption events with proper context
7. **TLS Configuration**: Modern ciphers, secure defaults, proper certificate handling
8. **Secret Management**: AWS Secrets Manager usage, never hardcoded secrets

## Security Principles Applied

Every response follows these security principles:

- **Input Validation**: All external inputs validated at boundaries
- **Least Privilege**: Minimum necessary permissions
- **Defense in Depth**: Multiple layers of security
- **Fail Securely**: Failures default to secure state
- **No Information Leakage**: Errors don't expose internal details
- **Secure by Default**: Security measures built-in, not optional

## Code Examples in Agent Knowledge

The agent includes extensive code examples for:

### Cryptographic Operations
- Secure random number generation with `crypto/rand`
- Constant-time comparisons for secrets
- Proper key zeroing after use
- Hybrid encryption patterns

### Authentication & Authorization
- JWT parsing with algorithm validation
- Token expiration checking
- Role-based access control middleware
- Secure session management

### Database Security
- Parameterized query patterns
- Named parameter usage with sqlx
- Connection pool configuration
- Error handling without credential leakage

### API Security
- Input validation with regex patterns
- Request size limiting with `http.MaxBytesReader`
- Secure header configuration
- Content-Type validation

### Go-Specific Patterns
- Goroutine lifecycle management with context
- Proper defer usage (especially in loops)
- Race condition prevention
- Slice safety and memory management

## Testing with the Agent

The agent can help with:
- Writing table-driven tests
- Creating mocks for external dependencies (KMS, Snowflake)
- Testing concurrent code
- Ensuring test coverage for security-critical paths
- Running race detector: `go test -race ./...`
- Vulnerability scanning: `govulncheck ./...`

## Configuration Location

The agent configuration is in:
- **File**: `CLAUDE.md`
- **Section**: "Claude Agent: Go Security Expert"

To modify the agent's behavior, edit the relevant sections in `CLAUDE.md`.

## Benefits

✅ **Always-On Security**: Every interaction includes security analysis
✅ **No Manual Invocation**: Works automatically, no special commands needed
✅ **Context-Aware**: Understands this project's specific architecture and requirements
✅ **Comprehensive Coverage**: Go expertise + security knowledge + project knowledge
✅ **Consistent Standards**: All code follows same security and style guidelines
✅ **Educational**: Explains security decisions and trade-offs

## Getting Started

Just start using Claude Code normally. Ask questions, request code reviews, implement features—the Go Security Expert Agent is always working in the background to ensure secure, idiomatic Go code.

### Example First Commands
```bash
# Review existing code for security issues
"Review all handlers for security vulnerabilities"

# Implement new feature securely
"Add rate limiting to the encrypt endpoint"

# Ask security questions
"How can we improve the JWT validation?"

# Optimize performance without compromising security
"Profile the encryption handler and optimize hot paths"
```

The agent will provide security-focused, Go-idiomatic solutions with complete examples and explanations.
