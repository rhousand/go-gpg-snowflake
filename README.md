# Secure PGP File Exchange API

**Bank-grade B2B encryption service** — fully reproducible with Nix.

## Build Docker Image
```bash
nix build .#container
docker load < result
```

## Go Security Expert Agent

This repository includes an always-active **Go Security Expert Agent** configured for Claude Code. The agent provides:

- **Go Language Expertise**: Concurrency, memory management, performance optimization, testing
- **Security Best Practices**: Cryptography, authentication, OWASP Top 10 prevention, secure coding
- **Project-Specific Knowledge**: PGP encryption, AWS KMS, Snowflake, JWT authentication

See [GO_EXPERT_AGENT.md](./GO_EXPERT_AGENT.md) for details.

The agent works automatically when using Claude Code—no special commands needed. It ensures all code follows security-first principles and Go best practices.

## Documentation

- [CLAUDE.md](./CLAUDE.md) - Complete project documentation and agent configuration
- [GO_EXPERT_AGENT.md](./GO_EXPERT_AGENT.md) - Go Security Expert Agent guide
- [schema.sql](./schema.sql) - Database schema
