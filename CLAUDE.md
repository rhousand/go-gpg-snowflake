# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Secure PGP File Exchange API — A bank-grade B2B encryption service that provides hybrid encryption using PGP public keys combined with AWS KMS-generated data keys. Built with Go, Snowflake, AWS KMS, and reproducibly packaged with Nix.

## Build and Development Commands

### Building with Nix

This project uses Nix flakes for reproducible builds:

```bash
# Build the application binary
nix build

# Build Docker container image
nix build .#container
docker load < result

# Enter development shell with all dependencies
nix develop
```

### Go Development

```bash
# Run the application locally (requires TLS certificates)
go run .

# Build binary manually
CGO_ENABLED=0 go build -ldflags="-s -w" -o main .

# Format code
go fmt ./...

# Update dependencies
go mod tidy
```

Note: The vendorHash in flake.nix needs to be updated when dependencies change. Set it to an empty hash, run `nix build`, then use the hash from the error message.

### Database Setup

```bash
# Initialize Snowflake schema
snowsql -f schema.sql
```

## Architecture

### Core Components

**main.go** - Application entry point
- Loads configuration from AWS Secrets Manager (or local file with `file://` prefix)
- Initializes Snowflake DB connection, AWS KMS client, and HTTP server
- Routes: `/encrypt` (JWT auth), `/import-key` (JWT auth + admin role), `/health`
- Runs HTTPS server on port 8443 (requires cert.pem and key.pem)

**handlers.go** - HTTP request handlers
- `ImportKeyHandler`: Accepts PGP public keys, validates them, stores in Snowflake with associated KMS CMK ID (requires "admin" role)
- `EncryptHandler`: Receives files, generates KMS data key, performs hybrid encryption using recipient's public key + KMS session key, records event in Snowflake

**pgp.go** - Hybrid encryption implementation
- `EncryptHybridStream`: Combines PGP asymmetric encryption with KMS symmetric keys
- Uses golang.org/x/crypto/openpgp (deprecated but stable)
- Session key from KMS is encrypted to recipient's public key(s)
- File data is symmetrically encrypted with the session key
- Output is standard armored OpenPGP message

**db.go** - Snowflake database layer
- `company_keys` table: Stores company PGP public keys, KMS CMK IDs, key versions
- `encryption_events` table: Audit log of encryption operations with encrypted data keys
- Key operations: GetCompany, UpsertCompany (with version increment), RecordEvent, IncrementVersion

**kms.go** - AWS KMS integration
- Thin wrapper around AWS KMS SDK v2
- `GenerateDataKey`: Creates AES-256 data keys for hybrid encryption
- Returns both plaintext key (for immediate use) and encrypted blob (for audit/recovery)

**auth.go** - JWT authentication middleware
- Bearer token authentication using HS256
- `JWTAuth`: Middleware that validates JWT and injects claims into request context
- `requireRole`: Helper to check for specific roles in JWT claims (e.g., "admin")

**types.go** - Core data structures
- `CompanyKey`: Company encryption key metadata
- `EncryptionEvent`: Audit trail for each encryption operation

### Configuration

Environment variables:
- `SECRETS_MANAGER_NAME`: AWS Secrets Manager secret name (default: "gopgp/prod/config")
  - Use `file:///path/to/secret.json` to load from local file in development

Required secrets (JSON format):
```json
{
  "SF_ACCOUNT": "snowflake-account",
  "SF_USER": "username",
  "SF_PASSWORD": "password",
  "SF_WAREHOUSE": "warehouse-name",
  "SF_DATABASE": "database-name",
  "SF_SCHEMA": "schema-name",
  "JWT_SECRET": "min-32-character-secret"
}
```

### Security Architecture

**Hybrid Encryption Flow**:
1. Client uploads file to `/encrypt` endpoint with company_id
2. Server fetches company's PGP public key from Snowflake
3. Server requests AES-256 data key from AWS KMS using company's CMK ID
4. KMS returns plaintext key + encrypted blob
5. Server encrypts file using PGP hybrid encryption (session key encrypted to public key, data encrypted with session key)
6. Encrypted data key blob stored in Snowflake for audit/recovery
7. Client receives encrypted PGP message with event_id and key_version headers

**Key Rotation**: Each company has a `current_version` counter that increments with key updates and encryptions, enabling key lifecycle tracking.

### Database Schema

The application expects these Snowflake tables (see schema.sql):

**company_keys**:
- `company_id` (STRING, PRIMARY KEY) - Unique company identifier
- `name` (STRING) - Company name
- `email` (STRING) - Contact email
- `public_key_armored` (STRING, NOT NULL) - ASCII-armored PGP public key
- `kms_cmk_id` (STRING, NOT NULL) - AWS KMS Customer Master Key ID
- `current_version` (NUMBER, DEFAULT 1) - Key version counter

**encryption_events**:
- `event_id` (STRING, PRIMARY KEY, DEFAULT UUID_STRING()) - Unique event identifier
- `company_id` (STRING) - Reference to company
- `kms_cmk_id` (STRING) - KMS key used for this encryption
- `key_version` (NUMBER) - Version of company key at encryption time
- `encrypted_data_key_b64` (STRING) - Base64-encoded KMS-encrypted data key
- `encrypted_at` (TIMESTAMP_NTZ, DEFAULT CURRENT_TIMESTAMP()) - Event timestamp

### Dependencies

Key packages:
- `github.com/snowflakedb/gosnowflake` - Snowflake driver
- `github.com/aws/aws-sdk-go-v2` - AWS SDK (KMS, Secrets Manager)
- `golang.org/x/crypto/openpgp` - PGP encryption (deprecated but functional)
- `github.com/golang-jwt/jwt/v5` - JWT authentication
- `github.com/jmoiron/sqlx` - SQL extensions for easier querying
- `github.com/rs/zerolog` - Structured logging

### Local Development Setup

1. Create TLS certificates: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes`
2. Set up Snowflake database with required tables: `snowsql -f schema.sql`
3. Create AWS KMS CMK for testing
4. Create local secrets file or AWS Secrets Manager entry
5. Set `SECRETS_MANAGER_NAME=file:///path/to/secrets.json`
6. Run with `go run .` or `nix develop` then `go run .`

### API Usage

**Import a company's PGP public key** (requires admin JWT):
```bash
curl -X POST https://localhost:8443/import-key \
  -H "Authorization: Bearer <admin-jwt-token>" \
  -F "company_id=acme-corp" \
  -F "name=Acme Corporation" \
  -F "email=security@acme.com" \
  -F "kms_cmk_id=arn:aws:kms:us-east-1:123456789012:key/..." \
  -F "public_key=@/path/to/pubkey.asc"
```

**Encrypt a file** (requires valid JWT):
```bash
curl -X POST https://localhost:8443/encrypt \
  -H "Authorization: Bearer <jwt-token>" \
  -F "company_id=acme-corp" \
  -F "file=@/path/to/sensitive-data.csv" \
  -o encrypted.pgp
```

Response headers include `X-Event-ID` and `X-Key-Version` for audit tracking.

---

## Claude Code Agent Configuration

This repository uses specialized agent instructions to guide Claude Code's behavior. The Go Security Expert agent provides comprehensive security guidance for Go development.

**Agent**: Go Security Expert
**Location**: `.claude/agents/go-security-expert.md`
**Purpose**: Provides expert-level Go language mastery and security best practices for all code reviews, implementations, and recommendations.

---

## Security Remediation

The codebase has undergone comprehensive security remediation addressing 26 identified vulnerabilities across 4 severity levels.

### Current Status

| Phase | Priority | Issues | Status | Commit |
|-------|----------|--------|--------|--------|
| Phase 1 | Critical | 4/4 | ✅ Complete | `ac1ac33` |
| Phase 2 | High | 7/7 | ✅ Complete | `677d8b3` |
| Phase 3 | Medium | 8/8 | ✅ Complete | `de77906` |
| Phase 4 | Low | 7 | ⏳ Pending | - |

**Overall Progress**: 19/26 vulnerabilities fixed (73%)

### Key Security Improvements

**Phase 1 - Critical Fixes**:
- Memory safety: Zero plaintext encryption keys after use (CWE-316)
- Race condition fix: Atomic version increment (CWE-362)
- DoS protection: Request size limits (CWE-770)
- Audit integrity: Error checking for all critical operations (CWE-252)

**Phase 2 - High Priority**:
- JWT expiration validation and clock skew tolerance (CWE-613)
- Per-IP rate limiting (10 req/s, burst 20) (CWE-770)
- Security headers (HSTS, CSP, X-Frame-Options, etc.) (CWE-693)
- TLS 1.3 enforcement with modern cipher suites (CWE-327)

**Phase 3 - Medium Priority**:
- Comprehensive input validation (company_id, email, name, KMS CMK ID)
- PGP key validation (expiration, strength, encryption capability)
- Content-Type validation for uploads
- Operation timeouts (5s PGP parsing, 10s database ops)

### References

- **Detailed History**: `.claude/SECURITY_REMEDIATION_HISTORY.md`
- **Issue Tracker**: [#6 - Security Vulnerabilities: Comprehensive Remediation Plan](https://github.com/rhousand/go-gpg-snowflake/issues/6)
- **Branch**: `security-remediation-comprehensive`
- **Standards Applied**: OWASP Top 10, CWE, PCI DSS, SOC 2, NIST 800-53

---
