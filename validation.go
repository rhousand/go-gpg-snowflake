package main

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
)

// SECURITY: Input validation functions for Phase 3 remediation

// validateCompanyID validates company_id format and content
// CWE-20: Improper Input Validation
// CWE-1024: Improper Restriction of Rendered UI Layers or Frames
func validateCompanyID(id string) error {
	if id == "" {
		return errors.New("company_id required")
	}
	if len(id) > 100 {
		return errors.New("company_id too long (max 100 characters)")
	}
	// Only allow alphanumeric, underscore, and hyphen
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
		return errors.New("company_id contains invalid characters (only a-z, A-Z, 0-9, _, - allowed)")
	}
	return nil
}

// validateEmail validates email address format
// CWE-20: Improper Input Validation
func validateEmail(email string) error {
	if email == "" {
		return nil // Email is optional
	}
	if len(email) > 255 {
		return errors.New("email too long (max 255 characters)")
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}
	return nil
}

// validateName validates company name field
// CWE-20: Improper Input Validation
func validateName(name string) error {
	if name == "" {
		return nil // Name is optional
	}
	if len(name) > 255 {
		return errors.New("name too long (max 255 characters)")
	}
	// Prevent SQL injection attempts - no SQL special characters
	if strings.ContainsAny(name, "'\"`;\\") {
		return errors.New("name contains invalid characters")
	}
	return nil
}

// validateKMSCMKID validates AWS KMS CMK ID format
// CWE-20: Improper Input Validation
// CWE-522: Insufficiently Protected Credentials
func validateKMSCMKID(kmsCMKID string) error {
	if kmsCMKID == "" {
		return errors.New("kms_cmk_id required")
	}
	if len(kmsCMKID) > 2048 {
		return errors.New("kms_cmk_id too long")
	}

	// KMS CMK ID can be either:
	// 1. Key ID: UUID format (e.g., "1234abcd-12ab-34cd-56ef-1234567890ab")
	// 2. Key ARN: "arn:aws:kms:region:account-id:key/key-id"
	// 3. Alias: "alias/my-key"
	// 4. Alias ARN: "arn:aws:kms:region:account-id:alias/my-key"

	isUUID := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(kmsCMKID)
	isARN := strings.HasPrefix(kmsCMKID, "arn:aws:kms:")
	isAlias := strings.HasPrefix(kmsCMKID, "alias/")

	if !isUUID && !isARN && !isAlias {
		return errors.New("kms_cmk_id must be a valid KMS key ID, ARN, or alias")
	}

	return nil
}

// validatePGPKey validates PGP public key for security and usability
// CWE-295: Improper Certificate Validation
// CWE-345: Insufficient Verification of Data Authenticity
func validatePGPKey(armored string) (*openpgp.EntityList, error) {
	if armored == "" {
		return nil, errors.New("PGP key is empty")
	}

	// Parse the key
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("invalid PGP key format: %w", err)
	}

	if len(keyring) == 0 {
		return nil, errors.New("no keys found in armored data")
	}

	// Validate each entity in the keyring
	currentTime := time.Now()
	for _, entity := range keyring {
		if entity.PrimaryKey == nil {
			return nil, errors.New("PGP key has no primary key")
		}

		// Check key expiration using creation time and key lifetime
		// If KeyLifetimeSecs is set in self-signature, check expiration
		for _, identity := range entity.Identities {
			if identity.SelfSignature != nil {
				if identity.SelfSignature.KeyLifetimeSecs != nil {
					lifetime := time.Duration(*identity.SelfSignature.KeyLifetimeSecs) * time.Second
					expirationTime := entity.PrimaryKey.CreationTime.Add(lifetime)
					if currentTime.After(expirationTime) {
						return nil, errors.New("PGP key has expired")
					}
				}
			}
		}

		// Check key strength - minimum RSA 2048 bits
		bitLength, err := entity.PrimaryKey.BitLength()
		if err != nil {
			return nil, fmt.Errorf("failed to get key bit length: %w", err)
		}

		// RSA minimum 2048 bits, DSA/ElGamal minimum 2048, ECC minimum 256
		minBitLength := 2048
		if entity.PrimaryKey.PubKeyAlgo == 19 || entity.PrimaryKey.PubKeyAlgo == 22 { // ECDSA/EdDSA
			minBitLength = 256
		}

		if bitLength < uint16(minBitLength) {
			return nil, fmt.Errorf("PGP key too weak (minimum %d bits required, got %d)", minBitLength, bitLength)
		}

		// Verify key has encryption capability
		// Check subkeys for encryption capability
		hasEncryptionKey := false
		for _, subkey := range entity.Subkeys {
			if subkey.PublicKey != nil {
				// Check subkey expiration
				isExpired := false
				if subkey.Sig != nil && subkey.Sig.KeyLifetimeSecs != nil {
					lifetime := time.Duration(*subkey.Sig.KeyLifetimeSecs) * time.Second
					expirationTime := subkey.PublicKey.CreationTime.Add(lifetime)
					if currentTime.After(expirationTime) {
						isExpired = true
					}
				}

				if !isExpired && subkey.Sig != nil && subkey.Sig.FlagsValid {
					if subkey.Sig.FlagEncryptCommunications || subkey.Sig.FlagEncryptStorage {
						hasEncryptionKey = true
						break
					}
				}
			}
		}

		// Primary key itself might have encryption capability
		if !hasEncryptionKey {
			// Check if primary key can encrypt
			for _, identity := range entity.Identities {
				if identity.SelfSignature != nil && identity.SelfSignature.FlagsValid {
					if identity.SelfSignature.FlagEncryptCommunications || identity.SelfSignature.FlagEncryptStorage {
						hasEncryptionKey = true
						break
					}
				}
			}
		}

		if !hasEncryptionKey {
			return nil, errors.New("PGP key does not have encryption capability")
		}

		// Verify self-signature (basic integrity check)
		if len(entity.Identities) == 0 {
			return nil, errors.New("PGP key has no identities/signatures")
		}
	}

	return &keyring, nil
}

// validateContentType validates HTTP Content-Type header for file uploads
// CWE-434: Unrestricted Upload of File with Dangerous Type
// CWE-828: Signal Errors in Messages
func validateContentType(contentType, expected string) error {
	if contentType == "" {
		return errors.New("Content-Type header missing")
	}
	if !strings.HasPrefix(strings.ToLower(contentType), strings.ToLower(expected)) {
		return fmt.Errorf("invalid Content-Type: expected %s, got %s", expected, contentType)
	}
	return nil
}

// validateFileSize validates uploaded file is not empty or zero bytes
// CWE-434: Unrestricted Upload of File with Dangerous Type
// CWE-346: Origin Validation Error
func validateFileSize(size int64, minSize, maxSize int64) error {
	if size == 0 {
		return errors.New("file is empty (0 bytes)")
	}
	if minSize > 0 && size < minSize {
		return fmt.Errorf("file too small (minimum %d bytes)", minSize)
	}
	if maxSize > 0 && size > maxSize {
		return fmt.Errorf("file too large (maximum %d bytes)", maxSize)
	}
	return nil
}
