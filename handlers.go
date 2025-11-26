package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/openpgp"
)

type App struct {
	db  *DB
	kms *KMS
}

func (a *App) ImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !requireRole(r, "admin") {
		http.Error(w, "admin required", http.StatusForbidden)
		return
	}

	companyID := r.FormValue("company_id")
	name := r.FormValue("name")
	kmsID := r.FormValue("kms_cmk_id")
	file, _, err := r.FormFile("public_key")
	if err != nil || companyID == "" || kmsID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// SECURITY FIX: Check io.ReadAll error and add size limit
	armored, err := io.ReadAll(io.LimitReader(file, 1*1024*1024)) // 1MB limit
	if err != nil {
		logger.Error().Err(err).Msg("failed to read public key")
		http.Error(w, "failed to read key", http.StatusInternalServerError)
		return
	}
	if _, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(armored))); err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}

	err = a.db.UpsertCompany(&CompanyKey{
		CompanyID:        companyID,
		Name:             name,
		Email:            r.FormValue("email"),
		PublicKeyArmored: string(armored),
		KMSCMKID:         kmsID,
	})
	if err != nil {
		// SECURITY FIX: Don't expose internal error details
		logger.Error().Err(err).Str("company_id", companyID).Msg("failed to upsert company")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// SECURITY: Log successful key import for audit trail
	logger.Info().
		Str("company_id", companyID).
		Str("name", name).
		Str("kms_cmk_id", kmsID).
		Str("ip", r.RemoteAddr).
		Msg("PGP key imported successfully")

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Key imported"))
}

func (a *App) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	companyID := r.FormValue("company_id")
	file, _, err := r.FormFile("file")
	if err != nil || companyID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	company, err := a.db.GetCompany(companyID)
	if err != nil {
		// SECURITY FIX: Don't reveal company existence, use generic error
		logger.Warn().Err(err).Str("company_id", companyID).Msg("company not found")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	recipients, err := openpgp.ReadArmoredKeyRing(strings.NewReader(company.PublicKeyArmored))
	if err != nil {
		// SECURITY FIX: Don't expose internal details
		logger.Error().Err(err).Str("company_id", companyID).Msg("failed to parse stored public key")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	dk, err := a.kms.GenerateDataKey(ctx, company.KMSCMKID)
	if err != nil {
		logger.Error().Err(err).Str("company_id", companyID).Str("kms_cmk_id", company.KMSCMKID).Msg("KMS GenerateDataKey failed")
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}
	// SECURITY: Zero plaintext key from memory after use
	defer func() {
		for i := range dk.Plaintext {
			dk.Plaintext[i] = 0
		}
	}()

	version, err := a.db.IncrementVersion(companyID)
	if err != nil {
		logger.Error().Err(err).Str("company_id", companyID).Msg("failed to increment version")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	eventID := uuid.New().String()

	err = a.db.RecordEvent(&EncryptionEvent{
		EventID:             eventID,
		CompanyID:           companyID,
		KMSCMKID:            company.KMSCMKID,
		KeyVersion:          version,
		EncryptedDataKeyB64: base64.StdEncoding.EncodeToString(dk.CiphertextBlob),
	})
	if err != nil {
		logger.Error().Err(err).Str("event_id", eventID).Msg("CRITICAL: encryption succeeded but audit logging failed")
		http.Error(w, "audit logging failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pgp-encrypted")
	w.Header().Set("Content-Disposition", `attachment; filename="encrypted.pgp"`)
	w.Header().Set("X-Event-ID", eventID)
	w.Header().Set("X-Key-Version", fmt.Sprintf("%d", version))

	if err := EncryptHybridStream(w, recipients, file, dk.Plaintext); err != nil {
		logger.Error().Err(err).Str("event_id", eventID).Msg("encryption failed")
		// Note: Response headers already sent, can't send error to client
	}
}
