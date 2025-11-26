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

	armored, _ := io.ReadAll(file)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	recipients, err := openpgp.ReadArmoredKeyRing(strings.NewReader(company.PublicKeyArmored))
	if err != nil {
		http.Error(w, "bad key", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	dk, err := a.kms.GenerateDataKey(ctx, company.KMSCMKID)
	if err != nil {
		http.Error(w, "KMS error", http.StatusInternalServerError)
		return
	}

	version, _ := a.db.IncrementVersion(companyID)
	eventID := uuid.New().String()

	a.db.RecordEvent(&EncryptionEvent{
		EventID:             eventID,
		CompanyID:           companyID,
		KMSCMKID:            company.KMSCMKID,
		KeyVersion:          version,
		EncryptedDataKeyB64: base64.StdEncoding.EncodeToString(dk.CiphertextBlob),
	})

	w.Header().Set("Content-Type", "application/pgp-encrypted")
	w.Header().Set("Content-Disposition", `attachment; filename="encrypted.pgp"`)
	w.Header().Set("X-Event-ID", eventID)
	w.Header().Set("X-Key-Version", fmt.Sprintf("%d", version))

	EncryptHybridStream(w, recipients, file, dk.Plaintext)
}
