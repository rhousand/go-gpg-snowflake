package main

type CompanyKey struct {
    CompanyID        string `db:"company_id"`
    Name             string `db:"name"`
    Email            string `db:"email"`
    PublicKeyArmored string `db:"public_key_armored"`
    KMSCMKID         string `db:"kms_cmk_id"`
    CurrentVersion   int    `db:"current_version"`
}

type EncryptionEvent struct {
    EventID             string
    CompanyID           string
    KMSCMKID            string
    KeyVersion          int
    EncryptedDataKeyB64 string
}
