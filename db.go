package main

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/snowflakedb/gosnowflake"
)

type DB struct{ *sqlx.DB }

func NewDB(cfg *Config) (*DB, error) {
	// SECURITY: Don't log DSN as it contains credentials
	dsn := fmt.Sprintf("%s:%s@%s/%s/%s?warehouse=%s",
		cfg.SFUser, cfg.SFPassword, cfg.SFAccount,
		cfg.SFDatabase, cfg.SFSchema, cfg.SFWarehouse)

	db, err := sqlx.Connect("snowflake", dsn)
	if err != nil {
		// Don't include DSN in error message
		logger.Error().Err(err).Msg("failed to connect to Snowflake")
		return nil, fmt.Errorf("database connection failed: %w", err)
	}
	// SECURITY FIX: Complete connection pooling configuration
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return &DB{db}, nil
}

func (d *DB) GetCompany(id string) (*CompanyKey, error) {
	var c CompanyKey
	err := d.Get(&c, `SELECT * FROM company_keys WHERE company_id = ?`, id)
	return &c, err
}

func (d *DB) UpsertCompany(c *CompanyKey) error {
	// SECURITY FIX: Fixed SQL syntax error (was "+ > 1", should be "+ 1")
	// Using MERGE for Snowflake (Snowflake doesn't support ON CONFLICT)
	_, err := d.NamedExec(`
		MERGE INTO company_keys t
		USING (SELECT :company_id AS company_id) s
		ON t.company_id = s.company_id
		WHEN MATCHED THEN UPDATE SET
			name = :name,
			email = :email,
			public_key_armored = :public_key_armored,
			kms_cmk_id = :kms_cmk_id,
			current_version = t.current_version + 1
		WHEN NOT MATCHED THEN INSERT
			(company_id, name, email, public_key_armored, kms_cmk_id, current_version)
			VALUES (:company_id, :name, :email, :public_key_armored, :kms_cmk_id, 1)`, c)
	return err
}

func (d *DB) RecordEvent(e *EncryptionEvent) error {
	_, err := d.NamedExec(`
        INSERT INTO encryption_events 
        (event_id, company_id, kms_cmk_id, key_version, encrypted_data_key_b64)
        VALUES (:event_id, :company_id, :kms_cmk_id, :key_version, :encrypted_data_key_b64)`,
		map[string]any{
			"event_id":               e.EventID,
			"company_id":             e.CompanyID,
			"kms_cmk_id":             e.KMSCMKID,
			"key_version":            e.KeyVersion,
			"encrypted_data_key_b64": e.EncryptedDataKeyB64,
		})
	return err
}

func (d *DB) IncrementVersion(id string) (int, error) {
	// SECURITY FIX: Use atomic operation to prevent race condition
	// Previous version had two separate queries (UPDATE then SELECT) which could
	// cause concurrent requests to get wrong version numbers in audit trail
	var v int
	err := d.Get(&v, `
		UPDATE company_keys
		SET current_version = current_version + 1
		WHERE company_id = ?
		RETURNING current_version`, id)
	return v, err
}
