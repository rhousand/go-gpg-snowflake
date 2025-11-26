package main

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/snowflakedb/gosnowflake"
)

type DB struct{ *sqlx.DB }

func NewDB(cfg *Config) (*DB, error) {
	dsn := fmt.Sprintf("%s:%s@%s/%s/%s?warehouse=%s",
		cfg.SFUser, cfg.SFPassword, cfg.SFAccount,
		cfg.SFDatabase, cfg.SFSchema, cfg.SFWarehouse)

	db, err := sqlx.Connect("snowflake", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	return &DB{db}, nil
}

func (d *DB) GetCompany(id string) (*CompanyKey, error) {
	var c CompanyKey
	err := d.Get(&c, `SELECT * FROM company_keys WHERE company_id = ?`, id)
	return &c, err
}

func (d *DB) UpsertCompany(c *CompanyKey) error {
	_, err := d.NamedExec(`
        INSERT INTO company_keys 
        (company_id, name, email, public_key_armored, kms_cmk_id, current_version)
        VALUES (:company_id, :name, :email, :public_key_armored, :kms_cmk_id, COALESCE((SELECT current_version FROM company_keys WHERE company_id = :company_id), 0) + > 1)
        ON CONFLICT (company_id) DO UPDATE SET
            name = EXCLUDED.name,
            email = EXCLUDED.email,
            public_key_armored = EXCLUDED.public_key_armored,
            kms_cmk_id = EXCLUDED.kms_cmk_id,
            current_version = company_keys.current_version + 1`, c)
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
	_, err := d.Exec(`UPDATE company_keys SET current_version = current_version + 1 WHERE company_id = ?`, id)
	if err != nil {
		return 0, err
	}
	var v int
	d.Get(&v, `SELECT current_version FROM company_keys WHERE company_id = ?`, id)
	return v, nil
}
