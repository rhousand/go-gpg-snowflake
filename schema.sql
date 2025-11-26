CREATE TABLE IF NOT EXISTS company_keys (
    company_id STRING PRIMARY KEY,
    name STRING,
    email STRING,
    public_key_armored STRING NOT NULL,
    kms_cmk_id STRING NOT NULL,
    current_version NUMBER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS encryption_events (
    event_id STRING PRIMARY KEY DEFAULT UUID_STRING(),
    company_id STRING,
    kms_cmk_id STRING,
    key_version NUMBER,
    encrypted_data_key_b64 STRING,
    encrypted_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);
