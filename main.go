package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/rs/zerolog"
)

type Config struct {
	SFAccount   string `json:"SF_ACCOUNT"`
	SFUser      string `json:"SF_USER"`
	SFPassword  string `json:"SF_PASSWORD"`
	SFWarehouse string `json:"SF_WAREHOUSE"`
	SFDatabase  string `json:"SF_DATABASE"`
	SFSchema    string `json:"SF_SCHEMA"`
	JWTSecret   string `json:"JWT_SECRET"`
}

var cfg Config
var app *App
var logger zerolog.Logger

func loadConfig() {
	ctx := context.TODO()
	awsCfg, _ := config.LoadDefaultConfig(ctx)

	client := secretsmanager.NewFromConfig(awsCfg)
	secretName := os.Getenv("SECRETS_MANAGER_NAME")
	if secretName == "" {
		secretName = "gopgp/prod/config"
	}

	var secretString string
	if len(secretName) > 8 && secretName[:7] == "file://" {
		data, err := os.ReadFile(secretName[7:])
		if err != nil {
			log.Fatal("Failed to read local secret:", err)
		}
		secretString = string(data)
	} else {
		out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			log.Fatal("Secrets Manager error:", err)
		}
		secretString = *out.SecretString
	}

	if err := json.Unmarshal([]byte(secretString), &cfg); err != nil {
		log.Fatal("Invalid secret JSON:", err)
	}
	if len(cfg.JWTSecret) < 32 {
		log.Fatal("JWT_SECRET too short")
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.SetFlags(0)

	// Initialize structured logger
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	loadConfig()

	db, err := NewDB(&cfg)
	if err != nil {
		log.Fatal("Snowflake:", err)
	}

	app = &App{
		db:  db,
		kms: NewKMS(),
	}

	mux := http.NewServeMux()
	mux.Handle("/encrypt", JWTAuth(http.HandlerFunc(app.EncryptHandler)))
	mux.Handle("/import-key", JWTAuth(http.HandlerFunc(app.ImportKeyHandler)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
	}

	log.Println("Secure PGP Exchange API running on :8443")
	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}
