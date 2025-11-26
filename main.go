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
	// SECURITY FIX: Add timeout for config loading
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// SECURITY FIX: Check AWS config loading error
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal("Failed to load AWS config:", err)
	}

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
		log.Fatal("JWT_SECRET must be at least 32 characters")
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

	// SECURITY FIX: Add request size limits middleware
	maxBytesHandler := func(maxBytes int64, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	// 100MB limit for file encryption uploads
	mux.Handle("/encrypt", maxBytesHandler(100*1024*1024, JWTAuth(http.HandlerFunc(app.EncryptHandler))))
	// 1MB limit for PGP key imports
	mux.Handle("/import-key", maxBytesHandler(1*1024*1024, JWTAuth(http.HandlerFunc(app.ImportKeyHandler))))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Secure PGP Exchange API running on :8443")
	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}
