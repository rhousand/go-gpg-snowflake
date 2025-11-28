package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
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

// SECURITY FIX: Rate limiter per IP address
type rateLimiterMap struct {
	sync.RWMutex
	limiters map[string]*rate.Limiter
}

func newRateLimiterMap() *rateLimiterMap {
	return &rateLimiterMap{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (rl *rateLimiterMap) getLimiter(ip string) *rate.Limiter {
	rl.RLock()
	limiter, exists := rl.limiters[ip]
	rl.RUnlock()

	if !exists {
		rl.Lock()
		// Double-check after acquiring write lock
		limiter, exists = rl.limiters[ip]
		if !exists {
			// 10 requests per second with burst of 20
			limiter = rate.NewLimiter(10, 20)
			rl.limiters[ip] = limiter
		}
		rl.Unlock()
	}

	return limiter
}

func rateLimitMiddleware(rlMap *rateLimiterMap) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			limiter := rlMap.getLimiter(ip)

			if !limiter.Allow() {
				logger.Warn().
					Str("ip", ip).
					Str("path", r.URL.Path).
					Msg("rate limit exceeded")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
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

	// SECURITY FIX: Add security headers middleware
	securityHeadersMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			w.Header().Set("Referrer-Policy", "no-referrer")
			next.ServeHTTP(w, r)
		})
	}

	// SECURITY FIX: Initialize rate limiter
	rlMap := newRateLimiterMap()
	rateLimit := rateLimitMiddleware(rlMap)

	mux := http.NewServeMux()
	// 100MB limit for file encryption uploads with rate limiting
	mux.Handle("/encrypt", securityHeadersMiddleware(rateLimit(maxBytesHandler(100*1024*1024, JWTAuth(http.HandlerFunc(app.EncryptHandler))))))
	// 1MB limit for PGP key imports with rate limiting
	mux.Handle("/import-key", securityHeadersMiddleware(rateLimit(maxBytesHandler(1*1024*1024, JWTAuth(http.HandlerFunc(app.ImportKeyHandler))))))
	// PHASE 3 FIX (Issue 3.8): Harden /health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Apply security headers for consistency
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Return basic status without sensitive information
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// SECURITY FIX: Harden TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, // TLS 1.3 only
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
	}

	srv := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    tlsConfig,
	}

	log.Println("Secure PGP Exchange API running on :8443 (TLS 1.3)")
	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}
