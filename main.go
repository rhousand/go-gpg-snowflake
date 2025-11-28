package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

// PHASE 4 FIX (Issue 4.4): Request ID middleware for distributed tracing
// Generates unique request ID and adds to context and response headers
type contextKey string

const requestIDKey contextKey = "request_id"

func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b)
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for existing request ID in headers (for tracing across services)
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Add request ID to response headers
		w.Header().Set("X-Request-ID", requestID)

		// Add request ID to context for use in handlers and logging
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)

		// Add request ID to logger context for this request
		reqLogger := logger.With().Str("request_id", requestID).Logger()
		ctx = reqLogger.WithContext(ctx)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
	// PHASE 4: Middleware chain order: requestID → securityHeaders → rateLimit → maxBytes → JWT → handler
	// 100MB limit for file encryption uploads with rate limiting and request tracing
	mux.Handle("/encrypt", requestIDMiddleware(securityHeadersMiddleware(rateLimit(maxBytesHandler(100*1024*1024, JWTAuth(http.HandlerFunc(app.EncryptHandler)))))))
	// 1MB limit for PGP key imports with rate limiting and request tracing
	mux.Handle("/import-key", requestIDMiddleware(securityHeadersMiddleware(rateLimit(maxBytesHandler(1*1024*1024, JWTAuth(http.HandlerFunc(app.ImportKeyHandler)))))))
	// PHASE 4 FIX (Issue 4.2): Health check with database connectivity test
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Apply security headers for consistency
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Test database connectivity with timeout
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		dbHealthy := true
		if err := app.db.DB.PingContext(ctx); err != nil {
			logger.Error().Err(err).Msg("health check: database ping failed")
			dbHealthy = false
		}

		// Return health status
		if dbHealthy {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","database":"healthy"}`))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"degraded","database":"unhealthy"}`))
		}
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

	// PHASE 4 FIX (Issue 4.5): Graceful shutdown handling
	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info().Str("addr", srv.Addr).Msg("starting HTTPS server with TLS 1.3")
		serverErrors <- srv.ListenAndServeTLS("cert.pem", "key.pem")
	}()

	// Setup signal handling for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received or server error occurs
	select {
	case err := <-serverErrors:
		logger.Fatal().Err(err).Msg("server error")

	case sig := <-shutdown:
		logger.Info().Str("signal", sig.String()).Msg("shutdown signal received, starting graceful shutdown")

		// Create context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error().Err(err).Msg("graceful shutdown failed, forcing close")
			// Force close connections if graceful shutdown times out
			srv.Close()
		}

		// Close database connection
		if err := app.db.Close(); err != nil {
			logger.Error().Err(err).Msg("error closing database connection")
		}

		logger.Info().Msg("server shutdown complete")
	}
}
