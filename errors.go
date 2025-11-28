package main

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// PHASE 4 FIX (Issue 4.7): Structured error response types
// Provides consistent, structured error responses across the API

// ErrorResponse represents a structured API error response
type ErrorResponse struct {
	Error   string `json:"error"`             // Human-readable error message
	Code    string `json:"code,omitempty"`    // Machine-readable error code
	Details string `json:"details,omitempty"` // Additional error details (optional)
}

// ErrorCode represents machine-readable error codes
type ErrorCode string

const (
	ErrCodeValidation      ErrorCode = "VALIDATION_ERROR"
	ErrCodeUnauthorized    ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden       ErrorCode = "FORBIDDEN"
	ErrCodeNotFound        ErrorCode = "NOT_FOUND"
	ErrCodeInternal        ErrorCode = "INTERNAL_ERROR"
	ErrCodeRateLimit       ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrCodeTimeout         ErrorCode = "REQUEST_TIMEOUT"
	ErrCodeBadRequest      ErrorCode = "BAD_REQUEST"
	ErrCodeUnsupportedType ErrorCode = "UNSUPPORTED_MEDIA_TYPE"
)

// RespondWithError writes a structured error response to the client
// It logs the internal error server-side without exposing details to client
func RespondWithError(w http.ResponseWriter, r *http.Request, statusCode int, code ErrorCode, message string, internalErr error) {
	// Get logger from context (set by request ID middleware)
	logger := zerolog.Ctx(r.Context())

	// Log internal error with full details server-side
	if internalErr != nil {
		logger.Error().
			Err(internalErr).
			Str("error_code", string(code)).
			Int("status_code", statusCode).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg("request error")
	} else {
		logger.Warn().
			Str("error_code", string(code)).
			Int("status_code", statusCode).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg("request error")
	}

	// Create structured error response (client-safe)
	errResp := ErrorResponse{
		Error: message,
		Code:  string(code),
	}

	// Set headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	// Encode and send error response
	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		logger.Error().Err(err).Msg("failed to encode error response")
	}
}

// RespondWithJSON writes a successful JSON response
func RespondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}
