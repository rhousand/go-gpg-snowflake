package main

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

type ctxKey string

const claimsKey ctxKey = "claims"

func JWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			logger.Warn().
				Str("ip", r.RemoteAddr).
				Str("path", r.URL.Path).
				Msg("authentication failed: missing bearer token")
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		}, jwt.WithValidMethods([]string{"HS256"}))

		if err != nil || !token.Valid {
			logger.Warn().
				Str("ip", r.RemoteAddr).
				Str("path", r.URL.Path).
				Err(err).
				Msg("authentication failed: invalid token")
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireRole(r *http.Request, role string) bool {
	// Safe type assertion to prevent panic if claims not in context
	claimsVal := r.Context().Value(claimsKey)
	if claimsVal == nil {
		return false
	}
	claims, ok := claimsVal.(jwt.MapClaims)
	if !ok {
		return false
	}

	// Check if roles claim exists and is the correct type
	if roles, ok := claims["roles"].([]any); ok {
		// Use safe type assertion in loop to prevent panic
		for _, roleVal := range roles {
			if roleStr, ok := roleVal.(string); ok && roleStr == role {
				return true
			}
		}
	}
	return false
}
