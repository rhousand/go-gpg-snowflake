package main

import (
    "context"
    "net/http"
    "strings"
    "github.com/golang-jwt/jwt/v5"
)

type ctxKey string
const claimsKey ctxKey = "claims"

func JWTAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        if !strings.HasPrefix(auth, "Bearer ") {
            http.Error(w, "missing token", http.StatusUnauthorized)
            return
        }
        tokenStr := strings.TrimPrefix(auth, "Bearer ")

        claims := jwt.MapClaims{}
        token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
            return []byte(cfg.JWTSecret), nil
        }, jwt.WithValidMethods([]string{"HS256"}))

        if err != nil || !token.Valid {
            http.Error(w, "invalid token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), claimsKey, claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func requireRole(r *http.Request, role string) bool {
    claims := r.Context().Value(claimsKey).(jwt.MapClaims)
    if roles, ok := claims["roles"].([]any); ok {
        for _, r := range roles {
            if r.(string) == role {
                return true
            }
        }
    }
    return false
}
