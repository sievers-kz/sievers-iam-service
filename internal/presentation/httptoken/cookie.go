package httptoken

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sievers-kz/sievers-iam-service/internal/application/token"
)

const (
	accessToken  = "accessToken"
	refreshToken = "refreshToken"
)

type CookieWriter struct {
	secure bool
}

func NewCookieWriter(secure bool) *CookieWriter {
	return &CookieWriter{secure: secure}
}

func (s *CookieWriter) SetCookies(w http.ResponseWriter, tokenPair token.Pair) error {
	accessMaxAge, err := maxAge(tokenPair.Access)
	if err != nil {
		return fmt.Errorf("access token: %w", err)
	}

	refreshMaxAge, err := maxAge(tokenPair.Refresh)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     accessToken,
		Value:    tokenPair.Access.Value,
		Path:     "/",
		MaxAge:   accessMaxAge,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     refreshToken,
		Value:    tokenPair.Refresh.Value,
		Path:     "/api/v1/iam",
		MaxAge:   refreshMaxAge,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (s *CookieWriter) ClearCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     accessToken,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshToken,
		Value:    "",
		Path:     "/api/v1/iam",
		MaxAge:   -1,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func maxAge(t token.Token) (int, error) {
	if t.ExpiresAt.IsZero() {
		return 0, errors.New("expiration time is not set")
	}
	seconds := int(time.Until(t.ExpiresAt).Seconds())
	if seconds <= 0 {
		return 0, errors.New("token already expired")
	}
	return seconds, nil
}
