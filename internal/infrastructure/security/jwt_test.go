package security

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sievers-kz/sievers-iam-service/internal/domain"
	"github.com/stretchr/testify/require"
)

func newTestTokenService(t *testing.T) *TokenService {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey
	accessLifetime := 30 * time.Minute
	refreshLifetime := time.Duration(3) * 24 * time.Hour

	return NewTokenService(
		privateKey,
		publicKey,
		accessLifetime,
		refreshLifetime,
	)
}

func TestGeneratePair(t *testing.T) {
	svc := newTestTokenService(t)
	tokenPair, err := svc.GeneratePair(uuid.New())
	require.NoError(t, err)

	require.NotEmpty(t, tokenPair.Access.Value)
	require.NotEmpty(t, tokenPair.Refresh.Value)

	require.Equal(t, domain.TokenTypeAccess, tokenPair.Access.Type)
	require.Equal(t, domain.TokenTypeRefresh, tokenPair.Refresh.Type)

	require.Greater(t, tokenPair.Refresh.ExpiresAt, tokenPair.Access.ExpiresAt)
}

func TestVerifyToken(t *testing.T) {
	accountID := uuid.New()
	svc := newTestTokenService(t)

	tokenPair, err := svc.GeneratePair(accountID)
	require.NoError(t, err)

	accessAccountID, err := svc.VerifyToken(tokenPair.Access.Value, domain.TokenTypeAccess)
	require.NoError(t, err)

	refreshAccountID, err := svc.VerifyToken(tokenPair.Refresh.Value, domain.TokenTypeRefresh)
	require.NoError(t, err)

	require.Equal(t, accountID, accessAccountID)
	require.Equal(t, accountID, refreshAccountID)
}

func TestVerifyToken_Rejects(t *testing.T) {
	accountID := uuid.New()
	svc := newTestTokenService(t)

	claims := jwt.MapClaims{
		"jti":  uuid.New().String(),
		"sub":  accountID.String(),
		"exp":  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		"type": domain.TokenTypeAccess,
	}

	expiredAccessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := expiredAccessToken.SignedString(svc.privateKey)
	require.NoError(t, err)

	pair, err := svc.GeneratePair(accountID)
	require.NoError(t, err)

	foreignSvc := newTestTokenService(t)
	foreignPair, err := foreignSvc.GeneratePair(accountID)
	require.NoError(t, err)

	table := []struct {
		name          string
		tokenValue    string
		tokenType     domain.TokenType
		wantErr       error
		wantAccountID uuid.UUID
	}{
		{
			name:          "Invalid access token value",
			tokenValue:    "wrongAccessToken",
			tokenType:     domain.TokenTypeAccess,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
		{
			name:          "Invalid refresh token value",
			tokenValue:    "wrongRefreshToken",
			tokenType:     domain.TokenTypeRefresh,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
		{
			name:          "Invalid access token type",
			tokenValue:    pair.Access.Value,
			tokenType:     pair.Refresh.Type,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
		{
			name:          "Invalid refresh token type",
			tokenValue:    pair.Refresh.Value,
			tokenType:     pair.Access.Type,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
		{
			name:          "Foreign access token signing",
			tokenValue:    foreignPair.Access.Value,
			tokenType:     foreignPair.Access.Type,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
		{
			name:          "Foreign refresh token signing",
			tokenValue:    foreignPair.Refresh.Value,
			tokenType:     foreignPair.Refresh.Type,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
		{
			name:          "Expired access token",
			tokenValue:    signed,
			tokenType:     domain.TokenTypeAccess,
			wantErr:       domain.ErrInvalidToken,
			wantAccountID: uuid.Nil(),
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			returnedAccountID, err := svc.VerifyToken(tt.tokenValue, tt.tokenType)
			require.ErrorIs(t, err, tt.wantErr)
			require.EqualValues(t, tt.wantAccountID, returnedAccountID)
		})
	}
}
