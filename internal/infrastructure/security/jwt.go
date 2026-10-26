package security

import (
	"crypto/rsa"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sievers-kz/sievers-iam-service/internal/domain"
)

type Token struct {
	Value     string
	Type      domain.TokenType
	ExpiresAt time.Time
}

type TokenPair struct {
	Access  Token
	Refresh Token
}

type TokenService struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	accessLifetime  time.Duration
	refreshLifetime time.Duration
}

func NewTokenService(
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	accessLifetime time.Duration,
	refreshLifetime time.Duration,
) *TokenService {
	return &TokenService{
		privateKey:      privateKey,
		publicKey:       publicKey,
		accessLifetime:  accessLifetime,
		refreshLifetime: refreshLifetime,
	}
}

func (t *TokenService) GeneratePair(accountID uuid.UUID) (TokenPair, error) {
	now := time.Now().UTC()

	accessExpiration := now.Add(t.accessLifetime)
	accessSignedToken, accessSignErr := t.sign(accountID, domain.TokenTypeAccess, accessExpiration)
	if accessSignErr != nil {
		return TokenPair{}, domain.ErrInvalidToken
	}

	refreshExpiration := now.Add(t.refreshLifetime)
	refreshSignedToken, refreshSignErr := t.sign(accountID, domain.TokenTypeRefresh, refreshExpiration)
	if refreshSignErr != nil {
		return TokenPair{}, domain.ErrInvalidToken
	}

	return TokenPair{Access: accessSignedToken, Refresh: refreshSignedToken}, nil
}

func (t *TokenService) sign(
	accountID uuid.UUID,
	tokenType domain.TokenType,
	expiresAt time.Time,
) (Token, error) {
	claims := jwt.MapClaims{
		"jti":  uuid.New().String(),
		"sub":  accountID.String(),
		"exp":  jwt.NewNumericDate(expiresAt),
		"type": tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(t.privateKey)
	if err != nil {
		return Token{}, err
	}

	return Token{
		Value:     signed,
		Type:      tokenType,
		ExpiresAt: expiresAt,
	}, nil
}

func (t *TokenService) VerifyToken(tokenValue string, tokenType domain.TokenType) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (any, error) {
		return t.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())

	if err != nil {
		return uuid.Nil(), domain.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil(), domain.ErrInvalidToken
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil(), domain.ErrInvalidToken
	}

	tp, ok := claims["type"].(string)
	if !ok {
		return uuid.Nil(), domain.ErrInvalidToken
	}

	if string(tokenType) != tp {
		return uuid.Nil(), domain.ErrInvalidToken
	}

	accountID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil(), domain.ErrInvalidToken
	}

	return accountID, nil
}
