package token

import (
	"time"

	"github.com/sievers-kz/sievers-iam-service/internal/domain"
)

type Token struct {
	Value     string
	Type      domain.TokenType
	ExpiresAt time.Time
}

type Pair struct {
	Access  Token
	Refresh Token
}
