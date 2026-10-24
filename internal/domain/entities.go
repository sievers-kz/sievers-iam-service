package domain

import (
	"time"
	"uuid"
)

type Account struct {
	id                uuid.UUID
	email             Email
	password          HashedPassword
	passwordChangedAt time.Time
	isActive          bool
	createdAt         time.Time
	updatedAt         time.Time
	tokens            []*Token
}

func NewAccount(email Email, password HashedPassword) *Account {
	return &Account{
		id:                uuid.New(),
		email:             email,
		password:          password,
		passwordChangedAt: time.Now(),
		isActive:          false,
		createdAt:         time.Now(),
		updatedAt:         time.Now(),
		tokens:            make([]*Token, 0),
	}
}

func (a *Account) ConfirmAccount() error {
	if a.isActive {
		return ErrAccountAlreadyConfirmed
	}

	a.isActive = true
	return nil
}

func (a *Account) Login(tokenValue string, expiresAt time.Time) error {
	if !a.isActive {
		return ErrAccountNotConfirmed
	}

	a.addNewToken(TokenTypeRefresh, tokenValue, expiresAt)
	return nil
}

func (a *Account) Logout(value string) error {
	old, err := a.getActiveTokenByValue(value)
	if err != nil {
		return err
	}

	_ = old.revoke() // Old token is active, so, it results cannot be as revoked token
	return nil
}

func (a *Account) RefreshToken(oldToken string, newTokenValue string, expiresAt time.Time) error {
	old, err := a.getActiveTokenByValue(oldToken)
	if err != nil {
		return err
	}

	_ = old.revoke() // Old token is active, so, it results cannot be as revoked token
	a.addNewToken(TokenTypeRefresh, newTokenValue, expiresAt)
	return nil
}

func (a *Account) ResetPassword(newHashedPassword HashedPassword) {
	a.password = newHashedPassword
	a.passwordChangedAt = time.Now()
	a.revokeAllTokensByType(TokenTypeRefresh)
}

func (a *Account) ChangePassword(newHashedPassword HashedPassword) {
	a.password = newHashedPassword
	a.passwordChangedAt = time.Now()
	a.revokeAllTokensByType(TokenTypeRefresh)
}

func (a *Account) ChangeEmail(newEmail Email) {
	a.email = newEmail
}

func (a *Account) addNewToken(tokenType TokenType, value string, expiresAt time.Time) {
	newToken := NewToken(a.id, tokenType, value, expiresAt)
	a.tokens = append(a.tokens, newToken)
}

func (a *Account) revokeAllTokensByType(tokenType TokenType) {
	for _, t := range a.tokens {
		if t.tokenType == tokenType {
			err := t.revoke()
			if err != nil {
				continue // Already revoked, skipping
			}
		}
	}
}

func (a *Account) getActiveTokenByValue(value string) (*Token, error) {
	for _, t := range a.tokens {
		if t.value == value && !t.isRevoked {
			return t, nil
		}
	}
	return nil, ErrInvalidToken
}

type Token struct {
	id        uuid.UUID
	accountID uuid.UUID
	tokenType TokenType
	value     string
	isRevoked bool
	expiresAt time.Time
}

func NewToken(accountID uuid.UUID, tokenType TokenType, value string, expiresAt time.Time) *Token {
	return &Token{
		id:        uuid.New(),
		accountID: accountID,
		tokenType: tokenType,
		value:     value,
		isRevoked: false,
		expiresAt: expiresAt,
	}
}

func (t *Token) revoke() error {
	if t.isRevoked {
		return ErrTokenAlreadyRevoked
	}

	t.isRevoked = true
	return nil
}
