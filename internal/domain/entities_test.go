package domain

import (
	"errors"
	"testing"
	"time"
	"uuid"
)

func AccountData(isActive bool, tokens []*Token) *Account {
	email := Email{value: "test@example.com"}
	password := HashedPassword{value: "some$hash$pass"}
	return &Account{
		id:                uuid.New(),
		email:             email,
		password:          password,
		passwordChangedAt: time.Now(),
		isActive:          isActive,
		createdAt:         time.Now(),
		updatedAt:         time.Now(),
		tokens:            tokens,
	}
}

func TokenData(isRevoked bool) *Token {
	return &Token{
		id:        uuid.New(),
		accountID: uuid.New(),
		tokenType: TokenTypeRefresh,
		value:     "testRefreshToken",
		isRevoked: isRevoked,
		expiresAt: time.Now().Add(time.Hour),
	}
}

func TestConfirmAccount(t *testing.T) {
	table := []struct {
		name    string
		account *Account
		err     error
	}{
		{name: "Success", account: AccountData(false, nil), err: nil},
		{name: "Failure", account: AccountData(true, nil), err: ErrAccountAlreadyConfirmed},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.account.ConfirmAccount()
			if !errors.Is(err, tt.err) {
				t.Errorf("ConfirmAccount(): Confirmation error:\ngot: %v\nwant: %v", err, tt.err)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	table := []struct {
		name       string
		account    *Account
		wantErr    error
		wantTokens int
	}{
		{
			name:       "Success",
			account:    AccountData(true, nil),
			wantErr:    nil,
			wantTokens: 1,
		},
		{
			name:       "Failure",
			account:    AccountData(false, nil),
			wantErr:    ErrAccountNotConfirmed,
			wantTokens: 0,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			refreshToken := TokenData(false)
			err := tt.account.Login(refreshToken.value, refreshToken.expiresAt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Login() error:\ngot: %v\nwant: %v", err, tt.wantErr)
			}

			tokens := len(tt.account.tokens)
			if tokens != tt.wantTokens {
				t.Errorf("Login() got: %v\nwant: %v", tokens, tt.wantTokens)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	table := []struct {
		name             string
		account          *Account
		wantErr          error
		logoutValue      string
		refreshIsRevoked bool
	}{
		{
			name:             "Success",
			account:          AccountData(true, []*Token{TokenData(false)}),
			wantErr:          nil,
			logoutValue:      "testRefreshToken",
			refreshIsRevoked: true,
		},
		{
			name:             "Failure",
			account:          AccountData(true, []*Token{TokenData(false)}),
			wantErr:          ErrInvalidToken,
			logoutValue:      "wrongRefreshToken",
			refreshIsRevoked: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.account.Logout(tt.logoutValue)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Logout() error:\ngot: %v\nwant: %v", err, tt.wantErr)
			}

			token := tt.account.tokens[0]
			if token.isRevoked != tt.refreshIsRevoked {
				t.Errorf("Logout() isRevoked:\ngot: %v\nwant: %v", token.isRevoked, tt.refreshIsRevoked)
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	table := []struct {
		name              string
		account           *Account
		wantErr           error
		refreshTokenValue string
		refreshIsRevoked  bool
		wantTokens        int
	}{
		{
			name:              "Success",
			account:           AccountData(true, []*Token{TokenData(false)}),
			wantErr:           nil,
			refreshTokenValue: "testRefreshToken",
			refreshIsRevoked:  true,
			wantTokens:        2,
		},
		{
			name:              "Invalid token",
			account:           AccountData(true, []*Token{TokenData(false)}),
			wantErr:           ErrInvalidToken,
			refreshTokenValue: "wrongRefreshToken",
			refreshIsRevoked:  false,
			wantTokens:        1,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			newRefreshToken := TokenData(false)
			err := tt.account.RefreshToken(tt.refreshTokenValue, newRefreshToken.value, newRefreshToken.expiresAt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Refresh token is failed:\ngot: %v\nwant: %v", err, tt.wantErr)
			}

			token := tt.account.tokens[0]
			if token.isRevoked != tt.refreshIsRevoked {
				t.Errorf("Refresh token() isRevoked:\ngot: %v\nwant: %v", token.isRevoked, tt.refreshIsRevoked)
			}

			tokens := len(tt.account.tokens)
			if tokens != tt.wantTokens {
				t.Errorf("Refresh token() got: %v\nwant: %v", tokens, tt.wantTokens)
			}
		})
	}
}

func TestReuseRefreshToken(t *testing.T) {
	account := AccountData(true, []*Token{TokenData(false)})

	err := account.RefreshToken("testRefreshToken", "newRefreshToken1", time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("Refresh token is failed:\ngot: %v\nwant: %v", err, nil)
	}

	oldRefreshToken := account.tokens[0]

	err2 := account.RefreshToken(oldRefreshToken.value, "newRefreshToken2", time.Now().Add(time.Hour))
	if !errors.Is(err2, ErrInvalidToken) {
		t.Errorf("Refresh token is failed:\ngot: %v\nwant: %v", err2, ErrInvalidToken)
	}

	tokens := len(account.tokens)
	if tokens != 2 {
		t.Errorf("Refresh token() got: %v\nwant: %v", tokens, 2)
	}
}

func TestResetPassword(t *testing.T) {
	account := AccountData(true, []*Token{TokenData(false)})
	newHashedPassword := HashedPassword{value: "newHashedPassword"}
	account.ResetPassword(newHashedPassword)

	changedPassword := account.password.Value()
	if changedPassword != newHashedPassword.Value() {
		t.Errorf("Password changed:\ngot: %v\nwant: %v", changedPassword, newHashedPassword.Value())
	}

	tokens := account.tokens
	for _, tt := range tokens {
		if !tt.isRevoked {
			t.Errorf("Reset password is failed:\ngot: %v\nwant: %v", tt.isRevoked, true)
		}
	}
}
