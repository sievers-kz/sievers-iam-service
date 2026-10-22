package domain

type TokenType string

const (
	TokenTypeRefresh  TokenType = "refresh"
	TokenTypeAccess   TokenType = "access"
	TokenTypeEmail    TokenType = "email"
	TokenTypePassword TokenType = "password"
)

type OTPType string

const (
	OTPTypeConfirmation      OTPType = "confirmation"
	OTPTypePasswordReset     OTPType = "password_reset"
	OTPTypeChangeEmail       OTPType = "change_email"
	OTPTypeChangePassword    OTPType = "change_password"
	OTPTypeChangePhoneNumber OTPType = "change_phone"
)
