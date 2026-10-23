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

type ErrCategoryType string

const (
	ErrCategoryTypeUnknown      ErrCategoryType = "unknown_error"
	ErrCategoryTypeConflict     ErrCategoryType = "conflict_error"
	ErrCategoryTypeNotFound     ErrCategoryType = "not_found_error"
	ErrCategoryTypeRules        ErrCategoryType = "rules_error"
	ErrCategoryTypeValidation   ErrCategoryType = "validation_error"
	ErrCategoryTypeUnauthorized ErrCategoryType = "unauthorized_error"
	ErrCategoryTypeAccessDenied ErrCategoryType = "access_denied_error"
)
