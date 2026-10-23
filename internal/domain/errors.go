package domain

import "fmt"

type ErrDomain struct {
	Category ErrCategoryType
	Code     string
	Message  string
}

func (e *ErrDomain) Error() string {
	return fmt.Sprintf(
		"Error category: %s, Error code: %s, Error message: %s",
		e.Category,
		e.Code,
		e.Message,
	)
}

func NewErrDomain(
	errorCategory ErrCategoryType,
	errorCode string,
	errorMessage string,
) *ErrDomain {
	return &ErrDomain{
		Category: errorCategory,
		Code:     errorCode,
		Message:  errorMessage,
	}
}

var (
	ErrAccountNotFound = NewErrDomain(
		ErrCategoryTypeNotFound,
		"account_not_found_error",
		"Account not found",
	)

	ErrAccountAlreadyExists = NewErrDomain(
		ErrCategoryTypeConflict,
		"account_already_exists_error",
		"Account already exists",
	)

	ErrAccountNotConfirmed = NewErrDomain(
		ErrCategoryTypeRules,
		"account_not_confirmed_error",
		"Account not confirmed",
	)

	ErrInvalidLoginCredentials = NewErrDomain(
		ErrCategoryTypeUnauthorized,
		"invalid_login_credentials_error",
		"Invalid login credentials",
	)

	ErrPasswordMismatch = NewErrDomain(
		ErrCategoryTypeRules,
		"password_mismatch_error",
		"Password mismatch",
	)

	ErrCompromisedPassword = NewErrDomain(
		ErrCategoryTypeRules,
		"compromised_password_error",
		"Password is weak",
	)
)
