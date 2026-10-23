package domain

import (
	"regexp"
	"unicode/utf8"
)

var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type Email struct {
	value string
}

func NewEmail(value string) (Email, error) {
	newEmail := Email{value: value}
	if err := newEmail.validateRequired(); err != nil {
		return Email{}, err
	}

	if err := newEmail.validateFormat(); err != nil {
		return Email{}, err
	}
	return newEmail, nil
}

func (e Email) validateRequired() error {
	if e.value == "" {
		return ErrEmailRequired
	}
	return nil
}

func (e Email) validateFormat() error {
	if !emailRe.MatchString(e.value) {
		return ErrInvalidEmail
	}
	return nil
}

func (e Email) Value() string {
	return e.value
}

type PlainPassword struct {
	value string
}

func NewPlainPassword(value string) (PlainPassword, error) {
	newPlainPassword := PlainPassword{value: value}
	if err := newPlainPassword.validateRequired(); err != nil {
		return PlainPassword{}, err
	}

	if err := newPlainPassword.validateLength(); err != nil {
		return PlainPassword{}, err
	}
	return newPlainPassword, nil
}

func (p PlainPassword) validateRequired() error {
	if p.value == "" {
		return ErrPasswordRequired
	}
	return nil
}

func (p PlainPassword) validateLength() error {
	passwordLength := utf8.RuneCountInString(p.value)
	if passwordLength < 8 || passwordLength > 64 {
		return ErrInvalidPassword
	}
	return nil
}

func (p PlainPassword) Value() string {
	return p.value
}

func (p PlainPassword) String() string {
	return "************"
}

type HashedPassword struct {
	value string
}

func NewHashedPassword(value string) (HashedPassword, error) {
	newHashedPassword := HashedPassword{value: value}
	if err := newHashedPassword.validateRequired(); err != nil {
		return HashedPassword{}, err
	}
	return newHashedPassword, nil
}

func (h HashedPassword) validateRequired() error {
	if h.value == "" {
		return ErrPasswordRequired
	}
	return nil
}

func (h HashedPassword) Value() string {
	return h.value
}

func (h HashedPassword) String() string {
	return "************"
}
