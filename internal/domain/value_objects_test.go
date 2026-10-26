package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewEmail(t *testing.T) {
	table := []struct {
		name    string
		value   string
		wantVal string
		wantErr error
	}{
		{name: "Valid email", value: "test@example.com", wantVal: "test@example.com", wantErr: nil},
		{name: "Lowered email", value: "Test@example.com", wantVal: "test@example.com", wantErr: nil},
		{name: "Stripped email", value: "  test@example.com  ", wantVal: "test@example.com", wantErr: nil},
		{name: "Empty email", value: "", wantVal: "", wantErr: ErrEmailRequired},
		{name: "Spaces only", value: "    ", wantVal: "", wantErr: ErrEmailRequired},
		{name: "Invalid email", value: "test", wantVal: "", wantErr: ErrInvalidEmail},
		{name: "Invalid domain", value: "test@example", wantVal: "", wantErr: ErrInvalidEmail},
		{name: "Spaces before domain", value: "test @example.com", wantVal: "", wantErr: ErrInvalidEmail},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			out, err := NewEmail(tt.value)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("[NewEmail]: Email is incorrect\ngot: %v, \nwant: %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && out.Value() != tt.wantVal {
				t.Errorf("[NewEmail]: Email is incorrect\ngot: %s, want: %s", out.Value(), tt.wantVal)
			}
		})
	}
}

func TestNewPlainPassword(t *testing.T) {
	table := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "Valid plain password", value: "supersecret", wantErr: nil},
		{name: "Empty plain password", value: "", wantErr: ErrPasswordRequired},
		{name: "Password too short", value: "1234567", wantErr: ErrInvalidPassword},
		{name: "Min length boundary", value: "password", wantErr: nil},
		{name: "Max length boundary", value: strings.Repeat("a", 64), wantErr: nil},
		{name: "Above max length", value: strings.Repeat("a", 65), wantErr: ErrInvalidPassword},
		{name: "Cyrillic below min", value: "яяяяя", wantErr: ErrInvalidPassword},
		{name: "Cyrillic within limit", value: strings.Repeat("я", 33), wantErr: nil},
		{name: "With Spaces between", value: "pass word 123", wantErr: nil},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPlainPassword(tt.value)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("[NewPlainPassword]: Password is incorrect\ngot: %v, want: %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordPrintingMask(t *testing.T) {
	inputPass := "password123"
	out, err := NewPlainPassword(inputPass)
	if err != nil {
		t.Fatalf("NewPlainPassword: %v", err)
	}

	if val := fmt.Sprint(out); strings.Contains(val, inputPass) {
		t.Errorf("String() leaked the password")
	}
}
