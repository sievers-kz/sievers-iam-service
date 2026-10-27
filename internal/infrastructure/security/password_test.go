package security

import (
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
	"github.com/sievers-kz/sievers-iam-service/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPasswordService(t *testing.T) *PasswordService {
	t.Helper()
	svc := NewPasswordService()

	testHashParams := argon2id.Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	svc.hashParams = &testHashParams
	return svc
}

func TestHash(t *testing.T) {
	svc := newTestPasswordService(t)
	plainPassword, err := domain.NewPlainPassword("plainPassword")
	require.NoError(t, err)

	hashedPassword, err := svc.Hash(plainPassword)
	require.NoError(t, err)

	hashedPassword2, err := svc.Hash(plainPassword)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(hashedPassword.Value(), "$argon2id$"))

	assert.NotEqual(t, hashedPassword.Value(), hashedPassword2.Value())
	assert.NotEqual(t, hashedPassword.Value(), plainPassword.Value())
}

func TestVerify(t *testing.T) {
	svc := newTestPasswordService(t)
	plainPassword, err := domain.NewPlainPassword("plainPassword")
	require.NoError(t, err)

	hashedPassword, err := svc.Hash(plainPassword)
	require.NoError(t, err)

	match, err := svc.Verify(plainPassword.Value(), hashedPassword.Value())
	require.NoError(t, err)
	assert.True(t, match)

	mismatch, err := svc.Verify("somePassword", hashedPassword.Value())
	require.NoError(t, err)
	assert.False(t, mismatch)
}
