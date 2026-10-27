package security

import (
	"github.com/alexedwards/argon2id"
	"github.com/sievers-kz/sievers-iam-service/internal/domain"
)

type PasswordService struct {
	hashParams *argon2id.Params
}

func NewPasswordService() *PasswordService {
	return &PasswordService{
		hashParams: &argon2id.Params{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

func (ps *PasswordService) Validate(plainPassword string) (domain.PlainPassword, error) {
	validatedPlain, err := domain.NewPlainPassword(plainPassword)
	if err != nil {
		return domain.PlainPassword{}, err
	}

	// TODO: здесь должна быть проверка по черному списку паролей (bloom)

	return validatedPlain, nil
}

func (ps *PasswordService) Hash(plainPassword domain.PlainPassword) (domain.HashedPassword, error) {
	hash, err := argon2id.CreateHash(plainPassword.Value(), ps.hashParams)
	if err != nil {
		return domain.HashedPassword{}, err
	}

	hashedPassword, err := domain.NewHashedPassword(hash)
	if err != nil {
		return domain.HashedPassword{}, err
	}

	return hashedPassword, nil
}

func (ps *PasswordService) Verify(plainPassword string, hashedPassword string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(plainPassword, hashedPassword)
	if err != nil {
		return false, err
	}

	return match, nil
}
