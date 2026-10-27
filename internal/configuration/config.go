package configuration

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type AuthConfig struct {
	JWTPrivateKeyPath    string        `env:"JWT_PRIVATE_KEY_PATH,required"`
	JWTPublicKeyPath     string        `env:"JWT_PUBLIC_KEY_PATH,required"`
	AccessTokenLifetime  time.Duration `env:"ACCESS_TOKEN_LIFETIME" envDefault:"30m"`
	RefreshTokenLifetime time.Duration `env:"REFRESH_TOKEN_LIFETIME" envDefault:"72h"`
}

type AppConfig struct {
	Mode string `env:"APP_MODE" envDefault:"dev"`
	Auth AuthConfig
}

func Load() (AppConfig, error) {
	err := godotenv.Load(".env")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return AppConfig{}, fmt.Errorf("load .env: %w", err)
	}

	config, err := env.ParseAs[AppConfig]()
	if err != nil {
		return AppConfig{}, fmt.Errorf("parse config: %w", err)
	}

	return config, nil
}
