package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func loadConfig() (config, error) {
	sessionTimeout, err := durationEnv("SESSION_TIMEOUT", 30*time.Minute)
	if err != nil {
		return config{}, err
	}
	lockoutDuration, err := durationEnv("LOCKOUT_DURATION", 15*time.Minute)
	if err != nil {
		return config{}, err
	}
	maxAttempts, err := intEnv("MAX_FAILED_ATTEMPTS", 5)
	if err != nil {
		return config{}, err
	}
	if maxAttempts < 1 {
		return config{}, errors.New("MAX_FAILED_ATTEMPTS must be at least 1")
	}
	cost, err := intEnv("BCRYPT_COST", bcrypt.DefaultCost)
	if err != nil {
		return config{}, err
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return config{}, fmt.Errorf("BCRYPT_COST must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	mfaEncryptionKey, err := mfaEncryptionKeyEnv()
	if err != nil {
		return config{}, err
	}

	return config{
		dbPath:            stringEnv("DB_PATH", "./data/auth.db"),
		sessionTimeout:    sessionTimeout,
		maxFailedAttempts: maxAttempts,
		lockoutDuration:   lockoutDuration,
		bcryptCost:        cost,
		mfaEncryptionKey:  mfaEncryptionKey,
	}, nil
}

func mfaEncryptionKeyEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("MFA_ENCRYPTION_KEY"))
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("MFA_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}
	return key, nil
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 30m or 1h: %w", key, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return duration, nil
}

func intEnv(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return value, nil
}

func stringEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
