package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const encryptedMFASecretPrefix = "v1:"

func ensureMFASecretsEncrypted(db *sql.DB, encryptionKey []byte) error {
	type storedSecret struct {
		id     int64
		secret string
	}

	rows, err := db.Query(`SELECT id, mfa_secret FROM users WHERE mfa_enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var secrets []storedSecret
	for rows.Next() {
		var item storedSecret
		if err := rows.Scan(&item.id, &item.secret); err != nil {
			return err
		}
		secrets = append(secrets, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(secrets) == 0 {
		return nil
	}
	if len(encryptionKey) == 0 {
		return errors.New("MFA_ENCRYPTION_KEY is required because MFA is enabled for one or more users")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range secrets {
		if item.secret == "" {
			return fmt.Errorf("user %d has MFA enabled without a secret", item.id)
		}
		if strings.HasPrefix(item.secret, encryptedMFASecretPrefix) {
			if _, err := decryptMFASecret(encryptionKey, item.secret); err != nil {
				return fmt.Errorf("cannot decrypt MFA secret for user %d: %w", item.id, err)
			}
			continue
		}
		encrypted, err := encryptMFASecret(encryptionKey, item.secret)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE users SET mfa_secret = ? WHERE id = ?`, encrypted, item.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func encryptMFASecret(key []byte, secret string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	payload := append(nonce, gcm.Seal(nil, nonce, []byte(secret), nil)...)
	return encryptedMFASecretPrefix + base64.RawStdEncoding.EncodeToString(payload), nil
}

func decryptMFASecret(key []byte, stored string) (string, error) {
	if !strings.HasPrefix(stored, encryptedMFASecretPrefix) {
		return "", errors.New("MFA secret is not encrypted")
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, encryptedMFASecretPrefix))
	if err != nil {
		return "", errors.New("invalid encrypted MFA secret")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted MFA secret")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("invalid MFA encryption key or encrypted MFA secret")
	}
	return string(plaintext), nil
}
