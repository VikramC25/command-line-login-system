package app

import (
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestMFAEncryptionKeyEnvAcceptsPaddedBase64(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	t.Setenv("MFA_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))

	parsed, err := mfaEncryptionKeyEnv()
	if err != nil {
		t.Fatalf("mfaEncryptionKeyEnv() error = %v", err)
	}
	if string(parsed) != string(key) {
		t.Fatalf("parsed key = %q, want %q", parsed, key)
	}
}

func TestMFASecretEncryptionRoundTrip(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	secret := "JBSWY3DPEHPK3PXP"

	encrypted, err := encryptMFASecret(key, secret)
	if err != nil {
		t.Fatalf("encryptMFASecret() error = %v", err)
	}
	if !strings.HasPrefix(encrypted, encryptedMFASecretPrefix) {
		t.Fatalf("encrypted secret is missing prefix: %q", encrypted)
	}
	if encrypted == secret {
		t.Fatal("encrypted secret must not equal plaintext")
	}

	decrypted, err := decryptMFASecret(key, encrypted)
	if err != nil {
		t.Fatalf("decryptMFASecret() error = %v", err)
	}
	if decrypted != secret {
		t.Fatalf("decrypted secret = %q, want %q", decrypted, secret)
	}
}

func TestMFASecretDecryptionRejectsWrongKey(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	encrypted, err := encryptMFASecret(key, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("encryptMFASecret() error = %v", err)
	}
	if _, err := decryptMFASecret(wrongKey, encrypted); err == nil {
		t.Fatal("decryptMFASecret() succeeded with the wrong key")
	}
}

func TestEnsureMFASecretsEncryptedMigratesPlaintextSecret(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close()
	if err := initDB(db); err != nil {
		t.Fatalf("initDB() error = %v", err)
	}

	const plaintextSecret = "JBSWY3DPEHPK3PXP"
	if _, err := db.Exec(`
INSERT INTO users (username, password_hash, registered_at, mfa_enabled, mfa_secret)
VALUES (?, ?, ?, 1, ?)`, "alice", "hash", time.Now().UTC(), plaintextSecret); err != nil {
		t.Fatalf("insert user error = %v", err)
	}
	key := []byte("01234567890123456789012345678901")
	if err := ensureMFASecretsEncrypted(db, key); err != nil {
		t.Fatalf("ensureMFASecretsEncrypted() error = %v", err)
	}

	var stored string
	if err := db.QueryRow(`SELECT mfa_secret FROM users WHERE username = ?`, "alice").Scan(&stored); err != nil {
		t.Fatalf("query migrated secret error = %v", err)
	}
	if !strings.HasPrefix(stored, encryptedMFASecretPrefix) {
		t.Fatalf("stored secret was not encrypted: %q", stored)
	}
	decrypted, err := decryptMFASecret(key, stored)
	if err != nil {
		t.Fatalf("decrypt migrated secret error = %v", err)
	}
	if decrypted != plaintextSecret {
		t.Fatalf("decrypted migrated secret = %q, want %q", decrypted, plaintextSecret)
	}
}
