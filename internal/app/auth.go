package app

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func (a *app) register() error {
	username, err := a.readLine("username: ")
	if err != nil {
		return err
	}
	if err := validateUsername(username); err != nil {
		return err
	}
	password, err := a.readPassword("password: ")
	if err != nil {
		return err
	}
	confirm, err := a.readPassword("confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return errors.New("passwords do not match")
	}
	if err := validatePassword(password); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), a.cfg.bcryptCost)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`INSERT INTO users (username, password_hash, registered_at) VALUES (?, ?, ?)`, username, string(hash), time.Now().UTC())
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("username already exists")
		}
		return err
	}
	fmt.Println("Registration successful. You can login now.")
	return nil
}

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return errors.New("username must be 3-32 characters")
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return errors.New("username may contain only letters, numbers, underscore, and dash")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func (a *app) login() error {
	username, err := a.readLine("username: ")
	if err != nil {
		return err
	}
	password, err := a.readPassword("password: ")
	if err != nil {
		return err
	}

	u, err := a.findUser(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("invalid username or password")
		}
		return err
	}
	now := time.Now().UTC()
	if u.LockedUntil.Valid && u.LockedUntil.Time.After(now) {
		return fmt.Errorf("account locked until %s", formatTime(u.LockedUntil.Time))
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return a.recordFailedLogin(u, now)
	}
	if u.MFAEnabled {
		code, err := a.readLine("totp code: ")
		if err != nil {
			return err
		}
		secret, err := a.decryptUserMFASecret(u)
		if err != nil {
			return err
		}
		if !totp.Validate(code, secret) {
			return a.recordFailedLogin(u, now)
		}
	}

	if _, err := a.db.Exec(`UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`, now, u.ID); err != nil {
		return err
	}
	a.session = &session{userID: u.ID, username: u.Username, expiresAt: time.Now().Add(a.cfg.sessionTimeout)}
	fmt.Println("Login successful.")
	return a.showCurrentUser()
}
