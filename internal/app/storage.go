package app

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func initDB(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		return err
	}
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	registered_at DATETIME NOT NULL,
	last_login_at DATETIME,
	mfa_enabled INTEGER NOT NULL DEFAULT 0,
	mfa_secret TEXT,
	failed_attempts INTEGER NOT NULL DEFAULT 0,
	locked_until DATETIME
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`)
	return err
}

func (a *app) findUser(username string) (user, error) {
	return a.queryUser(`WHERE username = ?`, username)
}

func (a *app) currentUser() (user, error) {
	if a.session == nil {
		return user{}, errors.New("not logged in")
	}
	return a.queryUser(`WHERE id = ?`, a.session.userID)
}

func (a *app) queryUser(where string, value any) (user, error) {
	var u user
	var mfaEnabled int
	err := a.db.QueryRow(`
SELECT id, username, password_hash, registered_at, last_login_at, mfa_enabled, mfa_secret, failed_attempts, locked_until
FROM users `+where, value).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.RegisteredAt, &u.LastLoginAt,
		&mfaEnabled, &u.MFASecret, &u.FailedAttempts, &u.LockedUntil,
	)
	u.MFAEnabled = mfaEnabled == 1
	return u, err
}

func (a *app) recordFailedLogin(u user, now time.Time) error {
	attempts := u.FailedAttempts + 1
	var lockedUntil any
	message := "invalid username or password"
	if attempts >= a.cfg.maxFailedAttempts {
		until := now.Add(a.cfg.lockoutDuration)
		lockedUntil = until
		attempts = 0
		message = fmt.Sprintf("invalid credentials; account locked until %s", formatTime(until))
	}
	if _, err := a.db.Exec(`UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`, attempts, lockedUntil, u.ID); err != nil {
		return err
	}
	return errors.New(message)
}
