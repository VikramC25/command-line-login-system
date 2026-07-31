package app

import (
	"database/sql"
	"time"

	"github.com/chzyer/readline"
)

type config struct {
	dbPath            string
	sessionTimeout    time.Duration
	maxFailedAttempts int
	lockoutDuration   time.Duration
	bcryptCost        int
	mfaEncryptionKey  []byte
}

type app struct {
	db      *sql.DB
	rl      *readline.Instance
	cfg     config
	session *session
}

type session struct {
	userID    int64
	username  string
	expiresAt time.Time
}

type user struct {
	ID             int64
	Username       string
	PasswordHash   string
	RegisteredAt   time.Time
	LastLoginAt    sql.NullTime
	MFAEnabled     bool
	MFASecret      sql.NullString
	FailedAttempts int
	LockedUntil    sql.NullTime
}
