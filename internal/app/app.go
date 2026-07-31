package app

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chzyer/readline"
	_ "modernc.org/sqlite"
)

// Run starts the interactive authentication CLI.
func Run() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.dbPath), 0750); err != nil {
		fmt.Fprintln(os.Stderr, "database directory error:", err)
		os.Exit(1)
	}

	db, err := sql.Open("sqlite", cfg.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "database error:", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		fmt.Fprintln(os.Stderr, "database initialization error:", err)
		os.Exit(1)
	}
	if err := ensureMFASecretsEncrypted(db, cfg.mfaEncryptionKey); err != nil {
		fmt.Fprintln(os.Stderr, "MFA configuration error:", err)
		os.Exit(1)
	}

	rl, err := newReadline()
	if err != nil {
		fmt.Fprintln(os.Stderr, "prompt error:", err)
		os.Exit(1)
	}
	defer rl.Close()

	a := &app{db: db, rl: rl, cfg: cfg}
	fmt.Println("Secure login CLI. Type help to see available commands.")
	a.loop()
}

func newReadline() (*readline.Instance, error) {
	return readline.NewEx(&readline.Config{
		Prompt:          "auth> ",
		HistoryFile:     filepath.Join(os.TempDir(), "auth-cli-history"),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete: readline.NewPrefixCompleter(
			readline.PcItem("register"),
			readline.PcItem("login"),
			readline.PcItem("whoami"),
			readline.PcItem("enable-2fa"),
			readline.PcItem("disable-2fa"),
			readline.PcItem("logout"),
			readline.PcItem("help"),
			readline.PcItem("exit"),
		),
	})
}
