package app

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

func (a *app) loop() {
	for {
		a.refreshPrompt()
		line, err := a.rl.Readline()
		if errors.Is(err, readline.ErrInterrupt) && strings.TrimSpace(line) == "" {
			fmt.Println("Use exit to quit.")
			continue
		}
		if errors.Is(err, io.EOF) {
			fmt.Println()
			return
		}
		if err != nil {
			fmt.Println("Input error:", err)
			continue
		}

		args := strings.Fields(strings.TrimSpace(line))
		if len(args) == 0 {
			continue
		}
		if args[0] == "exit" {
			return
		}
		if err := a.dispatch(args); err != nil {
			fmt.Println("Error:", err)
		}
	}
}

func (a *app) refreshPrompt() {
	if a.session != nil && time.Now().After(a.session.expiresAt) {
		fmt.Println("Session expired. Please login again.")
		a.session = nil
	}
	if a.session == nil {
		a.rl.SetPrompt("auth> ")
		return
	}
	a.rl.SetPrompt(a.session.username + "> ")
}

func (a *app) dispatch(args []string) error {
	command := args[0]
	if command == "help" {
		a.help()
		return nil
	}
	if a.session == nil {
		switch command {
		case "register":
			return a.register()
		case "login":
			return a.login()
		default:
			return errors.New("please login first; available commands: register, login, help, exit")
		}
	}
	if time.Now().After(a.session.expiresAt) {
		a.session = nil
		return errors.New("session expired; please login again")
	}

	switch command {
	case "whoami":
		return a.showCurrentUser()
	case "enable-2fa":
		return a.enable2FA()
	case "disable-2fa":
		return a.disable2FA()
	case "logout":
		a.session = nil
		fmt.Println("Logged out.")
		return nil
	default:
		return errors.New("unknown command after login; available commands: whoami, enable-2fa, disable-2fa, logout, help, exit")
	}
}

func (a *app) help() {
	if a.session == nil {
		fmt.Println("Available commands: register, login, help, exit")
		return
	}
	fmt.Println("Available commands: whoami, enable-2fa, disable-2fa, logout, help, exit")
}

func (a *app) showCurrentUser() error {
	u, err := a.currentUser()
	if err != nil {
		return err
	}
	fmt.Println("User details:")
	fmt.Println("  Username:", u.Username)
	fmt.Println("  Registration date:", formatTime(u.RegisteredAt))
	if u.MFAEnabled {
		fmt.Println("  MFA status: enabled")
	} else {
		fmt.Println("  MFA status: disabled")
	}
	fmt.Println("  Session expires:", formatTime(a.session.expiresAt))
	if u.LastLoginAt.Valid {
		fmt.Println("  Last login:", formatTime(u.LastLoginAt.Time))
	} else {
		fmt.Println("  Last login: unavailable")
	}
	return nil
}

func (a *app) readLine(prompt string) (string, error) {
	previous := a.rl.Config.Prompt
	a.rl.SetPrompt(prompt)
	defer a.rl.SetPrompt(previous)
	line, err := a.rl.Readline()
	return strings.TrimSpace(line), err
}

func (a *app) readPassword(prompt string) (string, error) {
	password, err := a.rl.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func formatTime(value time.Time) string {
	return value.Local().Format("2006-01-02 15:04:05 MST")
}
