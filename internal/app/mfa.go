package app

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"strings"

	"github.com/pquerna/otp/totp"
)

func (a *app) decryptUserMFASecret(u user) (string, error) {
	if !u.MFASecret.Valid || u.MFASecret.String == "" {
		return "", errors.New("MFA is enabled but its secret is unavailable")
	}
	if len(a.cfg.mfaEncryptionKey) == 0 {
		return "", errors.New("MFA_ENCRYPTION_KEY is required to use MFA")
	}
	return decryptMFASecret(a.cfg.mfaEncryptionKey, u.MFASecret.String)
}

func (a *app) enable2FA() error {
	u, err := a.currentUser()
	if err != nil {
		return err
	}
	if u.MFAEnabled {
		fmt.Println("MFA is already enabled.")
		return nil
	}
	if len(a.cfg.mfaEncryptionKey) == 0 {
		return errors.New("MFA_ENCRYPTION_KEY must be configured before enabling MFA")
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "SecureCLI", AccountName: u.Username})
	if err != nil {
		return err
	}
	qrCode, err := key.Image(48, 48)
	if err != nil {
		return err
	}
	fmt.Println("Scan this QR code with Google Authenticator or another TOTP app:")
	printQRCode(qrCode)
	fmt.Println("If scanning is unavailable, enter this secret manually:")
	fmt.Println("  Secret:", key.Secret())
	code, err := a.readLine("enter current totp code to confirm: ")
	if err != nil {
		return err
	}
	if !totp.Validate(strings.TrimSpace(code), key.Secret()) {
		return errors.New("invalid TOTP code; MFA was not enabled")
	}

	encryptedSecret, err := encryptMFASecret(a.cfg.mfaEncryptionKey, key.Secret())
	if err != nil {
		return err
	}
	if _, err := a.db.Exec(`UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?`, encryptedSecret, u.ID); err != nil {
		return err
	}
	fmt.Println("MFA enabled.")
	return nil
}

func printQRCode(qrCode image.Image) {
	bounds := qrCode.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y += 2 {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			top := isDark(qrCode.At(x, y))
			bottom := y+1 < bounds.Max.Y && isDark(qrCode.At(x, y+1))
			switch {
			case top && bottom:
				fmt.Print("█")
			case top:
				fmt.Print("▀")
			case bottom:
				fmt.Print("▄")
			default:
				fmt.Print(" ")
			}
		}
		fmt.Println()
	}
}

func isDark(pixelColor color.Color) bool {
	red, green, blue, _ := pixelColor.RGBA()
	return red+green+blue < 3*0x8000
}

func (a *app) disable2FA() error {
	u, err := a.currentUser()
	if err != nil {
		return err
	}
	if !u.MFAEnabled {
		fmt.Println("MFA is already disabled.")
		return nil
	}
	code, err := a.readLine("totp code: ")
	if err != nil {
		return err
	}
	secret, err := a.decryptUserMFASecret(u)
	if err != nil {
		return err
	}
	if !totp.Validate(strings.TrimSpace(code), secret) {
		return errors.New("invalid TOTP code; MFA remains enabled")
	}
	if _, err := a.db.Exec(`UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?`, u.ID); err != nil {
		return err
	}
	fmt.Println("MFA disabled.")
	return nil
}
