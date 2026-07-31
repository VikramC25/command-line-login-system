# Secure Command-Line Login System

Interactive Go CLI with registration, bcrypt password hashing, login, optional Google Authenticator-compatible TOTP MFA, account lockout, session timeout, and SQLite persistence.

## Run Locally

```powershell
go mod tidy
go run ./cmd/auth-cli
```

## Run In Docker

This project stores SQLite data in a Docker named volume so users persist across container restarts.
The Docker image uses current patch-level Go and Alpine base images. Rebuild it regularly to receive base-image security updates.

```powershell
docker build -t command-line-login-system .
docker run --rm -it -v auth-cli-data:/data command-line-login-system
```

If your Docker installation includes Compose:

```powershell
docker compose run --rm auth-cli
```

## Commands

Before login:

- `register`
- `login`
- `help`
- `exit`

After login:

- `whoami`
- `enable-2fa`
- `disable-2fa`
- `logout`
- `help`
- `exit`

`enable-2fa` displays a terminal QR code that can be scanned by an authenticator app. A manual secret is also shown as a fallback.

## Configuration

Environment variables:

- `DB_PATH` defaults to `./data/auth.db` locally and `/data/auth.db` in Docker.
- `SESSION_TIMEOUT` defaults to `30m`.
- `MAX_FAILED_ATTEMPTS` defaults to `5`.
- `LOCKOUT_DURATION` defaults to `15m`.
- `BCRYPT_COST` defaults to Go's bcrypt default cost.
- `MFA_ENCRYPTION_KEY` is an optional base64-encoded 32-byte AES-256 key. It is required before MFA can be enabled and whenever the database contains an MFA-enabled user. Keep this value outside the SQLite volume and do not commit it.

Generate a key before enabling MFA:

```powershell
$mfaKeyBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($mfaKeyBytes)
[Convert]::ToBase64String($mfaKeyBytes)
```

Set the command output as `MFA_ENCRYPTION_KEY` in the environment that runs the CLI or container. Existing plaintext MFA secrets are encrypted automatically on the next startup when this key is provided.
