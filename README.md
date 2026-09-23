# VOID — Personal Credential Vault

VOID is a security-first personal credential vault MVP. Paste messy credential text, let the parser organize it into website/username/password fields, encrypt the credential before storing it, and access the vault through one master password.

## Features

- Single master-password login
- Verification question for the recovery flow
- Messy credential parser
- Encrypted credential storage with Fernet
- Search, reveal, copy, edit, delete
- Automatic session timeout
- SQLite database
- Optional Telegram notification integration
- No Supabase required

## Important security note

This is an MVP/reference implementation, not a professionally audited password manager. Do not use it as your only password store for critical accounts until it has undergone security review.

Telegram bots are not a suitable place to transmit plaintext passwords. VOID's Telegram integration is intentionally limited to notifications and a link back to the web vault.

## Local setup

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env
python app.py
```

Open http://127.0.0.1:5000

## Telegram

See `TELEGRAM_SETUP.md`.

## Production

Set a strong `VOID_SECRET_KEY`, use HTTPS, disable debug mode, and put the database/encryption key in protected server-side storage. Never commit `.env`, `vault.db`, or `instance/`.
