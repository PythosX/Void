# Telegram Integration — Step by Step

VOID uses Telegram only for notifications. It does not send or expose saved passwords through Telegram.

## 1. Create a Telegram bot

1. Open Telegram.
2. Search for `@BotFather`.
3. Start a chat.
4. Send `/newbot`.
5. Choose a display name, for example `VOID Vault`.
6. Choose a username ending in `bot`, for example `void_vault_demo_bot`.
7. BotFather returns a bot token.
8. Copy the token into `.env` as `TELEGRAM_BOT_TOKEN`.

Never publish the token in GitHub.

## 2. Start your VOID app

Run:

```bash
python app.py
```

Keep the terminal open.

## 3. Start a chat with your bot

1. Open the bot username in Telegram.
2. Press Start.
3. Send any message such as `hello`.

## 4. Find your Telegram chat ID

For a simple personal bot, open this URL in your browser after replacing TOKEN with your token:

`https://api.telegram.org/botTOKEN/getUpdates`

Find:

```json
"chat": {
  "id": 123456789
}
```

Copy that number.

Do not publish the URL or token.

## 5. Add the values to `.env`

Example:

```env
VOID_SECRET_KEY=your_long_flask_secret
VOID_FERNET_KEY=your_persistent_fernet_key
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
VOID_BASE_URL=http://127.0.0.1:5000
SESSION_MINUTES=15
```

### Generate a persistent Fernet key

Run:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the output to `VOID_FERNET_KEY`.

Keep this key safe. If you lose it, encrypted credential data cannot be decrypted.

## 6. Test Telegram

Run:

```bash
python telegram_bot.py
```

You should receive a test message.

## 7. Test the full flow

1. Open VOID.
2. Unlock the vault.
3. Add a credential.
4. Save it.
5. VOID sends a Telegram notification saying a credential was added.
6. Open the web vault to view the password.

## Why passwords are not sent through Telegram

A Telegram bot is a third-party communication channel. Sending your saved passwords there would create another copy of your secrets and increase the attack surface.

For a future browser-extension/mobile implementation, use Telegram for alerts rather than credential transport.

## Production checklist

Before deploying:

- Use HTTPS.
- Store secrets in platform environment variables.
- Never commit `.env`.
- Use a persistent database volume.
- Back up the encryption key separately.
- Add rate limiting.
- Add CSRF protection.
- Add login attempt throttling.
- Add audit logging without recording passwords.
- Consider WebAuthn/passkeys for the master login.
- Get a security review before using it for important real credentials.
