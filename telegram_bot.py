"""
VOID Telegram helper.

This script is optional. It verifies that your bot token works and can send
a test notification. It deliberately does NOT implement password retrieval
through Telegram because bot chats are not an appropriate channel for
plaintext credentials.

Run:
    python telegram_bot.py
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
BASE_URL = os.getenv("VOID_BASE_URL", "http://127.0.0.1:5000")

if not TOKEN or not CHAT_ID:
    raise SystemExit("Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env first.")

message = (
    "🔐 VOID test notification\n\n"
    "Your Telegram integration is connected.\n"
    f"Open your vault: {BASE_URL}"
)

response = requests.post(
    f"https://api.telegram.org/bot{TOKEN}/sendMessage",
    json={"chat_id": CHAT_ID, "text": message},
    timeout=10,
)
response.raise_for_status()
print("Telegram test message sent successfully.")
