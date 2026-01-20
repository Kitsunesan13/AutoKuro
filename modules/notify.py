import requests
from rich.console import Console

console = Console()

def send_telegram(message, config):
    if not config.get('enabled', False):
        return

    bot_token = config.get('bot_token')
    chat_id = config.get('chat_id')

    if not bot_token or not chat_id or "YOUR_BOT" in bot_token:
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        console.print(f"[red][!] Failed to send Telegram alert: {e}[/red]")