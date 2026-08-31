/**
 * Deep links to the real WhatsApp/Telegram bots (apps/whatsapp_bot,
 * apps/telegram_bot — phase 5). No OAuth/account-linking backend exists yet
 * (that's phase 14), so "connect" here means "open a chat with the bot" —
 * the same thing a "Message us on WhatsApp" button does on any site.
 *
 * Returns null when the identifier isn't configured, rather than guessing a
 * number/handle — an unregistered bot deep link would 404 and look broken.
 */

const WHATSAPP_PREFILL = "Hi Rakshak, I'd like to check something suspicious.";

export function whatsAppChatUrl(): string | null {
  const number = process.env.NEXT_PUBLIC_WHATSAPP_NUMBER;
  if (!number) return null;
  const digits = number.replace(/[^0-9]/g, "");
  return `https://wa.me/${digits}?text=${encodeURIComponent(WHATSAPP_PREFILL)}`;
}

export function telegramBotUrl(): string | null {
  const username = process.env.NEXT_PUBLIC_TELEGRAM_BOT_USERNAME;
  if (!username) return null;
  return `https://t.me/${username.replace(/^@/, "")}`;
}
