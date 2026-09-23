# Secure License Server + Telegram Admin Bot

## 1. Requirements
- Node.js 18+ (20+ recommended)
- A Telegram bot token from @BotFather
- Your Telegram numeric user ID

## 2. Install
```bash
npm install
```

## 3. Configure
Copy `.env.example` to `.env` and set:
- `JWT_SECRET`
- `ADMIN_API_KEY`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ADMIN_ID`

Generate strong secrets with:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## 4. Run
```bash
npm start
```

Open:
`http://YOUR_SERVER_IP:3000`

## 5. Telegram commands

```text
/add username password 30d
/users
/info username
/extend username 7d
/enable username
/disable username
/delete username
/logs
/help
```

Password requirements:
- 8-128 characters

Duration suffixes:
- `m` = minutes
- `h` = hours
- `d` = days

## 6. Connecting an existing website

Replace its old JSONBin login request with:

```js
const response = await fetch("https://YOUR-DOMAIN/api/login", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({username, password})
});

const data = await response.json();

if (data.ok) {
  localStorage.setItem("license_session_token", data.token);
  // continue into your application
} else {
  // show data.error
}
```

For protected API calls:

```js
fetch("/api/me", {
  headers: {
    Authorization: "Bearer " + localStorage.getItem("license_session_token")
  }
});
```

## Security
Passwords are bcrypt-hashed. Plaintext passwords are not stored in SQLite.
The Telegram bot is restricted to the configured numeric Telegram user ID.
Use HTTPS in production (for example, Nginx + Let's Encrypt).
Do not commit `.env` or `data/licenses.db` to Git.
"# mytiktokpasskeeper-bot" 
