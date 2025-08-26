
# Untitled RNG Game

A minimal full-stack RNG loot-box game with:
- Account signup/login (session-based)
- Stats & inventory
- RNG box opening with rarity weights
- Global chat (Socket.IO)
- Trades between users
- Leaderboard
- Logout

## Tech
- Node.js (Express) + SQLite (file `data.db` auto-created)
- Sessions stored via `connect-sqlite3`
- Socket.IO for chat
- Vanilla HTML/CSS/JS frontend (multi-page)

## Dev Quickstart
```bash
npm install
npm run dev
# open http://localhost:3000/welcome.html
```
**Windows (PowerShell):**
```powershell
$env:NODE_ENV="development"; node server.js
```

## File Structure
```
server.js
public/
  welcome.html
  home.html
  stats.html
  rng.html
  chat.html
  trade.html
  leaderboard.html
  css/styles.css
  js/auth.js
  js/app.js
```

## Gameplay Defaults
- New users start with **100 points**.
- Each box costs **10 points**.
- Rarity weights: common 60, uncommon 25, rare 10, epic 4, legendary 1.

## Notes
- This is intentionally simple and unopinionated. You can harden auth, add CSRF, and move to a SPA later.
- Trading UI is basic: offer items only; extend to request items by adding selectors similar to offer.
