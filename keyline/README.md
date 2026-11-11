# Keyline

A free, end-to-end encrypted messenger. People sign up with a username and password, are randomly given a
**10-digit key** (like a phone number), and can message each other only by that key. No email, no phone number.

Zero npm dependencies. Runs on **Node.js 22.13+** (built-in SQLite and WebCrypto).

## Run it

```bash
npm start                      # http://127.0.0.1:8787
npm test                       # 18 end-to-end tests, ~7 seconds
```

| Variable | Default | Meaning |
|---|---|---|
| `PORT`, `HOST` | `8787`, `127.0.0.1` | Where to listen |
| `DATA_DIR` | `./data` | SQLite database (ciphertext and hashes only) |
| `MSGR_PEPPER` | generated into `./secrets` | 64+ hex chars. Keyed-hash secret, see below |
| `TRUST_PROXY` | off | Set to `1` behind a reverse proxy so rate limits see real client IPs |

### Deploying

Browsers refuse WebCrypto on plain HTTP (except `localhost`), so production **must** be behind HTTPS. Caddy does it in one line:

```
chat.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Then run with `TRUST_PROXY=1 MSGR_PEPPER=$(cat /etc/keyline/pepper) npm start`. Generate the pepper once with
`openssl rand -hex 32` and keep it **off the database disk** (env var, secrets manager). A `Dockerfile` is also included
(`docker run -e MSGR_PEPPER=... -e TRUST_PROXY=1 -v keyline:/data -p 8787:8787 keyline`).

### Free: run it on your computer with a Cloudflare tunnel

This is the free option with no sign-in hurdles. Keyline runs on your computer, and Cloudflare's free quick tunnel gives it a
public HTTPS address. Nothing is installed on a server, and you don't need an account.

1. Install [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) and Node.js 22.13+.
2. From the `keyline` folder, run:
   ```bash
   bash deploy/tunnel.sh
   ```
   It starts Keyline and prints a link like `https://random-words.trycloudflare.com`. Send that link to people.
3. Press Ctrl+C to stop. Your accounts stay in `data/`, and the pepper stays in `secrets/`. Back up `secrets/pepper.key`.

Limits: the link changes each time you start it, and it works only while your computer is on and connected. Quick tunnels are
meant for trying things out, not as a permanent address. A permanent address needs a Cloudflare account and a domain.

### Always-on server (paid, or Oracle with a sign-in)

`deploy/setup.sh` installs Keyline on a fresh Ubuntu server with Node 22, Caddy (automatic HTTPS) and a systemd service.
Run it as root from the keyline folder: `sudo bash deploy/setup.sh chat.yourdomain.com`. Without a hostname it uses
`<your-ip>.sslip.io`. The pepper is saved to `/etc/keyline/env`, separate from the database. Back that file up.

## How a hacked server learns nothing

Everything secret is derived and used **in the browser**. The server only ever stores:

| Table | Contents | What an attacker gets |
|---|---|---|
| accounts | HMAC of the username, scrypt hash of a login proof, an AES-encrypted vault | No usernames, no passwords. The proof is derived (PBKDF2, 600k rounds) from the password but is not the password and cannot decrypt the vault |
| mailboxes | HMAC of the 10-digit key, two **public** keys, HMAC of a secret | No keys, no private keys |
| messages | Encrypted blob addressed to an HMAC'd mailbox id, deleted once delivered | Ciphertext only. No sender, no plaintext, fixed-size padding hides length |

There is deliberately **no link** between an account row and a mailbox row, so even with the pepper nobody can say which
username owns which key. Private keys, contacts, block list and the user's own 10-digit key live in the vault, which is
encrypted on the device with a key the server never sees. Sender identity and a signature travel *inside* the ciphertext.
The `HACKED SERVER` test in `test/e2e.test.js` dumps the whole data directory and searches it for usernames, passwords,
keys, plaintext and private keys.

**Messages:** ephemeral ECDH (P-256) per message → HKDF → AES-256-GCM, signed with the sender's ECDSA key. Safety numbers let
two people confirm nobody swapped keys; a changed key blocks sending and holds incoming mail until the user accepts it.

## Honest limits

- **Forgotten passwords can't be reset.** The vault is encrypted with a key from the password, so nobody, including the operator, can recover it.
- **A live attacker is different from a stolen disk.** Someone who controls the *running* server can see IPs and timing, and in any
  web app could serve modified JavaScript. HTTPS, the strict CSP and `no-referrer` policy limit this, but only a native or
  installable client with signed releases fully removes it.
- **One signed-in device at a time.** A mailbox is drained by one device; a new sign-in takes over and the old one is told. Conversation history is stored encrypted on the device, not on the server.
- With the pepper, an attacker could test whether a *guessed* 10-digit key exists (only 9 billion possibilities). That's why the pepper must live off the database disk.
- Text only (2000 characters per message), undelivered messages expire after 30 days, rate limits are in memory and reset on restart.

## Layout

```
server.js        entry point and config
lib/app.js       HTTP API, sessions, rate limits
lib/db.js        SQLite storage
public/          the web client (crypto.js, client.js = protocol, app.js = UI)
deploy/          tunnel.sh (run on your computer), setup.sh (server), systemd unit, Caddyfile
test/            end-to-end tests (node:test)
scripts/         optional Playwright browser smoke test
```
