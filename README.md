# Crypto Multitool (static)

Opens from `index.html`. All libraries are bundled locally into `dist/bundle.js` (no CDN).

## Build

1) Install dependencies:

```bash
npm install
```

2) Build:

```bash
npm run build
```

Then open `index.html` (double-click) or upload it to a server together with `styles.css` and the `dist/` folder.

## Deploy to GitHub Pages

### Simplest: commit `dist/`

1) Build locally:

```bash
npm install
npm run build
```

2) Commit and push (make sure `dist/bundle.js` exists in the repo)
3) In GitHub repo settings → **Pages**:
   - **Build and deployment**: “Deploy from a branch”
   - **Branch**: `main` (or your default)
   - **Folder**: `/ (root)`

This works because `index.html` references `./dist/bundle.js` with a relative path.

Notes:
- If you change output location, ensure `index.html` still points to the correct JS bundle path.
- For better security, consider running it offline; never paste real mnemonics into untrusted environments.

## Features

- BIP39 mnemonic → addresses/keys for BTC, ETH, LTC, DOGE, XRP
- BIP39 passphrase (optional)
- Custom derivation paths (supports `{index}` template)
- For BTC-like coins: P2PKH **compressed/uncompressed**
- Brain Wallet: SHA-256(string) → private key → addresses

