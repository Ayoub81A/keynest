# 🗝️ KeyNest — Password Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Security](https://img.shields.io/badge/Crypto-AES--256--GCM-success.svg)](keynest-site/security.html)
[![Web Crypto](https://img.shields.io/badge/Web_Crypto_API-Zero--Knowledge-informational.svg)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

A secure, zero-knowledge full-stack password manager built with vanilla HTML, CSS, JavaScript, PHP, and MySQL. KeyNest stores your passwords encrypted client-side — even the database server cannot decrypt them. Built as a portfolio project demonstrating real-world security practices including browser-side AES-256-GCM encryption and PBKDF2 key derivation.

---

## ✨ Features

- **Authentication** — Register and sign in with email and password. Protected with bcrypt hashing and session fixation defense.
- **Client-Side Encryption** — All vault entries are encrypted with AES-256-GCM in the browser before transmission. The database stores only ciphertext.
- **Password Vault** — Add, edit, and delete credentials with site name, username, and password.
- **Secure Notes** — Store sensitive text like WiFi credentials, license keys, or recovery codes, fully encrypted.
- **Tags & Categorization** — Organize entries with custom tags, synchronized in real time.
- **Password Generator** — Cryptographically secure generator (Fisher-Yates shuffle) with guaranteed selection of enabled character classes (A–Z, a–z, 0–9, symbols). Available standalone and inline within the entry modal.
- **Password Strength Indicator** — Real-time visual strength scoring as you type.
- **Password Health Report** — Automated health assessment identifying weak, reused, and medium-strength passwords.
- **Trash & Restore** — Soft-delete with a 30-day auto-purge safety window and instant restoration.
- **Instant Search** — Fast, client-side filtering across entries by title, username, or note content.
- **Copy to Clipboard** — One-click username and password copying with temporary visual confirmation.
- **Import & Export** — Download vault backups as JSON or import existing JSON archives with automated schema validation.
- **Marketing & Documentation Site** — Integrated static site detailing product features and security specifications.

---

## 🔐 Security Architecture

| Layer | Implementation |
|-------|----------------|
| Password hashing | bcrypt (cost 12) via PHP `password_hash()` |
| Key derivation | PBKDF2-SHA256, 310,000 iterations (NIST recommended) |
| Vault encryption | AES-256-GCM via Web Crypto API |
| Session management | PHP server-side sessions with fixation protection (`session_regenerate_id`) |
| Cookie security | HttpOnly, SameSite=Lax, path=/ |
| Key storage | Never stored — derived in browser at login, wiped on logout |

**Encryption flow:**
1. User registers — server generates a unique random salt and stores it with the account
2. User logs in — browser derives a 256-bit encryption key from the password + salt using PBKDF2
3. Every entry is encrypted client-side with AES-256-GCM before being sent to the API
4. The server stores only ciphertext — it has no access to the encryption key
5. On logout the key is wiped from memory

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Encryption | Web Crypto API (built into all modern browsers) |
| Backend | PHP 8+ |
| Database | MySQL 5.7+ / MariaDB |
| Local Server | XAMPP (Apache + MySQL) |
| Fonts | Google Fonts (Lora + Outfit) |

No frameworks. No npm. No build tools. No external crypto libraries.

---

## 📁 Project Structure

```text
keynest/
├── index.html         # Root gateway / redirect
│
├── keynest-app/       # The vault application
│   ├── index.html     # App shell — all HTML structure
│   ├── keynest.sql    # Database schema, run once to set up
│   ├── assets/
│   │   ├── style.css  # All vault styles & responsive rules
│   │   ├── crypto.js  # AES-256-GCM + PBKDF2 encryption module
│   │   ├── api.js     # All fetch() calls to the PHP backend
│   │   └── app.js     # Full vault UI logic
│   └── api/
│       ├── db.php     # MySQL connection and shared helpers
│       ├── auth.php   # Register, login, logout, session check
│       └── entries.php# Vault entries, trash, and tags CRUD
│
└── keynest-site/      # Marketing / info site
    ├── index.html     # Home page
    ├── features.html  # Features overview
    ├── security.html  # Security architecture details
    └── style.css      # Shared marketing styles
```

---

## 🚀 Getting Started

### Prerequisites

- [XAMPP](https://www.apachefriends.org/) installed (or any Apache + MySQL + PHP stack)
- PHP 8.0 or higher
- MySQL 5.7+ or MariaDB
- A modern browser (Chrome, Firefox, Safari, Edge)

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/Ayoub81A/keynest.git
```

**2. Move to htdocs**

Copy the entire `keynest` repository directory into your XAMPP `htdocs` folder:

```text
C:\xampp\htdocs\keynest
```

**3. Start XAMPP**

Open XAMPP Control Panel and start both **Apache** and **MySQL**.

**4. Set up the database**

- Open your browser and go to `http://localhost/phpmyadmin`
- Click the **SQL** tab
- Open `keynest-app/keynest.sql` in any text editor, copy all contents, paste into the SQL box
- Click **Go**

You should see a `keynest` database appear in the left sidebar.

**5. Configure database credentials** *(if needed)*

Open `keynest-app/api/db.php` and update if your MySQL setup uses a password:

```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');   // Add your MySQL password here if you set one
define('DB_NAME', 'keynest');
```

**6. Open the app**

- **Root Gateway / Landing:** `http://localhost/keynest/`
- **Vault app:** `http://localhost/keynest/keynest-app/`
- **Info & Security site:** `http://localhost/keynest/keynest-site/`

---

## 🗺️ Roadmap

- [x] User authentication (register / login)
- [x] Client-side AES-256-GCM encryption
- [x] Password vault with full CRUD
- [x] Secure notes
- [x] Custom tags
- [x] Password generator (standalone + inline in new entry form)
- [x] Password health report
- [x] Trash & restore with 30-day auto-purge
- [x] Marketing / info site
- [x] Import / Export vault as JSON backup
- [ ] Favourite / pin entries
- [ ] Password history per entry

---

## ⚠️ Disclaimer

This project is built for learning and portfolio purposes. It runs locally on your machine. While the encryption implementation follows real-world standards, it has not been professionally audited. Do not use it as your primary password manager for critical accounts.

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

Built by Hmaidi Ayoub
- GitHub: [@Ayoub81A](https://github.com/Ayoub81A)
