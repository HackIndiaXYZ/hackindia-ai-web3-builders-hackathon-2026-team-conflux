# hackindia-ai-web3-builders-hackathon-2026-team-conflux
Hackathon team repository for Team Conflux - [hackindia-team:hackindia-ai-web3-builders-hackathon-2026:team-conflux]

## SecureCode AI 🛡️

**Team Conflux — HackIndia AI & Web3 Builders Hackathon 2026**

SecureCode AI is a web-based code security scanner that helps developers find vulnerabilities in their source code. Upload a ZIP of your project or paste a code snippet — the platform scans for security issues, classifies them with a lightweight ML model, and generates a tamper-evident blockchain-ready proof of the assessment.

---

### What It Does

1. **Scans** your source code for common vulnerabilities using regex-based static analysis.
2. **Classifies** each finding as High / Medium / Low severity using a 9-tree Random Forest ensemble.
3. **Clusters** related findings into categories (Credential Exposure, Injection Risks, etc.).
4. **Generates** a SHA-256 Security Passport — a tamper-evident fingerprint of the report.
5. **Prepares** a blockchain-ready cryptographic proof that can be anchored to Polygon / Ethereum.

---

### Vulnerabilities Detected

| Category               | Examples                                          |
|------------------------|---------------------------------------------------|
| Hardcoded Credentials  | Passwords, API keys, secrets embedded in code     |
| SQL Injection          | Dynamically constructed SQL queries               |
| XSS / DOM Manipulation | Unsafe `innerHTML` assignments                    |
| Dangerous Functions    | Use of `eval()` in JavaScript                     |
| Insecure Transport     | HTTP URLs instead of HTTPS                        |
| Debug Mode             | `debug=True` left enabled in Python apps          |

**Supported file types:** `.html`, `.css`, `.js`, `.jsx`, `.ts`, `.tsx`, `.php`, `.py`, `.java`, `.c`, `.cpp`, `.h`, `.json`, `.xml`, `.sql`, `.env`, `.txt`

---

### Tech Stack

| Component            | Technology                                |
|----------------------|-------------------------------------------|
| Web Framework        | Flask (Python)                            |
| Database             | SQLite                                    |
| ML Classifier        | Custom Random Forest — pure Python, zero external ML dependencies |
| Cryptography         | SHA-256 via Python `hashlib`              |
| Authentication       | Werkzeug (PBKDF2 password hashing)        |
| Target Blockchain    | Polygon / Ethereum (proof-ready)          |

---

### Project Structure

```
├── app.py                 # Flask app — routes, auth, database, core logic
├── scanner.py             # Static analysis engine — regex pattern matching
├── ml_classifier.py       # Random Forest ensemble — severity classification & clustering
├── security_seal.py       # SHA-256 report seal & Security Passport generation
├── blockchain_proof.py    # Blockchain-ready cryptographic proof creation
├── templates/
│   ├── index.html         # Landing page
│   ├── page.html          # All info pages + scan results
│   ├── dashboard.html     # User dashboard with audit history
│   ├── login.html         # Login page
│   └── register.html      # Registration page
└── demo_website/          # Sample project to test the scanner
```

---

### Getting Started

#### Prerequisites

- Python 3.8+

#### Option 1 — Run with `uv` (fastest)

```bash
uv run --with Flask python app.py
```

#### Option 2 — Standard virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install Flask
python app.py
```

The SQLite database (`securecode.db`) is created automatically on first run.

Open **http://127.0.0.1:5000** in your browser.

---

## How to Use

1. **Create an account** — Register and log in to save your audit history.
2. **Upload a ZIP** — Package your project as a `.zip` file and upload it for a full scan.
3. **Or paste code** — Paste a code snippet directly and select the language.
4. **Review results** — View findings, ML classifications, vulnerability clusters, and your Security Passport.
5. **Check history** — Access all past audits from your dashboard.

---

### How the AI Pipeline Works

```
Source Code
    │
    ▼
┌─────────────────────┐
│  1. Code Seal       │  SHA-256 fingerprint for integrity
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  2. Static Scanner  │  Regex pattern matching across files
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  3. Feature Extract │  7-dim binary vector per finding
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  4. Random Forest   │  9-tree ensemble → severity + confidence
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  5. Clustering      │  Group findings by vulnerability type
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  6. Blockchain Proof│  Tamper-evident hash for verification
└─────────────────────┘
```

---

### Security & Privacy

- **No code stored** — Uploaded files are deleted immediately after scanning.
- **No code on-chain** — Only the report hash goes to the blockchain, never source code.
- **Parameterized queries** — All database operations use parameterized SQL.
- **Zip-Slip protection** — Path traversal attacks are blocked during ZIP extraction.
- **Passwords hashed** — User passwords are stored using PBKDF2 (Werkzeug).

---

### ⚠️ Disclaimer

SecureCode AI is a hackathon prototype. It uses pattern-based detection and may produce false positives or miss vulnerabilities. It does not replace professional security auditing. The blockchain proof is generated locally and is not yet submitted on-chain.

---

### License

MIT — see [LICENSE](LICENSE) for details.