# 🔐 Secure Authentication System

<p align="center">
  <strong>A secure authentication web application built with Flask and Python.</strong>
</p>

<p align="center">
  Password security · Session protection · CSRF protection · Two-factor authentication
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask" alt="Flask">
  <img src="https://img.shields.io/badge/Database-SQLite-blue" alt="SQLite">
  <img src="https://img.shields.io/badge/Security-2FA-success" alt="2FA">
</p>

## 📸 Project Preview

![Secure Authentication System Screenshot](screenshots/secureauth-preview.png)

> Add a screenshot of your actual login page or dashboard to the `screenshots` folder.

## 🚀 About the Project

Secure Authentication System is a Flask-based web application developed to demonstrate authentication security and essential cybersecurity practices. It focuses on protecting user accounts, validating requests, managing sessions and recording authentication activity.

## ✨ Key Features

- 🔑 User authentication and login protection
- 🔒 Password hashing using Argon2id
- 🛡️ CSRF protection for forms
- ⏱️ Signed, time-limited sessions
- 🔐 Two-factor authentication (TOTP)
- 📝 Authentication audit logging
- 📊 Dashboard for security status and configuration
- 🧪 Automated tests for authentication functionality

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Application logic |
| Flask | Web framework |
| SQLite | Database |
| Argon2id | Password hashing |
| TOTP | Two-factor authentication |
| Pytest | Automated testing |
| HTML/CSS | Web interface |

## 💻 Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/deependerk789/secure-authentication-system.git
cd secure-authentication-system
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create your local `.env` file using `.env.example` as a reference. Set the required values for your application.

**Never commit your `.env` file, passwords, secret keys or production credentials.**

### 5. Start the application

Use the entry-point command configured in your project. For example, if `app.py` is the entry point:

```bash
python app.py
```

Open the local URL printed by Flask in your terminal.

### 6. Run tests

```bash
python -m pytest -q
```

## 🌐 Live Demo

**Status:** Coming soon — deployment and production database configuration are pending.

- **Live Application:** To be added after deployment.
- **Source Code:** [View on GitHub](https://github.com/deependerk789/secure-authentication-system)

## 🎯 Learning Objectives

This project demonstrates practical implementation of password security, session management, CSRF protection, multi-factor authentication and authentication testing.

## 🔮 Future Improvements

- PostgreSQL integration for production deployment
- Cloud deployment with secure environment configuration
- Additional security testing and monitoring
- Further improvements to the user interface

## 👨‍💻 Author

**Deepender Kumar**  
B.Tech Cybersecurity Student

- GitHub: [@deependerk789](https://github.com/deependerk789)
- Project: [Secure Authentication System](https://github.com/deependerk789/secure-authentication-system)

---

<p align="center">
  ⭐ If you find this project useful, consider starring the repository!
</p>
