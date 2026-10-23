# 🔐 Secure Authentication System

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=0:0f172a,100:1d4ed8&height=180&section=header&text=SecureAuth&fontSize=52&fontColor=ffffff&fontAlignY=42&desc=Secure%20Authentication%20with%20Flask&descAlignY=68&descSize=18" width="100%" alt="SecureAuth project banner"/>
</p>

<p align="center">
  A Flask-based authentication project focused on password security, protected sessions, CSRF defense and two-factor authentication.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask" alt="Flask"/>
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white" alt="SQLite"/>
  <img src="https://img.shields.io/badge/Password%20Hashing-Argon2id-success" alt="Argon2id"/>
  <img src="https://img.shields.io/badge/Authentication-TOTP-blueviolet" alt="TOTP"/>
</p>

<p align="center">
  <a href="https://github.com/deependerk789/secure-authentication-system">📂 Source Code</a>
  &nbsp; • &nbsp;
  <a href="https://github.com/deependerk789">👨‍💻 GitHub Profile</a>
</p>

---

## 📌 About the Project

**Secure Authentication System** is a web application built using Python and Flask to demonstrate secure user authentication and essential cybersecurity practices.

It focuses on password hashing, session security, CSRF protection, two-factor authentication and authentication audit logging.

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔑 Authentication | User sign-in and authentication flows |
| 🔒 Argon2id | Secure password hashing |
| 🛡️ CSRF Protection | Helps protect forms from cross-site request forgery |
| ⏱️ Session Security | Signed, time-limited sessions |
| 🔐 Two-Factor Authentication | TOTP-based verification |
| 📝 Audit Logging | Records authentication activity |
| 📊 Security Dashboard | Displays security configuration status |
| 🧪 Automated Tests | Test suite for authentication functionality |

## 🛠️ Technology Stack

<p>
  <img src="https://skillicons.dev/icons?i=python,flask,sqlite,html,css,git,github" alt="Python Flask SQLite HTML CSS Git GitHub" />
</p>

- **Language:** Python
- **Framework:** Flask
- **Database:** SQLite
- **Password hashing:** Argon2id
- **Two-factor authentication:** TOTP
- **Testing:** Pytest

## 🖼️ Project Preview

The application screenshot will be added here after uploading the actual login page or dashboard image to the repository.

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/deependerk789/secure-authentication-system.git
cd secure-authentication-system
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Use `.env.example` as a reference and configure the environment variables required by the application.

**Never upload `.env` files, passwords or production secrets to GitHub.**

### 5. Run the application

Use the entry point configured in the project. If the entry point is `app.py`, run:

```bash
python app.py
```

Open the local address displayed in the terminal.

### 6. Run tests

```bash
python -m pytest -q
```
## 🌐 Live Demo

🚀 **Status: Deployed on Render**

- **Live application:** [🔗 Open SecureAuth](https://secure-authentication-system-1.onrender.com)
- **Repository:** [Secure Authentication System](https://github.com/deependerk789/secure-authentication-system)

Try the SecureAuth application to explore secure user registration, login, password management, and two-factor authentication.


## 🎯 Learning Outcomes

This project demonstrates practical concepts related to:

- Secure password storage
- Authentication and session management
- CSRF protection
- Multi-factor authentication
- Security audit logging
- Automated testing

## 🔮 Future Improvements

- PostgreSQL integration for production
- Cloud deployment
- Improved user interface
- Additional security testing and monitoring

## 👨‍💻 Author

**Deepender Kumar**  
B.Tech Cybersecurity Student

- GitHub: [@deependerk789](https://github.com/deependerk789)
- Project: [Secure Authentication System](https://github.com/deependerk789/secure-authentication-system)

---

<p align="center">
  ⭐ If you find this project interesting, consider starring the repository!
</p>
