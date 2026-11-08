# BLOCKVAULT — C++ Backend Architecture & API Guide

BlockVault is a secure, local-first password manager and user authentication service built in C++17.

---

## 1. System Architecture

```
backend/
├── CMakeLists.txt              # Builds blockvault_server.exe with modern CMake
├── README.md                   # This documentation
├── database/                   # SQLite storage directory
│   └── blockvault.db           # Persistent SQLite database file
├── include/                    # Header definitions
│   ├── Auth.h                  # User registration, login, token management
│   ├── Database.h              # SQLite connection, migrations, prepared statements
│   ├── Encryption.h            # Libsodium Argon2id & XChaCha20-Poly1305
│   ├── OtpEmail.h              # HTTPS Google Apps Script verification email
│   ├── Middleware.h            # CORS middleware & Bearer token authentication
│   └── Vault.h                 # Password manager CRUD & search/filter operations
└── src/                        # Implementations
    ├── Auth.cpp
    ├── Database.cpp
    ├── OtpEmail.cpp
    ├── Encryption.cpp
    ├── Middleware.cpp
    ├── Vault.cpp
    └── main.cpp                # Crow HTTP server & REST route mappings
```

---

## 2. Windows 11 Build & Run Instructions

### Prerequisites
1. **MinGW-W64 / GCC 14+ or Clang** with C++17 support.
2. **CMake 3.15+** and **Ninja** (or `mingw32-make`). The Windows build
   downloads libcurl using CMake FetchContent; allow CMake network access.

### Build Steps
Open PowerShell in the `backend/` directory:

```powershell
# 1. Configure the build with CMake and Ninja
cmake -B build -G "Ninja"

# 2. Compile the server executable
cmake --build build
```

### Run Server
```powershell
cd build
.\blockvault_server.exe
```
The server starts on: **`http://127.0.0.1:10000`** by default.

### Email verification configuration

Set `EMAIL_SERVICE_URL`, `EMAIL_SERVICE_TOKEN`, and a persistent random
`OTP_HASH_SECRET` (at least 32 characters) in the backend environment.
`EMAIL_SERVICE_URL` must be the deployed Google Apps Script web app URL using
the `/macros/s/<deployment-id>/exec` path. The endpoint must accept a JSON POST
with `token`, `email`, and `otp`, then return JSON containing `{"success":true}`
only after `MailApp.sendEmail` succeeds. For local development, the server loads
an optional `.env` from the current directory or its backend parent; when
starting from `backend/build`, put the file at `backend/.env`. Values already
set in the process environment take precedence. For Render, add
`EMAIL_SERVICE_URL` and `EMAIL_SERVICE_TOKEN` under the service's Environment
settings; the container does not include or load the repository `.env` file.
Keep `EMAIL_SERVICE_TOKEN` on the backend and Apps Script only; never put it in
`VITE_` variables or frontend configuration. The backend sends HTTPS requests
with certificate verification, redirect following, and bounded timeouts.
OTP codes expire after five minutes, are limited to five guesses and five
messages per hour per address, and can be resent once per 60 seconds. Existing
SQLite user accounts remain active; only newly registered users need OTP
verification. An OTP remains unusable until Apps Script reports success and its
delivery status is saved; failed sends remain pending but can only be retried
through the existing resend cooldown and rate limits.

Email service failures are categorized in backend logs without logging service
tokens, addresses, message content, or OTP values. Apps Script success means
MailApp accepted the message for sending; it does not guarantee delivery to the
recipient's inbox.

---

## 3. Postman / API Testing Reference

### Endpoints Overview

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/health` | No | Server status & version check |
| **POST** | `/api/auth/signup` | No | Start registration and email a one-time code |
| **POST** | `/api/auth/verify-otp` | No | Verify code and complete registration |
| **POST** | `/api/auth/resend-otp` | No | Resend a code subject to cooldown/rate limits |
| **POST** | `/api/auth/login` | No | Authenticate user & receive session token |
| **POST** | `/api/auth/logout` | Yes (`Bearer`) | Revoke token and wipe memory keys |
| **GET** | `/api/auth/me` | Yes (`Bearer`) | Retrieve current user profile |
| **POST** | `/api/vault` | Yes (`Bearer`) | Encrypt & save new credential |
| **GET** | `/api/vault` | Yes (`Bearer`) | Retrieve and decrypt all user credentials |
| **GET** | `/api/vault/<id>` | Yes (`Bearer`) | Retrieve and decrypt single credential |
| **PUT** | `/api/vault/<id>` | Yes (`Bearer`) | Update credential (re-encrypts if password changed) |
| **DELETE** | `/api/vault/<id>` | Yes (`Bearer`) | Delete credential |
| **POST** | `/api/vault/<id>/favorite`| Yes (`Bearer`) | Toggle favorite status |

---

### Postman Examples & Expected Responses

#### 1. Start Registration
* **Method**: `POST`
* **URL**: `http://127.0.0.1:10000/api/auth/signup`
* **Headers**: `Content-Type: application/json`
* **Body** (Raw JSON):
```json
{
  "name": "Maya Rao",
  "email": "maya@proton.me",
  "master_password": "SecretP@ssw0rd!"
}
```
* **Expected Response (`202 Accepted`)** (the code is sent by email and is never returned by the API):
```json
{
  "message": "If this email can be registered, a verification code has been submitted for delivery.",
  "success": true,
  "retry_after_seconds": 60
}
```

#### 2. Verify Email
* **Method**: `POST`
* **URL**: `http://127.0.0.1:10000/api/auth/verify-otp`
* **Body**:
```json
{
  "email": "maya@proton.me",
  "otp": "123456",
  "master_password": "SecretP@ssw0rd!"
}
```
* A successful response creates the account and opens its vault session. Resend
  with `POST /api/auth/resend-otp` and `{"email":"maya@proton.me"}`.

#### 3. Login User
* **Method**: `POST`
* **URL**: `http://127.0.0.1:10000/api/auth/login`
* **Body**:
```json
{
  "email": "maya@proton.me",
  "master_password": "SecretP@ssw0rd!"
}
```
* **Expected Response (`200 OK`)**:
```json
{
  "message": "Login successful.",
  "success": true,
  "token": "4df0587386de328765474c0a1f3a9ca0a3d6e24743ecac978bc15d2d8d4839ea",
  "user": {
    "email": "maya@proton.me",
    "id": 1,
    "name": "Maya Rao"
  }
}
```

#### 4. Add Credential (Encrypted at Rest)
* **Method**: `POST`
* **URL**: `http://127.0.0.1:10000/api/vault`
* **Headers**:
  * `Content-Type: application/json`
  * `Authorization: Bearer <TOKEN>`
* **Body**:
```json
{
  "website": "GitHub",
  "website_url": "https://github.com",
  "username": "maya_dev",
  "password": "SuperStrongTokenPass123!",
  "category": "Development",
  "notes": "Personal account",
  "is_favorite": true
}
```
* **Expected Response (`201 Created`)**:
```json
{
  "credential_id": 1,
  "message": "Credential saved successfully.",
  "success": true
}
```

#### 5. Get Decrypted Vault Credentials
* **Method**: `GET`
* **URL**: `http://127.0.0.1:10000/api/vault`
* **Headers**: `Authorization: Bearer <TOKEN>`
* **Expected Response (`200 OK`)**:
```json
{
  "credentials": [
    {
      "category": "Development",
      "created_at": "2026-11-03 17:58:24",
      "id": 1,
      "is_favorite": true,
      "notes": "Personal account [FAVORITE]",
      "password": "SuperStrongTokenPass123!",
      "updated_at": "2026-11-03 17:58:24",
      "username": "maya_dev",
      "website": "GitHub",
      "website_url": "https://github.com"
    }
  ]
}
```

#### 5. Search & Filter
* By category: `GET http://127.0.0.1:10000/api/vault?category=Development`
* By search query: `GET http://127.0.0.1:10000/api/vault?search=git`

#### 6. Logout & Session Invalidation
* **Method**: `POST`
* **URL**: `http://127.0.0.1:10000/api/auth/logout`
* **Headers**: `Authorization: Bearer <TOKEN>`
* **Expected Response (`200 OK`)**:
```json
{
  "message": "Logged out successfully.",
  "success": true
}
```
* *Subsequent access using the revoked token returns `401 Unauthorized`:*
```json
{
  "error": "Unauthorized or expired session."
}
```
