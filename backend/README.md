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
│   ├── Auth.h                  # Google account linking and vault sessions
│   ├── GoogleOAuth.h           # Google authorization-code exchange
│   ├── Database.h              # SQLite connection, migrations, prepared statements
│   ├── Encryption.h            # Libsodium Argon2id & XChaCha20-Poly1305
│   ├── Middleware.h            # CORS middleware & Bearer token authentication
│   └── Vault.h                 # Password manager CRUD & search/filter operations
└── src/                        # Implementations
    ├── Auth.cpp
    ├── GoogleOAuth.cpp
    ├── Database.cpp
    ├── Encryption.cpp
    ├── Middleware.cpp
    ├── Vault.cpp
    └── main.cpp                # Crow HTTP server & REST route mappings
```

---

## 2. Windows 11 Build & Run Instructions

### Prerequisites
1. **MinGW-W64 / GCC 14+ or Clang** with C++17 support.
2. **CMake 3.15+** and **Ninja** (or `mingw32-make`). Windows builds fetch
   libcurl with the platform TLS backend for Google OAuth HTTPS requests.

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

### Google OAuth setup

Sign-in and signup use Google OAuth. A master password is still required to
unlock vault encryption. Existing users must use their original master password
and a Google account whose email matches their existing account on first sign-in.
After linking, accounts are identified by Google's stable subject ID, so Google
email changes do not create a second vault. No existing vault data is deleted.

1. In [Google Cloud Console](https://console.cloud.google.com/auth/clients), create
   an OAuth client with application type **Web application** and configure its
   consent screen. Add test users if the app is in testing mode.
2. Add your frontend origins under **Authorized JavaScript origins**, such as
   `http://localhost:5173` and your deployed frontend's HTTPS origin. For GIS popup
   mode, add those same origins under **Authorized redirect URIs**; the code
   exchange uses the requesting frontend origin as its redirect URI.
3. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` on the backend (Render
   Environment or local `backend/.env`). Never put the secret in frontend variables.
4. Set `VITE_GOOGLE_CLIENT_ID` to the same public client ID in the frontend
   environment. Set `VITE_API_BASE_URL` to your backend, then rebuild the frontend.
5. Set backend `FRONTEND_ORIGIN` to your exact frontend origin (comma-separated
   values are supported). Localhost ports 5173 and 5174 are allowed for development.

The browser posts the single-use authorization code with `X-Requested-With:
XMLHttpRequest`. The backend checks this header and the allowed origin, exchanges
the code at Google's token endpoint, and retrieves the verified identity from
Google's userinfo endpoint over certificate-verified HTTPS. Tokens are not stored.
See [Google's code-model guide](https://developers.google.com/identity/oauth2/web/guides/use-code-model).
Email OTP and standalone email/password login endpoints are removed.

Run backend authentication checks with `ctest --test-dir build --output-on-failure`.

---

## 3. Postman / API Testing Reference

### Endpoints Overview

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/health` | No | Server status & version check |
| **POST** | `/api/auth/google` | No | Exchange Google code, create/link account, and unlock vault |
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

#### 1. Google sign-in / signup
* **Method**: `POST`
* **URL**: `http://127.0.0.1:10000/api/auth/google`
* **Headers**: `Content-Type: application/json`, `Origin: http://localhost:5173`,
  `X-Requested-With: XMLHttpRequest`
* **Body**:
```json
{
  "code": "<fresh Google popup authorization code>",
  "master_password": "SecretP@ssw0rd!"
}
```
A successful response contains `success`, `token`, and `user` (`id`, `name`,
`email`). Google codes are single-use: failed attempts require a fresh Google
popup authorization. New vault passwords require at least 8 characters including
uppercase, lowercase, a number, and a symbol. Existing passwords remain valid.

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
