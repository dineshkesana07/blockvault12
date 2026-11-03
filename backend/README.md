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
│   ├── Middleware.h            # CORS middleware & Bearer token authentication
│   └── Vault.h                 # Password manager CRUD & search/filter operations
└── src/                        # Implementations
    ├── Auth.cpp
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
2. **CMake 3.15+** and **Ninja** (or `mingw32-make`).

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
The server starts on: **`http://127.0.0.1:8080`**

---

## 3. Postman / API Testing Reference

### Endpoints Overview

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/health` | No | Server status & version check |
| **POST** | `/api/auth/register` | No | Register new user with Argon2id master password |
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

#### 1. Register User
* **Method**: `POST`
* **URL**: `http://127.0.0.1:8080/api/auth/register`
* **Headers**: `Content-Type: application/json`
* **Body** (Raw JSON):
```json
{
  "name": "Maya Rao",
  "email": "maya@proton.me",
  "master_password": "SecretP@ssw0rd!"
}
```
* **Expected Response (`201 Created`)**:
```json
{
  "message": "Registration successful.",
  "success": true,
  "token": "4df0587386de328765474c0a1f3a9ca0a3d6e24743ecac978bc15d2d8d4839ea",
  "user": {
    "email": "maya@proton.me",
    "id": 1,
    "name": "Maya Rao"
  }
}
```

#### 2. Login User
* **Method**: `POST`
* **URL**: `http://127.0.0.1:8080/api/auth/login`
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

#### 3. Add Credential (Encrypted at Rest)
* **Method**: `POST`
* **URL**: `http://127.0.0.1:8080/api/vault`
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

#### 4. Get Decrypted Vault Credentials
* **Method**: `GET`
* **URL**: `http://127.0.0.1:8080/api/vault`
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
* By category: `GET http://127.0.0.1:8080/api/vault?category=Development`
* By search query: `GET http://127.0.0.1:8080/api/vault?search=git`

#### 6. Logout & Session Invalidation
* **Method**: `POST`
* **URL**: `http://127.0.0.1:8080/api/auth/logout`
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

