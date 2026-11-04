#include "Auth.h"
#include "Encryption.h"
#include <sodium.h>
#include <regex>
#include <random>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cctype>

namespace {
    // Ensures sodium_init() is called safely once across the program
    struct SodiumInitializer {
        SodiumInitializer() {
            if (sodium_init() < 0) {
                std::cerr << "[Security Fatal] libsodium initialization failed!" << std::endl;
            }
        }
    };
    static SodiumInitializer g_sodiumInit;
}

Auth::Auth(std::shared_ptr<Database> db, int sessionDurationHours)
    : m_db(std::move(db)), m_sessionDurationHours(sessionDurationHours) {}

bool Auth::isValidEmail(const std::string& email) {
    if (email.empty() || email.length() > 254) {
        return false;
    }
    // RFC 5322 compatible regex for email format validation
    static const std::regex emailPattern(
        R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$)"
    );
    return std::regex_match(email, emailPattern);
}

bool Auth::isValidPassword(const std::string& password, std::string& outReason) {
    if (password.length() < 8) {
        outReason = "Password must be at least 8 characters long.";
        return false;
    }
    if (password.length() > 1024) {
        outReason = "Password is too long (maximum 1024 characters).";
        return false;
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char c : password) {
        if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
        else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
        else hasSpecial = true;
    }

    if (!hasUpper) {
        outReason = "Password must contain at least one uppercase letter.";
        return false;
    }
    if (!hasLower) {
        outReason = "Password must contain at least one lowercase letter.";
        return false;
    }
    if (!hasDigit) {
        outReason = "Password must contain at least one digit.";
        return false;
    }
    if (!hasSpecial) {
        outReason = "Password must contain at least one special character.";
        return false;
    }

    return true;
}

std::string Auth::generateSecureToken() {
    // 32 random bytes = 256 bits of cryptographic entropy
    constexpr size_t TOKEN_BYTES = 32;
    unsigned char randomBytes[TOKEN_BYTES];
    randombytes_buf(randomBytes, TOKEN_BYTES);

    // Convert to hex representation (64 characters)
    std::ostringstream oss;
    for (size_t i = 0; i < TOKEN_BYTES; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(randomBytes[i]);
    }

    // Zero out memory of temporary buffer
    sodium_memzero(randomBytes, TOKEN_BYTES);

    return oss.str();
}

std::string Auth::hashPassword(const std::string& password) {
    char hashed[crypto_pwhash_STRBYTES];

    // crypto_pwhash_str uses Argon2id with recommended memory and CPU cost parameters
    int res = crypto_pwhash_str(
        hashed,
        password.c_str(),
        password.length(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE
    );

    if (res != 0) {
        std::cerr << "[Auth Error] libsodium password hashing failed." << std::endl;
        return "";
    }

    std::string result(hashed);
    // Securely wipe stack buffer
    sodium_memzero(hashed, sizeof(hashed));
    return result;
}

bool Auth::verifyPassword(const std::string& password, const std::string& hash) {
    if (hash.empty() || password.empty()) {
        return false;
    }

    // crypto_pwhash_str_verify performs constant-time password hash verification
    int res = crypto_pwhash_str_verify(
        hash.c_str(),
        password.c_str(),
        password.length()
    );

    // Returns 0 if password is correct
    return (res == 0);
}

void Auth::purgeExpiredSessions() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = m_sessions.begin(); it != m_sessions.end(); ) {
        if (it->second.expires_at <= now) {
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

AuthResult Auth::registerUser(const std::string& name, const std::string& email, const std::string& masterPassword) {
    AuthResult res;

    // 1. Validate name
    if (name.empty() || name.length() > 100) {
        res.message = "Name must be between 1 and 100 characters.";
        return res;
    }

    // 2. Validate email syntax
    if (!isValidEmail(email)) {
        res.message = "Invalid email format.";
        return res;
    }

    // 3. Validate master password complexity
    std::string reason;
    if (!isValidPassword(masterPassword, reason)) {
        res.message = reason;
        return res;
    }

    // 4. Duplicate email check
    if (!m_db) {
        res.message = "Database is not connected.";
        return res;
    }

    auto existingUser = m_db->getUserByEmail(email);
    if (existingUser.has_value()) {
        res.message = "An account with this email already exists.";
        return res;
    }

    // 5. Generate a cryptographically secure random 16-byte salt for this user
    std::string vaultSalt = Encryption::generateSaltHex();
    if (vaultSalt.empty()) {
        res.message = "Cryptographic error while generating vault salt.";
        return res;
    }

    // 6. Hash master password using libsodium Argon2id
    std::string passwordHash = hashPassword(masterPassword);
    if (passwordHash.empty()) {
        res.message = "Internal cryptographic error while securing master password.";
        return res;
    }

    // 7. Persist user into database with their unique vault_salt
    int64_t newUserId = m_db->createUser(name, email, passwordHash, vaultSalt);
    if (newUserId <= 0) {
        res.message = "Failed to create user account in database.";
        return res;
    }

    // 8. Generate session token for immediate login
    std::string token = generateSecureToken();

    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        purgeExpiredSessions();

        SessionInfo session;
        session.user_id = newUserId;
        session.email = email;
        session.token = token;
        session.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(m_sessionDurationHours);

        m_sessions[token] = session;
    }

    res.success = true;
    res.message = "Registration successful.";
    res.token = token;
    res.user_id = newUserId;
    res.name = name;
    res.email = email;
    res.vault_salt = vaultSalt;

    return res;
}

AuthResult Auth::loginUser(const std::string& email, const std::string& masterPassword) {
    AuthResult res;

    if (!isValidEmail(email)) {
        res.message = "Invalid email or master password.";
        return res;
    }

    if (masterPassword.empty()) {
        res.message = "Invalid email or master password.";
        return res;
    }

    if (!m_db) {
        res.message = "Database is not connected.";
        return res;
    }

    // 1. Retrieve user by email
    auto userOpt = m_db->getUserByEmail(email);
    if (!userOpt.has_value()) {
        // Generic error message to prevent user enumeration attacks
        res.message = "Invalid email or master password.";
        return res;
    }

    const UserRecord& user = userOpt.value();

    // 2. Verify master password against stored Argon2id hash in constant-time
    bool match = verifyPassword(masterPassword, user.password_hash);
    if (!match) {
        res.message = "Invalid email or master password.";
        return res;
    }

    // 3. Ensure user has a valid vault_salt; if empty (legacy record), fallback to email salt
    std::string salt = user.vault_salt;
    if (salt.empty()) {
        salt = Encryption::toHex(
            reinterpret_cast<const unsigned char*>(user.email.data()),
            std::min<size_t>(user.email.size(), 16)
        );
        while (salt.length() < 32) salt += "0";
    }

    // 4. Create active session token
    std::string token = generateSecureToken();

    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        purgeExpiredSessions();

        SessionInfo session;
        session.user_id = user.id;
        session.email = user.email;
        session.token = token;
        session.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(m_sessionDurationHours);

        m_sessions[token] = session;
    }

    res.success = true;
    res.message = "Login successful.";
    res.token = token;
    res.user_id = user.id;
    res.name = user.name;
    res.email = user.email;
    res.vault_salt = salt;

    return res;
}

bool Auth::logoutUser(const std::string& token) {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    auto it = m_sessions.find(token);
    if (it != m_sessions.end()) {
        m_sessions.erase(it);
        return true;
    }
    return false;
}

std::optional<SessionInfo> Auth::validateToken(const std::string& token) {
    if (token.empty()) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(m_sessionMutex);
    auto it = m_sessions.find(token);
    if (it == m_sessions.end()) {
        return std::nullopt;
    }

    // Check expiration
    if (it->second.expires_at <= std::chrono::steady_clock::now()) {
        m_sessions.erase(it);
        return std::nullopt;
    }

    return it->second;
}
