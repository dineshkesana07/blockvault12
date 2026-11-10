#include "Auth.h"
#include "Encryption.h"
#include <sodium.h>
#include <regex>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cctype>
#include <algorithm>

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

AuthResult Auth::loginGoogle(const GoogleIdentity& identity, const std::string& masterPassword) {
    AuthResult res;

    if (identity.subject.empty() || identity.subject.size() > 255 ||
        !isValidEmail(identity.email)) {
        res.message = "Invalid email or master password.";
        return res;
    }

    if (masterPassword.empty() || masterPassword.size() > 1024) {
        res.message = "Invalid email or master password.";
        return res;
    }

    if (!m_db) {
        res.message = "Database is not connected.";
        return res;
    }

    auto userOpt = m_db->getUserByGoogleSubject(identity.subject);
    if (!userOpt) {
        userOpt = m_db->getUserByEmail(identity.email);
        if (userOpt) {
            // Require the old vault password before linking an existing account.
            if (!verifyPassword(masterPassword, userOpt->password_hash) ||
                !m_db->bindGoogleSubject(userOpt->id, identity.subject)) {
                res.message = "Unable to link this Google account or unlock the vault.";
                return res;
            }
        } else {
            std::string reason;
            if (!isValidPassword(masterPassword, reason)) {
                res.message = reason;
                return res;
            }
            const std::string hash = hashPassword(masterPassword);
            const std::string salt = Encryption::generateSaltHex();
            if (hash.empty() || salt.empty()) {
                res.message = "Could not prepare vault encryption.";
                return res;
            }
            const auto id = m_db->createUser(identity.name.empty() ? identity.email : identity.name,
                                             identity.email, hash, salt, identity.subject);
            if (id <= 0) {
                res.message = "Could not create your vault. Please try again.";
                return res;
            }
            userOpt = m_db->getUserById(id);
        }
    }
    if (!userOpt || !verifyPassword(masterPassword, userOpt->password_hash)) {
        res.message = "Unable to unlock your vault with this master password.";
        return res;
    }
    const UserRecord& user = *userOpt;

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
