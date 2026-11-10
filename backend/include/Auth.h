#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <optional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include "Database.h"
#include "GoogleOAuth.h"

/**
 * @brief Represents an active user session in memory.
 */
struct SessionInfo {
    int64_t user_id{0};
    std::string email;
    std::string token;
    std::chrono::steady_clock::time_point expires_at;
};

/**
 * @brief Represents the result of an authentication operation (registration/login).
 */
struct AuthResult {
    bool success{false};
    std::string message;
    std::string token;      // Populated on successful login/registration
    int64_t user_id{0};     // Populated on successful login/registration
    std::string name;       // User's name
    std::string email;      // User's email
    std::string vault_salt; // Stored per-user random salt (internal C++ only, never returned to frontend)
};

/**
 * @brief Handles user authentication, password hashing, and session management.
 */
class Auth {
public:
    /**
     * @brief Constructs the Auth module with a reference to the initialized Database.
     * @param db Shared pointer to the Database instance.
     * @param sessionDurationHours Duration in hours before a session token expires (default: 24h).
     */
    explicit Auth(std::shared_ptr<Database> db, int sessionDurationHours = 24);

    ~Auth() = default;

    // Prevent copy
    Auth(const Auth&) = delete;
    Auth& operator=(const Auth&) = delete;

    /**
     * @brief Creates or links a verified Google identity and unlocks its vault session.
     *
     * @param identity Identity verified by GoogleOAuth::exchangeCode, never client-supplied profile data.
     * @param masterPassword Existing vault password, or a strong password for a new vault.
     * @return AuthResult with status, session token, and stored vault salt if successful.
     */
    AuthResult loginGoogle(const GoogleIdentity& identity, const std::string& masterPassword);

    /**
     * @brief Logs out a user by invalidating their session token.
     * @param token Active session token to revoke.
     * @return true if token was found and revoked, false otherwise.
     */
    bool logoutUser(const std::string& token);

    /**
     * @brief Validates an active session token.
     * @param token The token received in HTTP Authorization headers.
     * @return std::optional<SessionInfo> if token is valid and not expired, std::nullopt otherwise.
     */
    std::optional<SessionInfo> validateToken(const std::string& token);

    /**
     * @brief Hashes a password using libsodium Argon2id (crypto_pwhash_str).
     * @param password Password to hash.
     * @return Argon2id hash string, or empty string on error.
     */
    static std::string hashPassword(const std::string& password);

    /**
     * @brief Verifies a password against an Argon2id hash in constant time (crypto_pwhash_str_verify).
     * @param password Password to test.
     * @param hash Stored Argon2id hash.
     * @return true if password matches, false otherwise.
     */
    static bool verifyPassword(const std::string& password, const std::string& hash);

    /**
     * @brief Generates a cryptographically secure random session token (hex encoded, 256-bit).
     */
    static std::string generateSecureToken();

    /**
     * @brief Validates email syntax (RFC-like format check).
     * @param email Email to validate.
     * @return true if valid format, false otherwise.
     */
    static bool isValidEmail(const std::string& email);

    /**
     * @brief Validates password complexity:
     * - At least 8 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one digit
     * - At least one special character
     *
     * @param password Password to test.
     * @param[out] outReason Description of reason if validation fails.
     * @return true if compliant, false otherwise.
     */
    static bool isValidPassword(const std::string& password, std::string& outReason);

private:
    std::shared_ptr<Database> m_db;
    int m_sessionDurationHours;

    mutable std::mutex m_sessionMutex;
    // Maps session_token -> SessionInfo
    std::unordered_map<std::string, SessionInfo> m_sessions;

    /**
     * @brief Cleans up expired sessions from the in-memory session map.
     */
    void purgeExpiredSessions();
};

#endif // AUTH_H
