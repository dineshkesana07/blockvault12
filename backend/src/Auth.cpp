#include "Auth.h"
#include "Encryption.h"
#include "OtpEmail.h"
#include <sodium.h>
#include <regex>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cctype>
#include <cstdlib>
#include <ctime>
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

    struct SensitiveStringWiper {
        std::string& value;
        ~SensitiveStringWiper() {
            Encryption::wipeString(value);
        }
    };

    std::string normalizeEmail(const std::string& email) {
        std::string normalized = email;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
            [](unsigned char character) {
                return static_cast<char>(std::tolower(character));
            });
        return normalized;
    }

    std::string trimWhitespace(const std::string& value) {
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return {};
        const auto last = value.find_last_not_of(" \t\r\n");
        return value.substr(first, last - first + 1);
    }

    bool getOtpHash(const std::string& email, const std::string& otp,
                    std::string& hash) {
        const char* configuredSecret = std::getenv("OTP_HASH_SECRET");
        if (!configuredSecret || std::char_traits<char>::length(configuredSecret) < 32) {
            return false;
        }

        unsigned char key[crypto_generichash_KEYBYTES];
        unsigned char digest[crypto_generichash_BYTES];
        const size_t secretLength = std::char_traits<char>::length(configuredSecret);
        if (crypto_generichash(key, sizeof(key),
                reinterpret_cast<const unsigned char*>(configuredSecret),
                secretLength, nullptr, 0) != 0) {
            sodium_memzero(key, sizeof(key));
            return false;
        }

        std::string input = email + '\0' + otp;
        const int result = crypto_generichash(
            digest, sizeof(digest),
            reinterpret_cast<const unsigned char*>(input.data()), input.size(),
            key, sizeof(key));
        Encryption::wipeString(input);
        sodium_memzero(key, sizeof(key));
        if (result != 0) {
            sodium_memzero(digest, sizeof(digest));
            return false;
        }

        hash = Encryption::toHex(digest, sizeof(digest));
        sodium_memzero(digest, sizeof(digest));
        return !hash.empty();
    }

    std::string generateOtp() {
        const unsigned int code = randombytes_uniform(1000000);
        std::ostringstream stream;
        stream << std::setw(6) << std::setfill('0') << code;
        return stream.str();
    }

    int64_t currentTimestamp() {
        return static_cast<int64_t>(std::time(nullptr));
    }
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

OtpFlowResult Auth::beginRegistration(const std::string& submittedName,
                                      const std::string& submittedEmail,
                                      const std::string& masterPassword) {
    OtpFlowResult result;
    const std::string name = trimWhitespace(submittedName);
    const std::string email = normalizeEmail(submittedEmail);

    if (name.empty() || name.size() > 100) {
        result.status = OtpFlowStatus::Invalid;
        result.message = "Name must be between 1 and 100 characters.";
        return result;
    }
    if (!isValidEmail(email)) {
        result.status = OtpFlowStatus::Invalid;
        result.message = "Invalid email format.";
        return result;
    }
    std::string passwordReason;
    if (!isValidPassword(masterPassword, passwordReason)) {
        result.status = OtpFlowStatus::Invalid;
        result.message = passwordReason;
        return result;
    }
    if (!m_db) {
        result.status = OtpFlowStatus::Error;
        result.message = "Database is not connected.";
        return result;
    }
    if (!OtpEmail::isConfigured()) {
        result.status = OtpFlowStatus::ConfigurationError;
        result.message = "Email verification is not configured. Set EMAIL_SERVICE_URL and EMAIL_SERVICE_TOKEN on the backend.";
        return result;
    }

    std::string otpHash;
    if (!getOtpHash(email, "configuration-check", otpHash)) {
        std::cerr << "[OTP email] OTP_HASH_SECRET is missing or shorter than "
                     "32 bytes; its value is not logged."
                  << std::endl;
        result.status = OtpFlowStatus::ConfigurationError;
        result.message = "Email verification is not configured. Set OTP_HASH_SECRET to a secret value of at least 32 characters on the backend.";
        return result;
    }

    const auto existingUser = m_db->getUserByEmail(email);
    if (existingUser.has_value()) {
        result.status = OtpFlowStatus::Accepted;
        result.message = "If this email can be registered, a verification code has been submitted for delivery.";
        result.retry_after_seconds = 60;
        return result;
    }

    const std::string vaultSalt = Encryption::generateSaltHex();
    const std::string passwordHash = hashPassword(masterPassword);
    if (vaultSalt.empty() || passwordHash.empty()) {
        result.status = OtpFlowStatus::Error;
        result.message = "Could not securely prepare the registration. Please try again.";
        return result;
    }

    std::string otp = generateOtp();
    SensitiveStringWiper otpWiper{otp};
    if (!getOtpHash(email, otp, otpHash)) {
        result.status = OtpFlowStatus::Error;
        result.message = "Could not securely prepare email verification.";
        return result;
    }

    const int64_t now = currentTimestamp();
    const PendingSignupCreateStatus createStatus = m_db->createPendingSignup(
        name, email, passwordHash, vaultSalt, otpHash, now + 300, now);
    if (createStatus == PendingSignupCreateStatus::Error) {
        result.status = OtpFlowStatus::Error;
        result.message = "Could not start registration. Please try again.";
        return result;
    }

    result.status = OtpFlowStatus::Accepted;
    result.message = "If this email can be registered, a verification code has been submitted for delivery.";
    result.retry_after_seconds = 60;
    if (createStatus == PendingSignupCreateStatus::AlreadyRegistered) {
        return result;
    }
    if (createStatus == PendingSignupCreateStatus::AlreadyPending) {
        if (m_db->isPendingSignupOtpDeliveryConfirmed(email)) {
            return result;
        }
        result.status = OtpFlowStatus::EmailError;
        result.message =
            "The verification email was not confirmed. Please request a new code after the cooldown.";
        return result;
    }

    const bool sent = OtpEmail::sendVerificationCode(email, otp);
    if (!sent) {
        result.status = OtpFlowStatus::EmailError;
        result.message = "We could not send the verification email. Please try again later.";
        result.retry_after_seconds = 60;
        return result;
    }
    if (!m_db->confirmPendingSignupOtpDelivery(email, otpHash)) {
        std::cerr << "[OTP email] Message was accepted but delivery status could "
                     "not be confirmed in the database."
                  << std::endl;
        result.status = OtpFlowStatus::EmailError;
        result.message = "We could not complete email verification. Please request a new code.";
        result.retry_after_seconds = 60;
    }
    return result;
}

OtpFlowResult Auth::resendRegistrationOtp(const std::string& submittedEmail) {
    OtpFlowResult result;
    const std::string email = normalizeEmail(submittedEmail);
    if (!isValidEmail(email)) {
        result.status = OtpFlowStatus::Invalid;
        result.message = "Enter a valid email address.";
        return result;
    }
    if (!m_db) {
        result.status = OtpFlowStatus::Error;
        result.message = "Database is not connected.";
        return result;
    }
    if (!OtpEmail::isConfigured()) {
        result.status = OtpFlowStatus::ConfigurationError;
        result.message = "Email verification is not configured. Set EMAIL_SERVICE_URL and EMAIL_SERVICE_TOKEN on the backend.";
        return result;
    }

    std::string otp = generateOtp();
    SensitiveStringWiper otpWiper{otp};
    std::string otpHash;
    if (!getOtpHash(email, otp, otpHash)) {
        std::cerr << "[OTP email] OTP_HASH_SECRET is missing or shorter than "
                     "32 bytes; its value is not logged."
                  << std::endl;
        result.status = OtpFlowStatus::ConfigurationError;
        result.message = "Email verification is not configured. Set OTP_HASH_SECRET to a secret value of at least 32 characters on the backend.";
        return result;
    }

    const int64_t now = currentTimestamp();
    switch (m_db->refreshPendingSignupOtp(email, otpHash, now + 300, now)) {
    case OtpResendStatus::NotFound:
      result.status = OtpFlowStatus::Invalid;
      result.message = "This verification request is unavailable. Start signup again.";
      return result;
    case OtpResendStatus::Cooldown:
      result.status = OtpFlowStatus::Cooldown;
      result.message = "Please wait before requesting another code.";
      result.retry_after_seconds = 60;
      return result;
    case OtpResendStatus::RateLimited:
      result.status = OtpFlowStatus::RateLimited;
      result.message = "Too many verification emails were requested. Try again later.";
      result.retry_after_seconds = 3600;
      return result;
    case OtpResendStatus::Error:
      result.status = OtpFlowStatus::Error;
      result.message = "Could not resend the verification code. Please try again.";
      return result;
    case OtpResendStatus::Updated:
      break;
    }

    const bool sent = OtpEmail::sendVerificationCode(email, otp);
    if (!sent) {
        result.status = OtpFlowStatus::EmailError;
        result.message = "We could not send the verification email. Please try again later.";
        return result;
    }
    if (!m_db->confirmPendingSignupOtpDelivery(email, otpHash)) {
        std::cerr << "[OTP email] Message was accepted but delivery status could "
                     "not be confirmed in the database."
                  << std::endl;
        result.status = OtpFlowStatus::EmailError;
        result.message = "We could not complete email verification. Please request a new code.";
        return result;
    }
    result.status = OtpFlowStatus::Accepted;
    result.message = "If this email can be registered, a verification code has been submitted for delivery.";
    result.retry_after_seconds = 60;
    return result;
}

OtpFlowResult Auth::verifyRegistrationOtp(const std::string& submittedEmail,
                                          const std::string& otp,
                                          const std::string& masterPassword) {
    OtpFlowResult result;
    const std::string email = normalizeEmail(submittedEmail);
    if (!isValidEmail(email)) {
        result.status = OtpFlowStatus::Invalid;
        result.message = "The verification code is invalid or expired.";
        return result;
    }
    if (masterPassword.empty() || masterPassword.size() > 1024) {
        result.status = OtpFlowStatus::Invalid;
        result.message = "The verification code or password is invalid.";
        return result;
    }
    if (!m_db) {
        result.status = OtpFlowStatus::Error;
        result.message = "Database is not connected.";
        return result;
    }

    std::string otpHash;
    const std::string candidateOtp = otp.size() == 6 ? otp : "invalid";
    if (!getOtpHash(email, candidateOtp, otpHash)) {
        std::cerr << "[OTP email] OTP_HASH_SECRET is missing or shorter than "
                     "32 bytes; its value is not logged."
                  << std::endl;
        result.status = OtpFlowStatus::ConfigurationError;
        result.message = "Email verification is not configured. Set OTP_HASH_SECRET to a secret value of at least 32 characters on the backend.";
        return result;
    }

    OtpVerificationResult verification = m_db->verifyPendingSignupOtp(
        email, otpHash, currentTimestamp(), masterPassword);
    switch (verification.status) {
    case OtpVerificationStatus::Invalid:
      result.status = OtpFlowStatus::Invalid;
      result.message = "The verification code is invalid.";
      return result;
    case OtpVerificationStatus::Expired:
      result.status = OtpFlowStatus::Expired;
      result.message = "The verification code has expired. Request a new code.";
      return result;
    case OtpVerificationStatus::TooManyAttempts:
      result.status = OtpFlowStatus::TooManyAttempts;
      result.message = "Too many incorrect attempts. Request a new code.";
      return result;
    case OtpVerificationStatus::Error:
      result.status = OtpFlowStatus::Error;
      result.message = "Could not verify the code. Please try again.";
      return result;
    case OtpVerificationStatus::Verified:
      return createSessionForUser(verification.user, "Email verified.");
    }

    return result;
}

OtpFlowResult Auth::createSessionForUser(const UserRecord& user,
                                         const std::string& message) {
    OtpFlowResult result;
    const std::string token = generateSecureToken();
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        purgeExpiredSessions();
        SessionInfo session;
        session.user_id = user.id;
        session.email = user.email;
        session.token = token;
        session.expires_at =
            std::chrono::steady_clock::now() +
            std::chrono::hours(m_sessionDurationHours);
        m_sessions[token] = session;
    }

    result.status = OtpFlowStatus::Accepted;
    result.message = message;
    result.auth.success = true;
    result.auth.message = message;
    result.auth.token = token;
    result.auth.user_id = user.id;
    result.auth.name = user.name;
    result.auth.email = user.email;
    result.auth.vault_salt = user.vault_salt;
    return result;
}

AuthResult Auth::loginUser(const std::string& email, const std::string& masterPassword) {
    AuthResult res;

    if (!isValidEmail(email)) {
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
