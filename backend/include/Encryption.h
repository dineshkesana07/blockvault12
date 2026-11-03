#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <sodium.h>

/**
 * @brief Represents the output of an authenticated encryption operation.
 * Both ciphertext and nonce are encoded in hex or base64 for safe transport and storage.
 */
struct EncryptedPayload {
    std::string ciphertext_hex; // Hex-encoded ciphertext with poly1305 authentication tag
    std::string nonce_hex;      // Hex-encoded 192-bit unique random nonce (24 bytes)
};

/**
 * @brief Secure RAII wrapper for a 256-bit symmetric key.
 * Automatically zeroes out sensitive key material from memory when destroyed.
 */
class SecureKey {
public:
    SecureKey();
    explicit SecureKey(const unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]);
    ~SecureKey();

    // Prevent copies so key is not duplicated in RAM
    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    // Move semantics allowed
    SecureKey(SecureKey&& other) noexcept;
    SecureKey& operator=(SecureKey&& other) noexcept;

    const unsigned char* data() const { return m_key; }
    unsigned char* data() { return m_key; }
    static constexpr size_t size() { return crypto_aead_xchacha20poly1305_ietf_KEYBYTES; }
    bool isValid() const { return m_valid; }

private:
    unsigned char m_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    bool m_valid{false};
};

/**
 * @brief Handles cryptographic key derivation and authenticated encryption for BlockVault.
 */
class Encryption {
public:
    /**
     * @brief Generates a cryptographically secure random 16-byte salt (for Argon2id key derivation).
     * @return Hex-encoded salt string (32 characters).
     */
    static std::string generateSaltHex();

    /**
     * @brief Generates a cryptographically secure 192-bit (24-byte) random nonce for XChaCha20.
     * @return Raw 24-byte vector.
     */
    static std::vector<unsigned char> generateNonce();

    /**
     * @brief Derives a 256-bit vault encryption key from a master password and salt using Argon2id.
     * 
     * Key Hierarchy Principle:
     * - This key is DERIVED independently of the login password hash.
     * - The key is kept ONLY in memory for the duration of the unlocked session and NEVER written to disk.
     *
     * @param masterPassword The plain-text master password.
     * @param saltHex Hex-encoded salt (16 bytes).
     * @return SecureKey object containing the derived key in protected memory.
     */
    static SecureKey deriveVaultKey(const std::string& masterPassword, const std::string& saltHex);

    /**
     * @brief Encrypts plain-text data using XChaCha20-Poly1305 with a random 24-byte nonce.
     * 
     * @param plaintext Data to encrypt (e.g. website password or sensitive notes).
     * @param key 256-bit vault encryption key derived from master password.
     * @param additionalData Optional metadata authenticated by Poly1305 (e.g. user_id string).
     * @return std::optional<EncryptedPayload> containing hex-encoded ciphertext and nonce.
     */
    static std::optional<EncryptedPayload> encrypt(
        const std::string& plaintext,
        const SecureKey& key,
        const std::string& additionalData = ""
    );

    /**
     * @brief Decrypts and authenticates ciphertext using XChaCha20-Poly1305.
     * 
     * Returns std::nullopt if:
     * - Nonce or ciphertext format is corrupted.
     * - Poly1305 MAC verification fails (tampering detection).
     * - Master key / derived key is incorrect.
     *
     * @param ciphertextHex Hex-encoded ciphertext + tag.
     * @param nonceHex Hex-encoded 24-byte nonce.
     * @param key 256-bit vault encryption key.
     * @param additionalData Optional metadata that was authenticated during encryption.
     * @return std::optional<std::string> plain-text on success, std::nullopt on authentication failure.
     */
    static std::optional<std::string> decrypt(
        const std::string& ciphertextHex,
        const std::string& nonceHex,
        const SecureKey& key,
        const std::string& additionalData = ""
    );

    /**
     * @brief Utility: Converts raw binary bytes to hexadecimal string.
     */
    static std::string toHex(const unsigned char* data, size_t length);

    /**
     * @brief Utility: Converts hexadecimal string to raw binary byte vector.
     */
    static std::vector<unsigned char> fromHex(const std::string& hexStr);

    /**
     * @brief Securely zeroes memory of a std::string buffer.
     */
    static void wipeString(std::string& str);
};

#endif // ENCRYPTION_H

