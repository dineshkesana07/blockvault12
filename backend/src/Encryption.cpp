#include "Encryption.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace {
    struct SodiumInitializer {
        SodiumInitializer() {
            if (sodium_init() < 0) {
                std::cerr << "[Encryption Fatal] libsodium initialization failed!" << std::endl;
            }
        }
    };
    static SodiumInitializer g_sodiumInit;
}

// ==========================================
// SecureKey Implementation
// ==========================================

SecureKey::SecureKey() {
    sodium_memzero(m_key, sizeof(m_key));
    m_valid = false;
}

SecureKey::SecureKey(const unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    std::memcpy(m_key, key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    m_valid = true;
}

SecureKey::~SecureKey() {
    // Guarantees zeroing out sensitive key material from RAM when object goes out of scope
    sodium_memzero(m_key, sizeof(m_key));
    m_valid = false;
}

SecureKey::SecureKey(SecureKey&& other) noexcept {
    std::memcpy(m_key, other.m_key, sizeof(m_key));
    m_valid = other.m_valid;
    sodium_memzero(other.m_key, sizeof(other.m_key));
    other.m_valid = false;
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
    if (this != &other) {
        sodium_memzero(m_key, sizeof(m_key));
        std::memcpy(m_key, other.m_key, sizeof(m_key));
        m_valid = other.m_valid;
        sodium_memzero(other.m_key, sizeof(other.m_key));
        other.m_valid = false;
    }
    return *this;
}

// ==========================================
// Hex Conversion Utilities
// ==========================================

std::string Encryption::toHex(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<unsigned char> Encryption::fromHex(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    if (hexStr.length() % 2 != 0) {
        return bytes;
    }
    bytes.reserve(hexStr.length() / 2);

    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteString = hexStr.substr(i, 2);
        char* endPtr = nullptr;
        unsigned long byteVal = std::strtoul(byteString.c_str(), &endPtr, 16);
        if (*endPtr != '\0') {
            bytes.clear();
            return bytes;
        }
        bytes.push_back(static_cast<unsigned char>(byteVal));
    }
    return bytes;
}

void Encryption::wipeString(std::string& str) {
    if (!str.empty()) {
        sodium_memzero(&str[0], str.size());
        str.clear();
    }
}

// ==========================================
// Salt and Nonce Generation
// ==========================================

std::string Encryption::generateSaltHex() {
    unsigned char salt[crypto_pwhash_SALTBYTES]; // 16 bytes
    randombytes_buf(salt, sizeof(salt));
    std::string hexSalt = toHex(salt, sizeof(salt));
    sodium_memzero(salt, sizeof(salt));
    return hexSalt;
}

std::vector<unsigned char> Encryption::generateNonce() {
    // XChaCha20 uses a 192-bit (24-byte) nonce
    std::vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

// ==========================================
// Key Derivation (Argon2id)
// ==========================================

SecureKey Encryption::deriveVaultKey(const std::string& masterPassword, const std::string& saltHex) {
    std::vector<unsigned char> saltBytes = fromHex(saltHex);
    if (saltBytes.size() != crypto_pwhash_SALTBYTES) {
        std::cerr << "[Encryption Error] Invalid salt size for key derivation." << std::endl;
        return SecureKey();
    }

    unsigned char derivedKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]; // 32 bytes (256-bit)

    // Derive 256-bit symmetric encryption key using Argon2id
    int res = crypto_pwhash(
        derivedKey,
        sizeof(derivedKey),
        masterPassword.c_str(),
        masterPassword.length(),
        saltBytes.data(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (res != 0) {
        std::cerr << "[Encryption Error] Key derivation failed." << std::endl;
        sodium_memzero(derivedKey, sizeof(derivedKey));
        return SecureKey();
    }

    SecureKey key(derivedKey);
    // Zero stack memory immediately after passing into RAII wrapper
    sodium_memzero(derivedKey, sizeof(derivedKey));
    return key;
}

// ==========================================
// Authenticated Encryption (XChaCha20-Poly1305)
// ==========================================

std::optional<EncryptedPayload> Encryption::encrypt(
    const std::string& plaintext,
    const SecureKey& key,
    const std::string& additionalData
) {
    if (!key.isValid()) {
        std::cerr << "[Encryption Error] Cannot encrypt with invalid key." << std::endl;
        return std::nullopt;
    }

    // 1. Generate unique 192-bit random nonce
    std::vector<unsigned char> nonce = generateNonce();

    // 2. Allocate buffer for ciphertext + Poly1305 MAC tag (16 bytes tag overhead)
    size_t ciphertextLen = plaintext.length() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<unsigned char> ciphertext(ciphertextLen);
    unsigned long long actualCiphertextLen = 0;

    // 3. Perform authenticated encryption
    int res = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &actualCiphertextLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.length(),
        additionalData.empty() ? nullptr : reinterpret_cast<const unsigned char*>(additionalData.data()),
        additionalData.length(),
        nullptr, // nsec parameter is not used by libsodium
        nonce.data(),
        key.data()
    );

    if (res != 0) {
        std::cerr << "[Encryption Error] crypto_aead_xchacha20poly1305_ietf_encrypt failed." << std::endl;
        return std::nullopt;
    }

    EncryptedPayload payload;
    payload.ciphertext_hex = toHex(ciphertext.data(), actualCiphertextLen);
    payload.nonce_hex = toHex(nonce.data(), nonce.size());

    // Wipe memory
    sodium_memzero(ciphertext.data(), ciphertext.size());
    sodium_memzero(nonce.data(), nonce.size());

    return payload;
}

// ==========================================
// Authenticated Decryption (XChaCha20-Poly1305)
// ==========================================

std::optional<std::string> Encryption::decrypt(
    const std::string& ciphertextHex,
    const std::string& nonceHex,
    const SecureKey& key,
    const std::string& additionalData
) {
    if (!key.isValid()) {
        std::cerr << "[Encryption Error] Cannot decrypt with invalid key." << std::endl;
        return std::nullopt;
    }

    std::vector<unsigned char> ciphertext = fromHex(ciphertextHex);
    std::vector<unsigned char> nonce = fromHex(nonceHex);

    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        std::cerr << "[Encryption Error] Invalid nonce length: expected 24 bytes." << std::endl;
        return std::nullopt;
    }

    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        std::cerr << "[Encryption Error] Ciphertext too short to contain Poly1305 tag." << std::endl;
        return std::nullopt;
    }

    size_t decryptedMaxLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<unsigned char> decrypted(decryptedMaxLen);
    unsigned long long actualDecryptedLen = 0;

    // Decrypt and verify Poly1305 authentication tag
    int res = crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted.data(),
        &actualDecryptedLen,
        nullptr, // nsec not used
        ciphertext.data(),
        ciphertext.size(),
        additionalData.empty() ? nullptr : reinterpret_cast<const unsigned char*>(additionalData.data()),
        additionalData.length(),
        nonce.data(),
        key.data()
    );

    if (res != 0) {
        // Authentication failed: MAC tag mismatch, data corrupted, or wrong key used
        std::cerr << "[Encryption Error] Authentication failed: invalid key or corrupted ciphertext." << std::endl;
        sodium_memzero(decrypted.data(), decrypted.size());
        return std::nullopt;
    }

    std::string plaintext(reinterpret_cast<char*>(decrypted.data()), actualDecryptedLen);
    // Wipe buffer from memory
    sodium_memzero(decrypted.data(), decrypted.size());

    return plaintext;
}

