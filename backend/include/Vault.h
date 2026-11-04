#ifndef VAULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "Database.h"
#include "Encryption.h"

/**
 * @brief Plain-text credential representation returned to authorized users.
 */
struct CredentialDTO {
    int64_t id{0};
    int64_t user_id{0};
    std::string website;
    std::string website_url;
    std::string username;
    std::string password;      // Decrypted plain-text password
    std::string category;
    std::string notes;
    bool is_favorite{false};
    std::string created_at;
    std::string updated_at;
};

/**
 * @brief Request data transfer object for creating or updating a credential.
 */
struct CredentialInputDTO {
    std::string website;
    std::string website_url;
    std::string username;
    std::string password;      // Plain-text password to be encrypted
    std::string category;
    std::string notes;
    bool is_favorite{false};
};

/**
 * @brief Generic operation result returned by Vault methods.
 */
struct VaultResult {
    bool success{false};
    std::string message;
    int64_t credential_id{0};
};

/**
 * @brief Password Management Module for BLOCKVAULT.
 * Encapsulates CRUD operations, searching, filtering, and favorites.
 */
class Vault {
public:
    /**
     * @brief Constructs the Vault module.
     * @param db Shared pointer to the Database instance.
     */
    explicit Vault(std::shared_ptr<Database> db);
    ~Vault() = default;

    // Prevent copy
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    /**
     * @brief Adds a new credential to the user's vault.
     * Encrypts all sensitive fields into a single authenticated payload with XChaCha20-Poly1305.
     *
     * @param userId Authenticated user's ID.
     * @param input Credential data to save.
     * @param vaultKey The user's derived 256-bit vault key.
     * @return VaultResult with success status and newly created credential ID.
     */
    VaultResult addCredential(
        int64_t userId,
        const CredentialInputDTO& input,
        const SecureKey& vaultKey
    );

    /**
     * @brief Retrieves and decrypts all credentials for the authenticated user.
     *
     * @param userId Authenticated user's ID.
     * @param vaultKey The user's derived vault key.
     * @return Vector of decrypted CredentialDTO objects.
     */
    std::vector<CredentialDTO> getAllCredentials(
        int64_t userId,
        const SecureKey& vaultKey
    );

    /**
     * @brief Retrieves and decrypts a single credential by ID.
     * Ensures the record belongs to the requesting user.
     *
     * @param credentialId ID of the credential.
     * @param userId Authenticated user's ID.
     * @param vaultKey The user's derived vault key.
     * @return std::optional<CredentialDTO> if found, authorized, and decrypted; std::nullopt otherwise.
     */
    std::optional<CredentialDTO> getCredentialById(
        int64_t credentialId,
        int64_t userId,
        const SecureKey& vaultKey
    );

    /**
     * @brief Updates an existing credential.
     * Re-encrypts all sensitive fields with a fresh random nonce.
     *
     * @param credentialId ID of the credential to update.
     * @param userId Authenticated user's ID.
     * @param input Updated fields.
     * @param vaultKey The user's derived vault key.
     * @return VaultResult indicating success or failure reason.
     */
    VaultResult updateCredential(
        int64_t credentialId,
        int64_t userId,
        const CredentialInputDTO& input,
        const SecureKey& vaultKey
    );

    /**
     * @brief Deletes a credential from the user's vault.
     * Ensures the record belongs to the requesting user.
     *
     * @param credentialId ID of the credential.
     * @param userId Authenticated user's ID.
     * @return VaultResult indicating success or failure.
     */
    VaultResult deleteCredential(int64_t credentialId, int64_t userId);

    /**
     * @brief Searches credentials matching a query substring in the website name or username.
     * Performs in-memory filtering over securely decrypted records.
     *
     * @param userId Authenticated user's ID.
     * @param query Search query string.
     * @param vaultKey The user's derived vault key.
     * @return Filtered vector of decrypted CredentialDTOs.
     */
    std::vector<CredentialDTO> searchByWebsite(
        int64_t userId,
        const std::string& query,
        const SecureKey& vaultKey
    );

    /**
     * @brief Filters credentials by category.
     *
     * @param userId Authenticated user's ID.
     * @param category Category name to filter by.
     * @param vaultKey The user's derived vault key.
     * @return Filtered vector of decrypted CredentialDTOs.
     */
    std::vector<CredentialDTO> filterByCategory(
        int64_t userId,
        const std::string& category,
        const SecureKey& vaultKey
    );

    /**
     * @brief Toggles or sets the favorite status of a credential.
     * Updates the dedicated is_favorite database column.
     *
     * @param credentialId ID of the credential.
     * @param userId Authenticated user's ID.
     * @param isFavorite Desired favorite status.
     * @return VaultResult indicating success or failure.
     */
    VaultResult setFavorite(int64_t credentialId, int64_t userId, bool isFavorite);

private:
    std::shared_ptr<Database> m_db;

    /**
     * @brief Validates credential input fields before database operations.
     */
    bool validateInput(const CredentialInputDTO& input, std::string& outError) const;

    /**
     * @brief Decrypts a database record into a clean CredentialDTO.
     */
    std::optional<CredentialDTO> decryptRecord(
        const VaultEntryRecord& record,
        const SecureKey& vaultKey
    ) const;
};

#endif // VAULT_H
