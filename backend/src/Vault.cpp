#include "Vault.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

Vault::Vault(std::shared_ptr<Database> db)
    : m_db(std::move(db)) {}

bool Vault::validateInput(const CredentialInputDTO& input, std::string& outError) const {
    if (input.website.empty()) {
        outError = "Website name cannot be empty.";
        return false;
    }
    if (input.website.length() > 255) {
        outError = "Website name is too long (maximum 255 characters).";
        return false;
    }

    if (input.username.empty()) {
        outError = "Username or email cannot be empty.";
        return false;
    }
    if (input.username.length() > 255) {
        outError = "Username is too long (maximum 255 characters).";
        return false;
    }

    if (input.website_url.length() > 2048) {
        outError = "Website URL is too long (maximum 2048 characters).";
        return false;
    }

    if (input.password.length() > 4096) {
        outError = "Password is too long (maximum 4096 characters).";
        return false;
    }

    if (input.category.length() > 100) {
        outError = "Category is too long (maximum 100 characters).";
        return false;
    }

    if (input.notes.length() > 10000) {
        outError = "Notes is too long (maximum 10000 characters).";
        return false;
    }

    return true;
}

std::optional<CredentialDTO> Vault::decryptRecord(
    const VaultEntryRecord& record,
    const SecureKey& vaultKey
) const {
    CredentialDTO dto;
    dto.id = record.id;
    dto.user_id = record.user_id;
    dto.created_at = record.created_at;
    dto.updated_at = record.updated_at;
    dto.is_favorite = record.is_favorite;

    // Modern V2 encrypted record (all sensitive fields encrypted together)
    if (record.encryption_version >= 2 || !record.encrypted_data.empty()) {
        std::string aad = Encryption::makeAAD(record.user_id, record.encryption_version);
        auto decryptedOpt = Encryption::decrypt(
            record.encrypted_data,
            record.data_nonce,
            vaultKey,
            aad
        );

        if (!decryptedOpt.has_value()) {
            std::cerr << "[Vault Error] Authenticated decryption failed for entry ID: " << record.id << std::endl;
            return std::nullopt;
        }

        try {
            json payload = json::parse(decryptedOpt.value());
            dto.website = payload.value("website", "");
            dto.website_url = payload.value("website_url", "");
            dto.username = payload.value("username", "");
            dto.password = payload.value("password", "");
            dto.category = payload.value("category", "General");
            dto.notes = payload.value("notes", "");
        } catch (const std::exception& e) {
            std::cerr << "[Vault Error] Failed to parse decrypted JSON for entry ID " << record.id << ": " << e.what() << std::endl;
            return std::nullopt;
        }

        // Wipe decrypted buffer from memory
        Encryption::wipeString(decryptedOpt.value());
        return dto;
    }

    // Legacy V1 record (only password was encrypted)
    std::string aad = std::to_string(record.user_id);
    auto decryptedPassword = Encryption::decrypt(
        record.encrypted_password,
        record.nonce,
        vaultKey,
        aad
    );

    if (!decryptedPassword.has_value()) {
        std::cerr << "[Vault Error] Legacy decryption failed for entry ID: " << record.id << std::endl;
        return std::nullopt;
    }

    dto.website = record.website;
    dto.website_url = record.website_url;
    dto.username = record.username;
    dto.password = decryptedPassword.value();
    dto.category = record.category.empty() ? "General" : record.category;
    dto.notes = record.notes;
    // Check if legacy note had [FAVORITE] tag
    dto.is_favorite = record.is_favorite || (record.notes.find("[FAVORITE]") != std::string::npos);

    return dto;
}

VaultResult Vault::addCredential(
    int64_t userId,
    const CredentialInputDTO& input,
    const SecureKey& vaultKey
) {
    VaultResult result;

    if (!m_db) {
        result.message = "Database is not connected.";
        return result;
    }

    if (!vaultKey.isValid()) {
        result.message = "Invalid or uninitialized encryption key.";
        return result;
    }

    std::string error;
    if (!validateInput(input, error)) {
        result.message = error;
        return result;
    }

    if (input.password.empty()) {
        result.message = "Password cannot be empty.";
        return result;
    }

    // 1. Pack all sensitive fields into a single JSON payload
    json payload = {
        {"website", input.website},
        {"website_url", input.website_url},
        {"username", input.username},
        {"password", input.password},
        {"category", input.category.empty() ? "General" : input.category},
        {"notes", input.notes}
    };
    std::string payloadStr = payload.dump();

    // 2. Encrypt with XChaCha20-Poly1305 and bind to owner via AAD
    std::string aad = Encryption::makeAAD(userId, 2);
    auto encrypted = Encryption::encrypt(payloadStr, vaultKey, aad);
    Encryption::wipeString(payloadStr);

    if (!encrypted.has_value()) {
        result.message = "Cryptographic error: failed to encrypt credential payload.";
        return result;
    }

    // 3. Prepare database record
    VaultEntryRecord record;
    record.user_id = userId;
    record.encrypted_data = encrypted->ciphertext_hex;
    record.data_nonce = encrypted->nonce_hex;
    record.encryption_version = 2;
    record.is_favorite = input.is_favorite;

    // 4. Persist into SQLite
    int64_t newId = m_db->createVaultEntry(record);
    if (newId <= 0) {
        result.message = "Database error: failed to save credential.";
        return result;
    }

    result.success = true;
    result.message = "Credential saved successfully.";
    result.credential_id = newId;
    return result;
}

std::vector<CredentialDTO> Vault::getAllCredentials(
    int64_t userId,
    const SecureKey& vaultKey
) {
    std::vector<CredentialDTO> results;
    if (!m_db || !vaultKey.isValid()) {
        return results;
    }

    std::vector<VaultEntryRecord> records = m_db->getVaultEntriesByUserId(userId);
    results.reserve(records.size());

    for (const auto& record : records) {
        auto dtoOpt = decryptRecord(record, vaultKey);
        if (dtoOpt.has_value()) {
            results.push_back(std::move(dtoOpt.value()));
        }
    }

    return results;
}

std::optional<CredentialDTO> Vault::getCredentialById(
    int64_t credentialId,
    int64_t userId,
    const SecureKey& vaultKey
) {
    if (!m_db || !vaultKey.isValid()) {
        return std::nullopt;
    }

    auto recordOpt = m_db->getVaultEntryById(credentialId, userId);
    if (!recordOpt.has_value()) {
        return std::nullopt;
    }

    return decryptRecord(recordOpt.value(), vaultKey);
}

VaultResult Vault::updateCredential(
    int64_t credentialId,
    int64_t userId,
    const CredentialInputDTO& input,
    const SecureKey& vaultKey
) {
    VaultResult result;

    if (!m_db || !vaultKey.isValid()) {
        result.message = "Database is not connected or encryption key is invalid.";
        return result;
    }

    // Verify ownership first
    auto existingOpt = m_db->getVaultEntryById(credentialId, userId);
    if (!existingOpt.has_value()) {
        result.message = "Credential not found or permission denied.";
        return result;
    }

    std::string error;
    if (!validateInput(input, error)) {
        result.message = error;
        return result;
    }

    // If password was left blank in the edit form, retain existing decrypted password
    std::string passwordToSave = input.password;
    if (passwordToSave.empty()) {
        auto decryptedExisting = decryptRecord(existingOpt.value(), vaultKey);
        if (decryptedExisting.has_value()) {
            passwordToSave = decryptedExisting->password;
        } else {
            result.message = "Cannot update without password: failed to decrypt current password.";
            return result;
        }
    }

    // Pack all sensitive fields into encrypted payload
    json payload = {
        {"website", input.website},
        {"website_url", input.website_url},
        {"username", input.username},
        {"password", passwordToSave},
        {"category", input.category.empty() ? "General" : input.category},
        {"notes", input.notes}
    };
    std::string payloadStr = payload.dump();

    // Encrypt with fresh random nonce and AAD binding
    std::string aad = Encryption::makeAAD(userId, 2);
    auto encrypted = Encryption::encrypt(payloadStr, vaultKey, aad);
    Encryption::wipeString(payloadStr);

    if (!encrypted.has_value()) {
        result.message = "Cryptographic error: failed to encrypt updated credential.";
        return result;
    }

    VaultEntryRecord updatedRecord;
    updatedRecord.id = credentialId;
    updatedRecord.user_id = userId;
    updatedRecord.encrypted_data = encrypted->ciphertext_hex;
    updatedRecord.data_nonce = encrypted->nonce_hex;
    updatedRecord.encryption_version = 2;
    updatedRecord.is_favorite = input.is_favorite;

    bool ok = m_db->updateVaultEntry(updatedRecord);
    if (!ok) {
        result.message = "Failed to update credential in database.";
        return result;
    }

    result.success = true;
    result.message = "Credential updated successfully.";
    result.credential_id = credentialId;
    return result;
}

VaultResult Vault::deleteCredential(int64_t credentialId, int64_t userId) {
    VaultResult result;

    if (!m_db) {
        result.message = "Database is not connected.";
        return result;
    }

    bool deleted = m_db->deleteVaultEntry(credentialId, userId);
    if (!deleted) {
        result.message = "Credential not found or permission denied.";
        return result;
    }

    result.success = true;
    result.message = "Credential deleted successfully.";
    result.credential_id = credentialId;
    return result;
}

std::vector<CredentialDTO> Vault::searchByWebsite(
    int64_t userId,
    const std::string& query,
    const SecureKey& vaultKey
) {
    std::vector<CredentialDTO> all = getAllCredentials(userId, vaultKey);
    if (query.empty()) {
        return all;
    }

    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    std::vector<CredentialDTO> filtered;
    for (auto& item : all) {
        std::string lowerSite = item.website;
        std::transform(lowerSite.begin(), lowerSite.end(), lowerSite.begin(), [](unsigned char c) {
            return std::tolower(c);
        });

        std::string lowerUser = item.username;
        std::transform(lowerUser.begin(), lowerUser.end(), lowerUser.begin(), [](unsigned char c) {
            return std::tolower(c);
        });

        if (lowerSite.find(lowerQuery) != std::string::npos || lowerUser.find(lowerQuery) != std::string::npos) {
            filtered.push_back(std::move(item));
        }
    }
    return filtered;
}

std::vector<CredentialDTO> Vault::filterByCategory(
    int64_t userId,
    const std::string& category,
    const SecureKey& vaultKey
) {
    std::vector<CredentialDTO> all = getAllCredentials(userId, vaultKey);
    if (category.empty() || category == "All") {
        return all;
    }

    std::vector<CredentialDTO> filtered;
    for (auto& item : all) {
        if (item.category == category) {
            filtered.push_back(std::move(item));
        }
    }
    return filtered;
}

VaultResult Vault::setFavorite(int64_t credentialId, int64_t userId, bool isFavorite) {
    VaultResult result;

    if (!m_db) {
        result.message = "Database is not connected.";
        return result;
    }

    // Update the separate is_favorite column in SQLite
    bool ok = m_db->setVaultEntryFavorite(credentialId, userId, isFavorite);
    if (!ok) {
        result.message = "Credential not found or permission denied.";
        return result;
    }

    result.success = true;
    result.message = isFavorite ? "Added to favorites." : "Removed from favorites.";
    result.credential_id = credentialId;
    return result;
}
