#include "Vault.h"
#include <iostream>
#include <algorithm>
#include <cctype>

Vault::Vault(std::shared_ptr<Database> db)
    : m_db(std::move(db)) {}

bool Vault::validateInput(const CredentialInputDTO& input, std::string& outError) const {
    if (input.website.empty()) {
        outError = "Website name cannot be empty.";
        return false;
    }
    if (input.username.empty()) {
        outError = "Username or email cannot be empty.";
        return false;
    }
    return true;
}

std::optional<CredentialDTO> Vault::decryptRecord(
    const VaultEntryRecord& record,
    const SecureKey& vaultKey
) const {
    // Decrypt the stored password ciphertext using XChaCha20-Poly1305
    std::string additionalData = std::to_string(record.user_id);
    auto decryptedPassword = Encryption::decrypt(
        record.encrypted_password,
        record.nonce,
        vaultKey,
        additionalData
    );

    if (!decryptedPassword.has_value()) {
        std::cerr << "[Vault Error] Decryption failed for credential ID: " << record.id << std::endl;
        return std::nullopt;
    }

    CredentialDTO dto;
    dto.id = record.id;
    dto.user_id = record.user_id;
    dto.website = record.website;
    dto.website_url = record.website_url;
    dto.username = record.username;
    dto.password = decryptedPassword.value();
    dto.category = record.category;
    dto.notes = record.notes;
    dto.created_at = record.created_at;
    dto.updated_at = record.updated_at;

    // Check if category or notes marks this entry as a favorite (e.g. prefix tag)
    // To support favorites without mutating schema, category can store "Favorite" or notes tag "[FAVORITE]"
    dto.is_favorite = (record.notes.find("[FAVORITE]") != std::string::npos);

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

    // 1. Authenticated encryption with user_id as additional authenticated data
    std::string additionalData = std::to_string(userId);
    auto encrypted = Encryption::encrypt(input.password, vaultKey, additionalData);
    if (!encrypted.has_value()) {
        result.message = "Cryptographic error: failed to encrypt password.";
        return result;
    }

    // 2. Prepare database record
    VaultEntryRecord record;
    record.user_id = userId;
    record.website = input.website;
    record.website_url = input.website_url;
    record.username = input.username;
    record.encrypted_password = encrypted->ciphertext_hex;
    record.nonce = encrypted->nonce_hex;
    record.category = input.category.empty() ? "General" : input.category;
    
    // Store favorite indicator in notes if requested
    record.notes = input.notes;
    if (input.is_favorite && record.notes.find("[FAVORITE]") == std::string::npos) {
        record.notes += " [FAVORITE]";
    }

    // 3. Persist into SQLite
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

    VaultEntryRecord updatedRecord = existingOpt.value();
    updatedRecord.website = input.website;
    updatedRecord.website_url = input.website_url;
    updatedRecord.username = input.username;
    updatedRecord.category = input.category.empty() ? "General" : input.category;

    // Handle notes & favorite status
    std::string cleanNotes = input.notes;
    // Strip old [FAVORITE] tag if present
    size_t tagPos = cleanNotes.find("[FAVORITE]");
    if (tagPos != std::string::npos) {
        cleanNotes.erase(tagPos, std::string("[FAVORITE]").length());
    }
    if (input.is_favorite) {
        cleanNotes += " [FAVORITE]";
    }
    updatedRecord.notes = cleanNotes;

    // If new password is provided, re-encrypt with fresh nonce
    if (!input.password.empty()) {
        std::string additionalData = std::to_string(userId);
        auto encrypted = Encryption::encrypt(input.password, vaultKey, additionalData);
        if (!encrypted.has_value()) {
            result.message = "Cryptographic error: failed to encrypt updated password.";
            return result;
        }
        updatedRecord.encrypted_password = encrypted->ciphertext_hex;
        updatedRecord.nonce = encrypted->nonce_hex;
    }

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

    auto existingOpt = m_db->getVaultEntryById(credentialId, userId);
    if (!existingOpt.has_value()) {
        result.message = "Credential not found or permission denied.";
        return result;
    }

    VaultEntryRecord record = existingOpt.value();
    std::string notes = record.notes;

    size_t tagPos = notes.find("[FAVORITE]");
    if (isFavorite) {
        if (tagPos == std::string::npos) {
            notes += " [FAVORITE]";
        }
    } else {
        if (tagPos != std::string::npos) {
            notes.erase(tagPos, std::string("[FAVORITE]").length());
        }
    }
    record.notes = notes;

    bool ok = m_db->updateVaultEntry(record);
    if (!ok) {
        result.message = "Failed to update favorite status.";
        return result;
    }

    result.success = true;
    result.message = isFavorite ? "Added to favorites." : "Removed from favorites.";
    result.credential_id = credentialId;
    return result;
}

