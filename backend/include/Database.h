#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <mutex>
#include <sqlite3.h>

/**
 * @brief Represents a user record stored in the database.
 * NOTE: password_hash stores the Argon2id hash; plain-text passwords are never stored.
 */
struct UserRecord {
    int64_t id{0};
    std::string name;
    std::string email;
    std::string password_hash;
    std::string created_at;
};

/**
 * @brief Represents an encrypted vault entry stored in the database.
 * NOTE: encrypted_password contains the ciphertext (hex/base64), and nonce contains
 * the cryptographic nonce used during encryption. Plain-text passwords are never stored.
 */
struct VaultEntryRecord {
    int64_t id{0};
    int64_t user_id{0};
    std::string website;
    std::string website_url;
    std::string username;
    std::string encrypted_password;
    std::string nonce;
    std::string category;
    std::string notes;
    std::string created_at;
    std::string updated_at;
};

/**
 * @brief Thread-safe Database manager using SQLite3 and prepared statements.
 */
class Database {
public:
    /**
     * @brief Constructor that accepts the database file path.
     * @param dbPath Path to the SQLite database file.
     */
    explicit Database(const std::string& dbPath);

    /**
     * @brief Destructor that closes the SQLite database connection.
     */
    ~Database();

    // Disable copy semantics to prevent duplicate handle mismanagement
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Allow move semantics
    Database(Database&& other) noexcept;
    Database& operator=(Database&& other) noexcept;

    /**
     * @brief Opens the SQLite connection, enables foreign keys, and initializes tables.
     * @return true on success, false on failure.
     */
    bool init();

    /**
     * @brief Closes the SQLite connection explicitly.
     */
    void close();

    /**
     * @brief Checks if the database is open and connected.
     */
    bool isOpen() const;

    // ==========================================
    // Transaction Support
    // ==========================================
    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();

    // ==========================================
    // User Operations
    // ==========================================

    /**
     * @brief Inserts a new user with a hashed password.
     * @param name User's full name or display name.
     * @param email User's email (unique identifier).
     * @param passwordHash Argon2id hash of the master password.
     * @return User's generated ID (> 0) on success, or -1 on failure.
     */
    int64_t createUser(const std::string& name, const std::string& email, const std::string& passwordHash);

    /**
     * @brief Retrieves a user by their unique email.
     * @param email User's email address.
     * @return std::optional<UserRecord> containing the user if found.
     */
    std::optional<UserRecord> getUserByEmail(const std::string& email);

    /**
     * @brief Retrieves a user by their user ID.
     * @param id User ID.
     * @return std::optional<UserRecord> containing the user if found.
     */
    std::optional<UserRecord> getUserById(int64_t id);

    // ==========================================
    // Vault Entry Operations
    // ==========================================

    /**
     * @brief Inserts a new encrypted credential into the vault.
     * @param entry Vault entry with encrypted_password and nonce populated.
     * @return Generated entry ID (> 0) on success, or -1 on failure.
     */
    int64_t createVaultEntry(const VaultEntryRecord& entry);

    /**
     * @brief Retrieves all encrypted vault entries belonging to a specific user.
     * @param userId The ID of the user.
     * @return Vector of VaultEntryRecord items.
     */
    std::vector<VaultEntryRecord> getVaultEntriesByUserId(int64_t userId);

    /**
     * @brief Retrieves a specific vault entry by its ID and user ID (ownership verification).
     * @param entryId Entry ID.
     * @param userId User ID of the owner.
     * @return std::optional<VaultEntryRecord> if found and owned by userId.
     */
    std::optional<VaultEntryRecord> getVaultEntryById(int64_t entryId, int64_t userId);

    /**
     * @brief Updates an existing vault entry.
     * @param entry Updated vault entry record (id and user_id must match).
     * @return true on success, false on failure or if not found.
     */
    bool updateVaultEntry(const VaultEntryRecord& entry);

    /**
     * @brief Deletes a vault entry belonging to a user.
     * @param entryId ID of the entry to delete.
     * @param userId ID of the owner user.
     * @return true if deleted, false otherwise.
     */
    bool deleteVaultEntry(int64_t entryId, int64_t userId);

    /**
     * @brief Gets the last error message from SQLite.
     */
    std::string getLastError() const;

private:
    std::string m_dbPath;
    sqlite3* m_db{nullptr};
    mutable std::mutex m_mutex; // Guards SQLite operations for thread-safety

    /**
     * @brief Creates the tables (users, vault_entries) and indexes if they don't exist.
     */
    bool createTables();

    /**
     * @brief Executes raw non-query SQL (e.g. PRAGMA foreign_keys = ON).
     */
    bool executeRaw(const std::string& sql);
};

#endif // DATABASE_H

