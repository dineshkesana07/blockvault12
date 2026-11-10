#include "Database.h"
#include <iostream>
#include <memory>
#include <set>

namespace {
    // Helper RAII wrapper for sqlite3_stmt to guarantee sqlite3_finalize is always called
    struct StmtCloser {
        void operator()(sqlite3_stmt* stmt) const {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
        }
    };
    using UniqueStmt = std::unique_ptr<sqlite3_stmt, StmtCloser>;
}

Database::Database(const std::string& dbPath)
    : m_dbPath(dbPath) {}

Database::~Database() {
    close();
}

Database::Database(Database&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.m_mutex);
    m_dbPath = std::move(other.m_dbPath);
    m_db = other.m_db;
    other.m_db = nullptr;
}

Database& Database::operator=(Database&& other) noexcept {
    if (this != &other) {
        // Lock both mutexes in a dead-lock-free order
        std::unique_lock<std::mutex> lockThis(m_mutex, std::defer_lock);
        std::unique_lock<std::mutex> lockOther(other.m_mutex, std::defer_lock);
        std::lock(lockThis, lockOther);

        closeInternal();
        m_dbPath = std::move(other.m_dbPath);
        m_db = other.m_db;
        other.m_db = nullptr;
    }
    return *this;
}

void Database::closeInternal() {
    if (m_db) {
        sqlite3_close_v2(m_db);
        m_db = nullptr;
    }
}

void Database::close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    closeInternal();
}

bool Database::isOpen() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_db != nullptr;
}

std::string Database::getLastError() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) {
        return sqlite3_errmsg(m_db);
    }
    return "Database handle is null";
}

bool Database::executeRawLocked(const std::string& sql) {
    if (!m_db) return false;
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Database Error] executeRaw failed: " 
                  << (errMsg ? errMsg : "Unknown error") 
                  << " (SQL: " << sql << ")" << std::endl;
        if (errMsg) sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool Database::init() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 1. Open SQLite database with read/write and create capabilities
    int rc = sqlite3_open_v2(
        m_dbPath.c_str(),
        &m_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc != SQLITE_OK) {
        std::cerr << "[Database Error] Failed to open database at " 
                  << m_dbPath << ": " << (m_db ? sqlite3_errmsg(m_db) : "Unknown error") << std::endl;
        closeInternal(); // Safe: does not re-acquire m_mutex
        return false;
    }

    // 2. Enable Foreign Key Constraints (SQLite disables them by default)
    if (!executeRawLocked("PRAGMA foreign_keys = ON;")) {
        std::cerr << "[Database Error] Failed to enable foreign keys." << std::endl;
        closeInternal();
        return false;
    }

    // 3. Set Write-Ahead Logging (WAL) mode for better concurrent performance
    executeRawLocked("PRAGMA journal_mode = WAL;");

    // 4. Create required database tables
    if (!createTables()) {
        closeInternal();
        return false;
    }

    // 5. Run automatic schema migrations if legacy database exists
    if (!migrateTables()) {
        closeInternal();
        return false;
    }

    return true;
}

bool Database::createTables() {
    // Table 1: users
    // Storing Argon2id master password hash and per-user unique random vault salt
    const std::string createUsersTable = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            vault_salt TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";

    if (!executeRawLocked(createUsersTable)) {
        std::cerr << "[Database Error] Failed to create 'users' table." << std::endl;
        return false;
    }

    // Table 2: vault_entries
    // Storing encrypted ciphertext, nonce, and separate favorite status
    const std::string createVaultTable = R"(
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_data TEXT NOT NULL DEFAULT '',
            data_nonce TEXT NOT NULL DEFAULT '',
            encryption_version INTEGER NOT NULL DEFAULT 2,
            is_favorite INTEGER NOT NULL DEFAULT 0,
            website TEXT DEFAULT '',
            website_url TEXT DEFAULT '',
            username TEXT DEFAULT '',
            encrypted_password TEXT DEFAULT '',
            nonce TEXT DEFAULT '',
            category TEXT DEFAULT 'General',
            notes TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";

    if (!executeRawLocked(createVaultTable)) {
        std::cerr << "[Database Error] Failed to create 'vault_entries' table." << std::endl;
        return false;
    }

    // Create index on user_id for fast lookup
    const std::string createIndex = R"(
        CREATE INDEX IF NOT EXISTS idx_vault_user_id ON vault_entries(user_id);
    )";
    executeRawLocked(createIndex);

    return true;
}

bool Database::migrateTables() {
    if (!m_db) return false;

    // Helper to get columns for a table
    auto getColumns = [this](const std::string& tableName) -> std::set<std::string> {
        std::set<std::string> columns;
        std::string sql = "PRAGMA table_info(" + tableName + ");";
        sqlite3_stmt* stmtRaw = nullptr;
        if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmtRaw, nullptr) == SQLITE_OK) {
            UniqueStmt stmt(stmtRaw);
            while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                const unsigned char* name = sqlite3_column_text(stmt.get(), 1);
                if (name) {
                    columns.insert(reinterpret_cast<const char*>(name));
                }
            }
        }
        return columns;
    };

    // 1. Check users table
    auto userCols = getColumns("users");
    if (!userCols.empty() && userCols.find("vault_salt") == userCols.end()) {
        std::cout << "[Database Migration] Adding 'vault_salt' column to 'users' table..." << std::endl;
        if (!executeRawLocked("ALTER TABLE users ADD COLUMN vault_salt TEXT NOT NULL DEFAULT '';")) {
            std::cerr << "[Database Error] Failed to add 'vault_salt' to 'users'." << std::endl;
            return false;
        }
    }

    if (userCols.find("google_subject") == userCols.end() &&
        !executeRawLocked("ALTER TABLE users ADD COLUMN google_subject TEXT;")) {
        return false;
    }
    if (!executeRawLocked("CREATE UNIQUE INDEX IF NOT EXISTS users_google_subject ON users(google_subject);")) {
        return false;
    }

    // 2. Check vault_entries table
    auto vaultCols = getColumns("vault_entries");
    if (!vaultCols.empty()) {
        if (vaultCols.find("encrypted_data") == vaultCols.end()) {
            std::cout << "[Database Migration] Adding 'encrypted_data' column to 'vault_entries' table..." << std::endl;
            executeRawLocked("ALTER TABLE vault_entries ADD COLUMN encrypted_data TEXT NOT NULL DEFAULT '';");
        }
        if (vaultCols.find("data_nonce") == vaultCols.end()) {
            std::cout << "[Database Migration] Adding 'data_nonce' column to 'vault_entries' table..." << std::endl;
            executeRawLocked("ALTER TABLE vault_entries ADD COLUMN data_nonce TEXT NOT NULL DEFAULT '';");
        }
        if (vaultCols.find("encryption_version") == vaultCols.end()) {
            std::cout << "[Database Migration] Adding 'encryption_version' column to 'vault_entries' table..." << std::endl;
            executeRawLocked("ALTER TABLE vault_entries ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 1;");
        }
        if (vaultCols.find("is_favorite") == vaultCols.end()) {
            std::cout << "[Database Migration] Adding 'is_favorite' column to 'vault_entries' table..." << std::endl;
            executeRawLocked("ALTER TABLE vault_entries ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;");
        }
    }

    return true;
}

// ==========================================
// Transactions
// ==========================================

bool Database::beginTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeRawLocked("BEGIN TRANSACTION;");
}

bool Database::commitTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeRawLocked("COMMIT;");
}

bool Database::rollbackTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeRawLocked("ROLLBACK;");
}

// ==========================================
// User Operations (Prepared Statements)
// ==========================================

int64_t Database::createUser(const std::string& name, const std::string& email, 
                             const std::string& passwordHash, const std::string& vaultSalt,
                             const std::string& googleSubject) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return -1;

    const char* sql = "INSERT INTO users (name, email, password_hash, vault_salt, google_subject) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmtRaw = nullptr;

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return -1;
    }
    UniqueStmt stmt(stmtRaw);

    // Bind parameters safely to avoid SQL injection
    sqlite3_bind_text(stmt.get(), 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, passwordHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, vaultSalt.c_str(), -1, SQLITE_TRANSIENT);

    if (googleSubject.empty()) sqlite3_bind_null(stmt.get(), 5);
    else sqlite3_bind_text(stmt.get(), 5, googleSubject.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Failed to insert user: " << sqlite3_errmsg(m_db) << std::endl;
        return -1;
    }

    return sqlite3_last_insert_rowid(m_db);
}

std::optional<UserRecord> Database::getUserByEmail(const std::string& email) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;

    const char* sql = "SELECT id, name, email, password_hash, vault_salt, created_at, google_subject FROM users WHERE email = ? LIMIT 1;";
    sqlite3_stmt* stmtRaw = nullptr;

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return std::nullopt;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_text(stmt.get(), 1, email.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        UserRecord user;
        user.id = sqlite3_column_int64(stmt.get(), 0);
        user.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        user.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        
        const unsigned char* salt = sqlite3_column_text(stmt.get(), 4);
        user.vault_salt = salt ? reinterpret_cast<const char*>(salt) : "";

        const unsigned char* createdAt = sqlite3_column_text(stmt.get(), 5);
        user.created_at = createdAt ? reinterpret_cast<const char*>(createdAt) : "";
        const auto* subject = sqlite3_column_text(stmt.get(), 6);
        user.google_subject = subject ? reinterpret_cast<const char*>(subject) : "";
        return user;
    }

    return std::nullopt;
}

std::optional<UserRecord> Database::getUserById(int64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;

    const char* sql = "SELECT id, name, email, password_hash, vault_salt, created_at, google_subject FROM users WHERE id = ? LIMIT 1;";
    sqlite3_stmt* stmtRaw = nullptr;

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return std::nullopt;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int64(stmt.get(), 1, id);

    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        UserRecord user;
        user.id = sqlite3_column_int64(stmt.get(), 0);
        user.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        user.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        
        const unsigned char* salt = sqlite3_column_text(stmt.get(), 4);
        user.vault_salt = salt ? reinterpret_cast<const char*>(salt) : "";

        const unsigned char* createdAt = sqlite3_column_text(stmt.get(), 5);
        user.created_at = createdAt ? reinterpret_cast<const char*>(createdAt) : "";
        const auto* subject = sqlite3_column_text(stmt.get(), 6);
        user.google_subject = subject ? reinterpret_cast<const char*>(subject) : "";
        return user;
    }

    return std::nullopt;
}

std::optional<UserRecord> Database::getUserByGoogleSubject(const std::string& subject) {
    int64_t id = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_db || subject.empty()) return std::nullopt;
        sqlite3_stmt* raw = nullptr;
        if (sqlite3_prepare_v2(m_db, "SELECT id FROM users WHERE google_subject = ?;",
                               -1, &raw, nullptr) != SQLITE_OK) return std::nullopt;
        UniqueStmt stmt(raw);
        sqlite3_bind_text(stmt.get(), 1, subject.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
        id = sqlite3_column_int64(stmt.get(), 0);
    }
    return getUserById(id);
}

bool Database::bindGoogleSubject(int64_t userId, const std::string& subject) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db || subject.empty()) return false;
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(m_db,
            "UPDATE users SET google_subject = ? WHERE id = ? AND "
            "(google_subject IS NULL OR google_subject = ?);",
            -1, &raw, nullptr) != SQLITE_OK) return false;
    UniqueStmt stmt(raw);
    sqlite3_bind_text(stmt.get(), 1, subject.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, userId);
    sqlite3_bind_text(stmt.get(), 3, subject.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(m_db) == 1;
}

// ==========================================
// Vault Entry Operations (Prepared Statements)
// ==========================================

int64_t Database::createVaultEntry(const VaultEntryRecord& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return -1;

    const char* sql = R"(
        INSERT INTO vault_entries 
        (user_id, encrypted_data, data_nonce, encryption_version, is_favorite, 
         website, website_url, username, encrypted_password, nonce, category, notes, 
         created_at, updated_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'));
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return -1;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int64(stmt.get(), 1, entry.user_id);
    sqlite3_bind_text(stmt.get(), 2, entry.encrypted_data.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, entry.data_nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 4, entry.encryption_version);
    sqlite3_bind_int(stmt.get(), 5, entry.is_favorite ? 1 : 0);

    // Empty / default for legacy columns so existing constraints pass
    sqlite3_bind_text(stmt.get(), 6, entry.website.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, entry.website_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 8, entry.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 9, entry.encrypted_password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 10, entry.nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 11, entry.category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 12, entry.notes.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Failed to create vault entry: " << sqlite3_errmsg(m_db) << std::endl;
        return -1;
    }

    return sqlite3_last_insert_rowid(m_db);
}

std::vector<VaultEntryRecord> Database::getVaultEntriesByUserId(int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<VaultEntryRecord> list;
    if (!m_db) return list;

    const char* sql = R"(
        SELECT id, user_id, encrypted_data, data_nonce, encryption_version, is_favorite,
               website, website_url, username, encrypted_password, nonce, category, notes,
               created_at, updated_at 
        FROM vault_entries 
        WHERE user_id = ? 
        ORDER BY updated_at DESC;
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return list;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int64(stmt.get(), 1, userId);

    const auto getStr = [&](int col) -> std::string {
        const unsigned char* val = sqlite3_column_text(stmt.get(), col);
        return val ? reinterpret_cast<const char*>(val) : "";
    };

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        VaultEntryRecord entry;
        entry.id = sqlite3_column_int64(stmt.get(), 0);
        entry.user_id = sqlite3_column_int64(stmt.get(), 1);
        entry.encrypted_data = getStr(2);
        entry.data_nonce = getStr(3);
        entry.encryption_version = sqlite3_column_int(stmt.get(), 4);
        entry.is_favorite = (sqlite3_column_int(stmt.get(), 5) != 0);

        entry.website = getStr(6);
        entry.website_url = getStr(7);
        entry.username = getStr(8);
        entry.encrypted_password = getStr(9);
        entry.nonce = getStr(10);
        entry.category = getStr(11);
        entry.notes = getStr(12);

        entry.created_at = getStr(13);
        entry.updated_at = getStr(14);

        list.push_back(std::move(entry));
    }

    return list;
}

std::optional<VaultEntryRecord> Database::getVaultEntryById(int64_t entryId, int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;

    const char* sql = R"(
        SELECT id, user_id, encrypted_data, data_nonce, encryption_version, is_favorite,
               website, website_url, username, encrypted_password, nonce, category, notes,
               created_at, updated_at 
        FROM vault_entries 
        WHERE id = ? AND user_id = ? 
        LIMIT 1;
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return std::nullopt;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int64(stmt.get(), 1, entryId);
    sqlite3_bind_int64(stmt.get(), 2, userId);

    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto getStr = [&](int col) -> std::string {
            const unsigned char* val = sqlite3_column_text(stmt.get(), col);
            return val ? reinterpret_cast<const char*>(val) : "";
        };

        VaultEntryRecord entry;
        entry.id = sqlite3_column_int64(stmt.get(), 0);
        entry.user_id = sqlite3_column_int64(stmt.get(), 1);
        entry.encrypted_data = getStr(2);
        entry.data_nonce = getStr(3);
        entry.encryption_version = sqlite3_column_int(stmt.get(), 4);
        entry.is_favorite = (sqlite3_column_int(stmt.get(), 5) != 0);

        entry.website = getStr(6);
        entry.website_url = getStr(7);
        entry.username = getStr(8);
        entry.encrypted_password = getStr(9);
        entry.nonce = getStr(10);
        entry.category = getStr(11);
        entry.notes = getStr(12);

        entry.created_at = getStr(13);
        entry.updated_at = getStr(14);

        return entry;
    }

    return std::nullopt;
}

bool Database::updateVaultEntry(const VaultEntryRecord& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;

    const char* sql = R"(
        UPDATE vault_entries 
        SET encrypted_data = ?, data_nonce = ?, encryption_version = ?, is_favorite = ?, updated_at = datetime('now')
        WHERE id = ? AND user_id = ?;
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_text(stmt.get(), 1, entry.encrypted_data.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, entry.data_nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 3, entry.encryption_version);
    sqlite3_bind_int(stmt.get(), 4, entry.is_favorite ? 1 : 0);
    sqlite3_bind_int64(stmt.get(), 5, entry.id);
    sqlite3_bind_int64(stmt.get(), 6, entry.user_id);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Update failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    return sqlite3_changes(m_db) > 0;
}

bool Database::setVaultEntryFavorite(int64_t entryId, int64_t userId, bool isFavorite) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;

    const char* sql = R"(
        UPDATE vault_entries 
        SET is_favorite = ?, updated_at = datetime('now')
        WHERE id = ? AND user_id = ?;
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int(stmt.get(), 1, isFavorite ? 1 : 0);
    sqlite3_bind_int64(stmt.get(), 2, entryId);
    sqlite3_bind_int64(stmt.get(), 3, userId);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Set favorite failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    return sqlite3_changes(m_db) > 0;
}

bool Database::deleteVaultEntry(int64_t entryId, int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;

    const char* sql = "DELETE FROM vault_entries WHERE id = ? AND user_id = ?;";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int64(stmt.get(), 1, entryId);
    sqlite3_bind_int64(stmt.get(), 2, userId);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Delete failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    return sqlite3_changes(m_db) > 0;
}
