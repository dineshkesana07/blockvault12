#include "Database.h"
#include <iostream>
#include <sstream>

// Helper RAII wrapper for sqlite3_stmt to guarantee sqlite3_finalize is always called
namespace {
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

        close();
        m_dbPath = std::move(other.m_dbPath);
        m_db = other.m_db;
        other.m_db = nullptr;
    }
    return *this;
}

void Database::close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
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

bool Database::executeRaw(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Database Error] executeRaw failed: " 
                  << (errMsg ? errMsg : "Unknown error") << std::endl;
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
                  << m_dbPath << ": " << sqlite3_errmsg(m_db) << std::endl;
        close();
        return false;
    }

    // 2. Enable Foreign Key Constraints (SQLite disables them by default)
    if (!executeRaw("PRAGMA foreign_keys = ON;")) {
        std::cerr << "[Database Error] Failed to enable foreign keys." << std::endl;
        return false;
    }

    // 3. Set Write-Ahead Logging (WAL) mode for better concurrent performance
    executeRaw("PRAGMA journal_mode = WAL;");

    // 4. Create required database tables
    return createTables();
}

bool Database::createTables() {
    // Table 1: users
    // Storing Argon2id master password hash (never plain text)
    const std::string createUsersTable = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";

    if (!executeRaw(createUsersTable)) {
        std::cerr << "[Database Error] Failed to create 'users' table." << std::endl;
        return false;
    }

    // Table 2: vault_entries
    // Storing encrypted ciphertext and nonce (never plain text)
    // foreign key user_id references users(id) with ON DELETE CASCADE
    const std::string createVaultTable = R"(
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            website_url TEXT,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            nonce TEXT NOT NULL,
            category TEXT DEFAULT 'General',
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";

    if (!executeRaw(createVaultTable)) {
        std::cerr << "[Database Error] Failed to create 'vault_entries' table." << std::endl;
        return false;
    }

    // Create index on user_id for faster lookup of user credentials
    const std::string createIndex = R"(
        CREATE INDEX IF NOT EXISTS idx_vault_user_id ON vault_entries(user_id);
    )";
    executeRaw(createIndex);

    return true;
}

// ==========================================
// Transactions
// ==========================================

bool Database::beginTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeRaw("BEGIN TRANSACTION;");
}

bool Database::commitTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeRaw("COMMIT;");
}

bool Database::rollbackTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeRaw("ROLLBACK;");
}

// ==========================================
// User Operations (Prepared Statements)
// ==========================================

int64_t Database::createUser(const std::string& name, const std::string& email, const std::string& passwordHash) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return -1;

    const char* sql = "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?);";
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

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Failed to insert user: " << sqlite3_errmsg(m_db) << std::endl;
        return -1;
    }

    return sqlite3_last_insert_rowid(m_db);
}

std::optional<UserRecord> Database::getUserByEmail(const std::string& email) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;

    const char* sql = "SELECT id, name, email, password_hash, created_at FROM users WHERE email = ? LIMIT 1;";
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
        const unsigned char* createdAt = sqlite3_column_text(stmt.get(), 4);
        user.created_at = createdAt ? reinterpret_cast<const char*>(createdAt) : "";
        return user;
    }

    return std::nullopt;
}

std::optional<UserRecord> Database::getUserById(int64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;

    const char* sql = "SELECT id, name, email, password_hash, created_at FROM users WHERE id = ? LIMIT 1;";
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
        const unsigned char* createdAt = sqlite3_column_text(stmt.get(), 4);
        user.created_at = createdAt ? reinterpret_cast<const char*>(createdAt) : "";
        return user;
    }

    return std::nullopt;
}

// ==========================================
// Vault Entry Operations (Prepared Statements)
// ==========================================

int64_t Database::createVaultEntry(const VaultEntryRecord& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return -1;

    const char* sql = R"(
        INSERT INTO vault_entries 
        (user_id, website, website_url, username, encrypted_password, nonce, category, notes, created_at, updated_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'));
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return -1;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_int64(stmt.get(), 1, entry.user_id);
    sqlite3_bind_text(stmt.get(), 2, entry.website.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, entry.website_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, entry.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, entry.encrypted_password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, entry.nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, entry.category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 8, entry.notes.c_str(), -1, SQLITE_TRANSIENT);

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
        SELECT id, user_id, website, website_url, username, encrypted_password, nonce, category, notes, created_at, updated_at 
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

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        VaultEntryRecord entry;
        entry.id = sqlite3_column_int64(stmt.get(), 0);
        entry.user_id = sqlite3_column_int64(stmt.get(), 1);
        
        const auto getStr = [&](int col) -> std::string {
            const unsigned char* val = sqlite3_column_text(stmt.get(), col);
            return val ? reinterpret_cast<const char*>(val) : "";
        };

        entry.website = getStr(2);
        entry.website_url = getStr(3);
        entry.username = getStr(4);
        entry.encrypted_password = getStr(5);
        entry.nonce = getStr(6);
        entry.category = getStr(7);
        entry.notes = getStr(8);
        entry.created_at = getStr(9);
        entry.updated_at = getStr(10);

        list.push_back(std::move(entry));
    }

    return list;
}

std::optional<VaultEntryRecord> Database::getVaultEntryById(int64_t entryId, int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return std::nullopt;

    const char* sql = R"(
        SELECT id, user_id, website, website_url, username, encrypted_password, nonce, category, notes, created_at, updated_at 
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
        VaultEntryRecord entry;
        entry.id = sqlite3_column_int64(stmt.get(), 0);
        entry.user_id = sqlite3_column_int64(stmt.get(), 1);

        const auto getStr = [&](int col) -> std::string {
            const unsigned char* val = sqlite3_column_text(stmt.get(), col);
            return val ? reinterpret_cast<const char*>(val) : "";
        };

        entry.website = getStr(2);
        entry.website_url = getStr(3);
        entry.username = getStr(4);
        entry.encrypted_password = getStr(5);
        entry.nonce = getStr(6);
        entry.category = getStr(7);
        entry.notes = getStr(8);
        entry.created_at = getStr(9);
        entry.updated_at = getStr(10);

        return entry;
    }

    return std::nullopt;
}

bool Database::updateVaultEntry(const VaultEntryRecord& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;

    const char* sql = R"(
        UPDATE vault_entries 
        SET website = ?, website_url = ?, username = ?, encrypted_password = ?, nonce = ?, category = ?, notes = ?, updated_at = datetime('now')
        WHERE id = ? AND user_id = ?;
    )";

    sqlite3_stmt* stmtRaw = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr) != SQLITE_OK) {
        std::cerr << "[Database Error] Prepare failed: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    UniqueStmt stmt(stmtRaw);

    sqlite3_bind_text(stmt.get(), 1, entry.website.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, entry.website_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, entry.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, entry.encrypted_password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, entry.nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, entry.category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, entry.notes.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 8, entry.id);
    sqlite3_bind_int64(stmt.get(), 9, entry.user_id);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        std::cerr << "[Database Error] Update failed: " << sqlite3_errmsg(m_db) << std::endl;
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

