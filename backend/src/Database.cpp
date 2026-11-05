#include "Database.h"
#include <iostream>
#include <sstream>
#include <cstring>

// Helper to log errors
static void logError(const std::string &msg) {
    std::cerr << "[Database Error] " << msg << std::endl;
}

Database::Database(const std::string &conninfo)
    : m_conninfo(conninfo), m_conn(nullptr) {}

Database::~Database() {
    close();
}

// Move constructor
Database::Database(Database &&other) noexcept {
    std::lock_guard<std::mutex> lock(other.m_mutex);
    m_conninfo = std::move(other.m_conninfo);
    m_conn = other.m_conn;
    other.m_conn = nullptr;
}

// Move assignment
Database &Database::operator=(Database &&other) noexcept {
    if (this != &other) {
        std::unique_lock<std::mutex> lockThis(m_mutex, std::defer_lock);
        std::unique_lock<std::mutex> lockOther(other.m_mutex, std::defer_lock);
        std::lock(lockThis, lockOther);
        closeInternal();
        m_conninfo = std::move(other.m_conninfo);
        m_conn = other.m_conn;
        other.m_conn = nullptr;
    }
    return *this;
}

bool Database::init() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_conn = PQconnectdb(m_conninfo.c_str());
    if (PQstatus(m_conn) != CONNECTION_OK) {
        logError(std::string("Failed to connect to PostgreSQL: ") + PQerrorMessage(m_conn));
        closeInternal();
        return false;
    }
    // Create schema if absent
    if (!createTables()) {
        closeInternal();
        return false;
    }
    // Run migrations (currently a no‑op placeholder)
    if (!migrateTables()) {
        closeInternal();
        return false;
    }
    return true;
}

void Database::close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    closeInternal();
}

bool Database::isOpen() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_conn && PQstatus(m_conn) == CONNECTION_OK;
}

std::string Database::getLastError() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_conn) {
        return PQerrorMessage(m_conn);
    }
    return "No connection";
}

void Database::closeInternal() {
    if (m_conn) {
        PQfinish(m_conn);
        m_conn = nullptr;
    }
}

bool Database::executeSQL(const std::string &sql) {
    // Used for statements that do not return rows (CREATE, UPDATE, etc.)
    PGresult *res = PQexec(m_conn, sql.c_str());
    if (!res) {
        logError(std::string("PQexec failed: ") + PQerrorMessage(m_conn));
        return false;
    }
    ExecStatusType status = PQresultStatus(res);
    bool ok = (status == PGRES_COMMAND_OK);
    if (!ok) {
        logError(std::string("SQL execution failed (" ) + PQerrorMessage(m_conn) + "): " + sql);
    }
    PQclear(res);
    return ok;
}

bool Database::beginTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeSQL("BEGIN");
}

bool Database::commitTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeSQL("COMMIT");
}

bool Database::rollbackTransaction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return executeSQL("ROLLBACK");
}

int64_t Database::createUser(const std::string &name,
                             const std::string &email,
                             const std::string &passwordHash,
                             const std::string &vaultSalt) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "INSERT INTO users (name, email, password_hash, vault_salt) "
                       "VALUES ($1, $2, $3, $4) RETURNING id;";
    const char *params[4] = {name.c_str(), email.c_str(), passwordHash.c_str(), vaultSalt.c_str()};
    int lengths[4] = {static_cast<int>(name.size()), static_cast<int>(email.size()),
                      static_cast<int>(passwordHash.size()), static_cast<int>(vaultSalt.size())};
    int formats[4] = {0, 0, 0, 0}; // text
    PGresult *res = PQexecParams(m_conn, stmt, 4, nullptr, params, lengths, formats, 0);
    if (!res) {
        logError(std::string("createUser PQexecParams failed: ") + PQerrorMessage(m_conn));
        return 0;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        logError(std::string("createUser failed: ") + PQerrorMessage(m_conn));
        PQclear(res);
        return 0;
    }
    char *idStr = PQgetvalue(res, 0, 0);
    int64_t id = std::stoll(idStr);
    PQclear(res);
    return id;
}

std::optional<UserRecord> Database::getUserByEmail(const std::string &email) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "SELECT id, name, email, password_hash, vault_salt, created_at FROM users WHERE email = $1;";
    const char *param = email.c_str();
    int len = static_cast<int>(email.size());
    int format = 0;
    PGresult *res = PQexecParams(m_conn, stmt, 1, nullptr, &param, &len, &format, 0);
    if (!res) {
        logError(std::string("getUserByEmail PQexecParams failed: ") + PQerrorMessage(m_conn));
        return {};
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        logError(std::string("getUserByEmail failed: ") + PQerrorMessage(m_conn));
        PQclear(res);
        return {};
    }
    if (PQntuples(res) == 0) {
        PQclear(res);
        return {};
    }
    UserRecord user;
    user.id = std::stoll(PQgetvalue(res, 0, 0));
    user.name = PQgetvalue(res, 0, 1);
    user.email = PQgetvalue(res, 0, 2);
    user.password_hash = PQgetvalue(res, 0, 3);
    user.vault_salt = PQgetvalue(res, 0, 4);
    user.created_at = PQgetvalue(res, 0, 5);
    PQclear(res);
    return user;
}

std::optional<UserRecord> Database::getUserById(int64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "SELECT id, name, email, password_hash, vault_salt, created_at FROM users WHERE id = $1;";
    std::string idStr = std::to_string(id);
    const char *param = idStr.c_str();
    int len = static_cast<int>(idStr.size());
    int format = 0;
    PGresult *res = PQexecParams(m_conn, stmt, 1, nullptr, &param, &len, &format, 0);
    if (!res) {
        logError(std::string("getUserById PQexecParams failed: ") + PQerrorMessage(m_conn));
        return {};
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        logError(std::string("getUserById failed: ") + PQerrorMessage(m_conn));
        PQclear(res);
        return {};
    }
    if (PQntuples(res) == 0) {
        PQclear(res);
        return {};
    }
    UserRecord user;
    user.id = std::stoll(PQgetvalue(res, 0, 0));
    user.name = PQgetvalue(res, 0, 1);
    user.email = PQgetvalue(res, 0, 2);
    user.password_hash = PQgetvalue(res, 0, 3);
    user.vault_salt = PQgetvalue(res, 0, 4);
    user.created_at = PQgetvalue(res, 0, 5);
    PQclear(res);
    return user;
}

int64_t Database::createVaultEntry(const VaultEntryRecord &entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt =
        "INSERT INTO vault_entries (user_id, encrypted_data, data_nonce, encryption_version, is_favorite, "
        "website, website_url, username, encrypted_password, nonce, category, notes) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id;";
    // Prepare string parameters that must outlive the call
    std::string s_user_id = std::to_string(entry.user_id);
    std::string s_enc_version = std::to_string(entry.encryption_version);
    const char *params[12] = {
        s_user_id.c_str(),
        entry.encrypted_data.c_str(),
        entry.data_nonce.c_str(),
        s_enc_version.c_str(),
        entry.is_favorite ? "true" : "false",
        entry.website.c_str(),
        entry.website_url.c_str(),
        entry.username.c_str(),
        entry.encrypted_password.c_str(),
        entry.nonce.c_str(),
        entry.category.c_str(),
        entry.notes.c_str()
    };
    // Let libpq compute lengths by passing nullptr.
    PGresult *res = PQexecParams(m_conn, stmt, 12, nullptr, params, nullptr, nullptr, 0);
    if (!res) {
        logError(std::string("createVaultEntry PQexecParams failed: ") + PQerrorMessage(m_conn));
        return 0;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        logError(std::string("createVaultEntry failed: ") + PQerrorMessage(m_conn));
        PQclear(res);
        return 0;
    }
    int64_t id = std::stoll(PQgetvalue(res, 0, 0));
    PQclear(res);
    return id;
}

std::vector<VaultEntryRecord> Database::getVaultEntriesByUserId(int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "SELECT id, user_id, encrypted_data, data_nonce, encryption_version, is_favorite, "
                        "website, website_url, username, encrypted_password, nonce, category, notes, created_at, updated_at "
                        "FROM vault_entries WHERE user_id = $1;";
    std::string idStr = std::to_string(userId);
    const char *param = idStr.c_str();
    int len = static_cast<int>(idStr.size());
    int format = 0;
    PGresult *res = PQexecParams(m_conn, stmt, 1, nullptr, &param, &len, &format, 0);
    std::vector<VaultEntryRecord> result;
    if (!res) {
        logError(std::string("getVaultEntriesByUserId PQexecParams failed: ") + PQerrorMessage(m_conn));
        return result;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        logError(std::string("getVaultEntriesByUserId failed: ") + PQerrorMessage(m_conn));
        PQclear(res);
        return result;
    }
    int rows = PQntuples(res);
    for (int i = 0; i < rows; ++i) {
        VaultEntryRecord rec;
        rec.id = std::stoll(PQgetvalue(res, i, 0));
        rec.user_id = std::stoll(PQgetvalue(res, i, 1));
        rec.encrypted_data = PQgetvalue(res, i, 2);
        rec.data_nonce = PQgetvalue(res, i, 3);
        rec.encryption_version = std::stoi(PQgetvalue(res, i, 4));
        rec.is_favorite = (std::string(PQgetvalue(res, i, 5)) == "t" || std::string(PQgetvalue(res, i, 5)) == "true");
        rec.website = PQgetvalue(res, i, 6);
        rec.website_url = PQgetvalue(res, i, 7);
        rec.username = PQgetvalue(res, i, 8);
        rec.encrypted_password = PQgetvalue(res, i, 9);
        rec.nonce = PQgetvalue(res, i, 10);
        rec.category = PQgetvalue(res, i, 11);
        rec.notes = PQgetvalue(res, i, 12);
        rec.created_at = PQgetvalue(res, i, 13);
        rec.updated_at = PQgetvalue(res, i, 14);
        result.push_back(std::move(rec));
    }
    PQclear(res);
    return result;
}

std::optional<VaultEntryRecord> Database::getVaultEntryById(int64_t entryId, int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "SELECT id, user_id, encrypted_data, data_nonce, encryption_version, is_favorite, "
                        "website, website_url, username, encrypted_password, nonce, category, notes, created_at, updated_at "
                        "FROM vault_entries WHERE id = $1 AND user_id = $2;";
    std::string idStr = std::to_string(entryId);
    std::string uidStr = std::to_string(userId);
    const char *params[2] = {idStr.c_str(), uidStr.c_str()};
    int lengths[2] = {static_cast<int>(idStr.size()), static_cast<int>(uidStr.size())};
    int formats[2] = {0, 0};
    PGresult *res = PQexecParams(m_conn, stmt, 2, nullptr, params, lengths, formats, 0);
    if (!res) {
        logError(std::string("getVaultEntryById PQexecParams failed: ") + PQerrorMessage(m_conn));
        return {};
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        logError(std::string("getVaultEntryById failed: ") + PQerrorMessage(m_conn));
        PQclear(res);
        return {};
    }
    if (PQntuples(res) == 0) {
        PQclear(res);
        return {};
    }
    VaultEntryRecord rec;
    rec.id = std::stoll(PQgetvalue(res, 0, 0));
    rec.user_id = std::stoll(PQgetvalue(res, 0, 1));
    rec.encrypted_data = PQgetvalue(res, 0, 2);
    rec.data_nonce = PQgetvalue(res, 0, 3);
    rec.encryption_version = std::stoi(PQgetvalue(res, 0, 4));
    rec.is_favorite = (std::string(PQgetvalue(res, 0, 5)) == "t" || std::string(PQgetvalue(res, 0, 5)) == "true");
    rec.website = PQgetvalue(res, 0, 6);
    rec.website_url = PQgetvalue(res, 0, 7);
    rec.username = PQgetvalue(res, 0, 8);
    rec.encrypted_password = PQgetvalue(res, 0, 9);
    rec.nonce = PQgetvalue(res, 0, 10);
    rec.category = PQgetvalue(res, 0, 11);
    rec.notes = PQgetvalue(res, 0, 12);
    rec.created_at = PQgetvalue(res, 0, 13);
    rec.updated_at = PQgetvalue(res, 0, 14);
    PQclear(res);
    return rec;
}

bool Database::updateVaultEntry(const VaultEntryRecord &entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt =
        "UPDATE vault_entries SET encrypted_data=$1, data_nonce=$2, encryption_version=$3, is_favorite=$4, "
        "website=$5, website_url=$6, username=$7, encrypted_password=$8, nonce=$9, category=$10, notes=$11, updated_at=CURRENT_TIMESTAMP "
        "WHERE id=$12 AND user_id=$13;";
    const char *params[13] = {
        entry.encrypted_data.c_str(),
        entry.data_nonce.c_str(),
        std::to_string(entry.encryption_version).c_str(),
        entry.is_favorite ? "true" : "false",
        entry.website.c_str(),
        entry.website_url.c_str(),
        entry.username.c_str(),
        entry.encrypted_password.c_str(),
        entry.nonce.c_str(),
        entry.category.c_str(),
        entry.notes.c_str(),
        std::to_string(entry.id).c_str(),
        std::to_string(entry.user_id).c_str()
    };
    int lengths[13];
    for (int i = 0; i < 13; ++i) lengths[i] = static_cast<int>(std::strlen(params[i]));
    int formats[13] = {0};
    PGresult *res = PQexecParams(m_conn, stmt, 13, nullptr, params, lengths, formats, 0);
    if (!res) {
        logError(std::string("updateVaultEntry PQexecParams failed: ") + PQerrorMessage(m_conn));
        return false;
    }
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (!ok) {
        logError(std::string("updateVaultEntry failed: ") + PQerrorMessage(m_conn));
    }
    PQclear(res);
    return ok;
}

bool Database::setVaultEntryFavorite(int64_t entryId, int64_t userId, bool isFavorite) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "UPDATE vault_entries SET is_favorite=$1 WHERE id=$2 AND user_id=$3;";
    const char *params[3] = {isFavorite ? "true" : "false", std::to_string(entryId).c_str(), std::to_string(userId).c_str()};
    int lengths[3] = {static_cast<int>(std::strlen(params[0])), static_cast<int>(std::strlen(params[1])), static_cast<int>(std::strlen(params[2]))};
    int formats[3] = {0,0,0};
    PGresult *res = PQexecParams(m_conn, stmt, 3, nullptr, params, lengths, formats, 0);
    if (!res) {
        logError(std::string("setVaultEntryFavorite PQexecParams failed: ") + PQerrorMessage(m_conn));
        return false;
    }
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (!ok) {
        logError(std::string("setVaultEntryFavorite failed: ") + PQerrorMessage(m_conn));
    }
    PQclear(res);
    return ok;
}

bool Database::deleteVaultEntry(int64_t entryId, int64_t userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char *stmt = "DELETE FROM vault_entries WHERE id = $1 AND user_id = $2;";
    const char *params[2] = {std::to_string(entryId).c_str(), std::to_string(userId).c_str()};
    int lengths[2] = {static_cast<int>(std::strlen(params[0])), static_cast<int>(std::strlen(params[1]))};
    int formats[2] = {0,0};
    PGresult *res = PQexecParams(m_conn, stmt, 2, nullptr, params, lengths, formats, 0);
    if (!res) {
        logError(std::string("deleteVaultEntry PQexecParams failed: ") + PQerrorMessage(m_conn));
        return false;
    }
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (!ok) {
        logError(std::string("deleteVaultEntry failed: ") + PQerrorMessage(m_conn));
    }
    PQclear(res);
    return ok;
}

bool Database::createTables() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string usersTable = R"(
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            vault_salt TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
    )";
    if (!executeSQL(usersTable)) return false;

    const std::string vaultTable = R"(
        CREATE TABLE IF NOT EXISTS vault_entries (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            encrypted_data TEXT NOT NULL DEFAULT '',
            data_nonce TEXT NOT NULL DEFAULT '',
            encryption_version INTEGER NOT NULL DEFAULT 2,
            is_favorite BOOLEAN NOT NULL DEFAULT FALSE,
            website TEXT DEFAULT '',
            website_url TEXT DEFAULT '',
            username TEXT DEFAULT '',
            encrypted_password TEXT DEFAULT '',
            nonce TEXT DEFAULT '',
            category TEXT DEFAULT 'General',
            notes TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
    )";
    if (!executeSQL(vaultTable)) return false;

    const std::string indexStmt = "CREATE INDEX IF NOT EXISTS idx_vault_user_id ON vault_entries(user_id);";
    executeSQL(indexStmt);
    return true;
}

bool Database::migrateTables() {
    // Placeholder – currently no migrations required.
    // Future schema changes can be handled here.
    return true;
}
