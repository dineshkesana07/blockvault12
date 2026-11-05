#ifndef DATABASE_H
#define DATABASE_H

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <libpq-fe.h>

struct UserRecord {
  int64_t id{0};
  std::string name;
  std::string email;
  std::string password_hash;
  std::string vault_salt;
  std::string created_at;
};

struct VaultEntryRecord {
  int64_t id{0};
  int64_t user_id{0};

  // Modern encrypted credential payload (v2)
  std::string encrypted_data;
  std::string data_nonce;
  int encryption_version{2};

  // Dedicated favorite metadata
  bool is_favorite{false};

  // Legacy fields (v1) retained for backwards-compatible reading
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

class Database {
 public:
  explicit Database(const std::string &conninfo);
  ~Database();

  Database(const Database &) = delete;
  Database &operator=(const Database &) = delete;

  Database(Database &&other) noexcept;
  Database &operator=(Database &&other) noexcept;

  bool init();
  void close();
  bool isOpen() const;

  bool beginTransaction();
  bool commitTransaction();
  bool rollbackTransaction();

  // User operations (Prepared Statements)
  int64_t createUser(const std::string &name, const std::string &email,
                     const std::string &passwordHash,
                     const std::string &vaultSalt);

  std::optional<UserRecord> getUserByEmail(const std::string &email);
  std::optional<UserRecord> getUserById(int64_t id);

  // Vault operations (Prepared Statements)
  int64_t createVaultEntry(const VaultEntryRecord &entry);

  std::vector<VaultEntryRecord> getVaultEntriesByUserId(int64_t userId);

  std::optional<VaultEntryRecord> getVaultEntryById(int64_t entryId,
                                                    int64_t userId);

  bool updateVaultEntry(const VaultEntryRecord &entry);

  bool setVaultEntryFavorite(int64_t entryId, int64_t userId, bool isFavorite);

  bool deleteVaultEntry(int64_t entryId, int64_t userId);

  std::string getLastError() const;

 private:
  std::string m_conninfo;
  PGconn *m_conn{nullptr};
  mutable std::mutex m_mutex;

  void closeInternal();
  bool executeSQL(const std::string &sql);
  bool createTables();
  bool migrateTables();
};

#endif // DATABASE_H