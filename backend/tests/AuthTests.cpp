#include "Auth.h"
#include "Encryption.h"
#include <cstdlib>
#include <iostream>
#include <memory>
#include <chrono>
#include <filesystem>

namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << std::endl;
        std::exit(1);
    }
}
}

int main() {
    require(Encryption::isInitialized(), "initialize encryption");
    const auto path = std::filesystem::temp_directory_path() /
        ("blockvault-auth-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".db");
    sqlite3* legacy = nullptr;
    require(sqlite3_open(path.string().c_str(), &legacy) == SQLITE_OK, "open legacy database");
    require(sqlite3_exec(legacy,
        "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, "
        "email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, vault_salt TEXT NOT NULL, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP);", nullptr, nullptr, nullptr) == SQLITE_OK,
        "prepare schema without Google identity column");
    sqlite3_close(legacy);
    auto db = std::make_shared<Database>(path.string());
    require(db->init(), "initialize database without email configuration");
    const std::string password = "StrongTestPassword9!";
    const std::string salt = Encryption::generateSaltHex();
    const auto id = db->createUser("Existing User", "existing@example.com",
                                   Auth::hashPassword(password), salt);
    require(id > 0, "prepare existing user");
    Auth auth(db);
    auto originalKey = Encryption::deriveVaultKey(password, salt);
    auto encrypted = Encryption::encrypt("existing vault secret", originalKey, Encryption::makeAAD(id));
    require(encrypted.has_value(), "encrypt existing vault entry");
    VaultEntryRecord entry;
    entry.user_id = id;
    entry.encrypted_data = encrypted->ciphertext_hex;
    entry.data_nonce = encrypted->nonce_hex;
    const auto entryId = db->createVaultEntry(entry);
    require(entryId > 0, "save existing vault entry");
    const GoogleIdentity existing{"google-existing", "existing@example.com", "Existing User"};
    require(!auth.loginGoogle(existing, "wrong").success,
            "do not link an existing vault without its password");
    const auto login = auth.loginGoogle(existing, password);
    require(login.success && login.user_id == id && login.vault_salt == salt,
            "preserve existing account and vault salt on login");
    require(auth.validateToken(login.token).has_value(), "create valid session");
    require(Encryption::deriveVaultKey(password, login.vault_salt).isValid(),
            "retain vault key derivation");
    require(auth.logoutUser(login.token), "log out session");
    require(!auth.validateToken(login.token).has_value(), "revoke session");
    const auto bound = db->getUserByGoogleSubject("google-existing");
    require(bound && bound->id == id,
            "bind verified Google subject to existing account");
    auto unlockedKey = Encryption::deriveVaultKey(password, login.vault_salt);
    const auto saved = db->getVaultEntryById(entryId, id);
    require(saved && Encryption::decrypt(saved->encrypted_data, saved->data_nonce,
                unlockedKey, Encryption::makeAAD(id)) == "existing vault secret",
            "decrypt pre-existing vault data after Google account linking");
    require(!auth.loginGoogle({"different-subject", "existing@example.com", "Other"}, password).success,
            "do not replace an existing Google identity even with the vault password");
    const GoogleIdentity fresh{"google-new", "new@example.com", "New User"};
    require(!auth.loginGoogle(fresh, "weak").success,
            "reject weak vault passwords for new accounts");
    const auto signup = auth.loginGoogle(fresh, password);
    require(signup.success && signup.user_id != id,
            "create a new vault for a verified Google account");
    require(!auth.loginGoogle(fresh, "wrong").success,
            "require vault password on returning Google sign-in");
    const auto returning = auth.loginGoogle({"google-new", "changed@example.com", "New Name"}, password);
    require(returning.success && returning.user_id == signup.user_id &&
                returning.vault_salt == signup.vault_salt,
            "identify returning users by stable Google subject and preserve vault key");
    require(!auth.loginGoogle({"", "new@example.com", "Invalid"}, password).success,
            "reject a missing Google subject");
    require(!GoogleOAuth::exchangeCode("", "http://localhost:5173"),
            "reject a missing OAuth code without contacting Google");
    require(!GoogleOAuth::exchangeCode(std::string(4097, 'x'), "http://localhost:5173"),
            "reject oversized OAuth codes");
    db->close();
    require(db->init(), "reopen migrated database");
    const auto persisted = db->getUserByGoogleSubject("google-existing");
    require(persisted && persisted->id == id, "persist Google account binding across restarts");
    db->close();
    std::filesystem::remove(path);
    std::cout << "Authentication checks passed." << std::endl;
}
