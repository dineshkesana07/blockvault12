#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include "Auth.h"
#include "Encryption.h"
#include "crow.h"
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

/**
 * @brief Context storing authenticated session information and decrypted vault
 * key in memory.
 */
struct UserSessionContext {
  int64_t user_id{0};
  std::string email;
  std::shared_ptr<SecureKey> vault_key;
};

/**
 * @brief Session and Key Manager for unlocked sessions.
 * Holds derived SecureKey instances in memory while session is active.
 * Key material is automatically wiped when session expires or user logs out.
 */
class SessionKeyStore {
public:
  static SessionKeyStore &instance();

  void storeKey(const std::string &token, SecureKey &&key);
  std::shared_ptr<SecureKey> getKey(const std::string &token);
  void removeKey(const std::string &token);

private:
  SessionKeyStore() = default;
  std::mutex m_mutex;
  std::unordered_map<std::string, std::shared_ptr<SecureKey>> m_keyStore;
};

/**
 * @brief Crow CORS Middleware allowing cross-origin requests from the React frontend.
 * Preflight OPTIONS requests are handled in before_handle() with HTTP 204.
 * Appropriate CORS headers are added to all responses in after_handle().
 */
struct CORSMiddleware {
  struct context {};

  void before_handle(crow::request &req, crow::response &res, context &ctx);
  void after_handle(crow::request &req, crow::response &res, context &ctx);
};

/**
 * @brief Helper function to extract and validate Bearer token from request headers.
 * Ensures the session token is valid and an in-memory vault key is present.
 */
std::optional<UserSessionContext>
authenticateRequest(const crow::request &req, std::shared_ptr<Auth> auth);

#endif // MIDDLEWARE_H
