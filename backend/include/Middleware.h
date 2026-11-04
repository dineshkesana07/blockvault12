#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include "Auth.h"
#include "Encryption.h"
#include "crow.h"
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

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
 * @brief Crow CORS Middleware allowing cross-origin requests from React
 * frontend.
 */
struct CORSMiddleware {
  struct context {};

  void before_handle(crow::request &req, crow::response &res,
                     context & /*ctx*/) {
    // Intercept preflight OPTIONS before route matching
    if (req.method == crow::HTTPMethod::Options) {
      std::string origin = req.get_header_value("Origin");
      std::string allowedOrigin = "*";
      const char* envOrigin = std::getenv("FRONTEND_ORIGIN");
      if (envOrigin && std::string(envOrigin).length() > 0) {
          allowedOrigin = envOrigin;
      } else if (!origin.empty()) {
          allowedOrigin = origin;
      }

      res.add_header("Access-Control-Allow-Origin", allowedOrigin);
      res.add_header("Access-Control-Allow-Methods",
                     "GET, POST, PUT, DELETE, OPTIONS");
      res.add_header("Access-Control-Allow-Headers",
                     "Content-Type, Authorization, X-Requested-With, Accept, Origin");
      res.add_header("Access-Control-Max-Age", "86400");
      res.code = 204;
      res.end();
    }
  }

  void after_handle(crow::request &req, crow::response &res,
                    context & /*ctx*/) {
    // Skip if this was an OPTIONS request already completed in before_handle
    if (req.method == crow::HTTPMethod::Options) {
      return;
    }

    std::string origin = req.get_header_value("Origin");
    std::string allowedOrigin = "*";
    const char* envOrigin = std::getenv("FRONTEND_ORIGIN");
    if (envOrigin && std::string(envOrigin).length() > 0) {
        allowedOrigin = envOrigin;
    } else if (!origin.empty()) {
        allowedOrigin = origin;
    }

    res.add_header("Access-Control-Allow-Origin", allowedOrigin);
    res.add_header("Access-Control-Allow-Methods",
                   "GET, POST, PUT, DELETE, OPTIONS");
    res.add_header("Access-Control-Allow-Headers",
                   "Content-Type, Authorization, X-Requested-With, Accept, Origin");
    res.add_header("Access-Control-Max-Age", "86400");
  }
};

/**
 * @brief Helper function to extract and validate Bearer token from request
 * headers.
 */
std::optional<UserSessionContext>
authenticateRequest(const crow::request &req, std::shared_ptr<Auth> auth);

#endif // MIDDLEWARE_H
