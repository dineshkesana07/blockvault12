
#include "Middleware.h"

#include <iostream>
#include <utility>

// Internal helper functions
namespace {

const char *const localFrontendOrigin = "http://localhost:5174";

const char *const allowedMethods = "GET, POST, PUT, DELETE, OPTIONS";

const char *const allowedHeaders = "Content-Type, Authorization";

std::string trim(const std::string &value) {
  const auto first = value.find_first_not_of(" \t\r\n");

  if (first == std::string::npos)
    return {};

  const auto last = value.find_last_not_of(" \t\r\n");

  return value.substr(0, last - first + 1);
}

std::unordered_set<std::string> getAllowedOrigins() {

  std::unordered_set<std::string> origins{localFrontendOrigin};

  const char *envOrigins = std::getenv("FRONTEND_ORIGIN");

  if (!envOrigins || *envOrigins == '\0')
    return origins;

  std::stringstream ss(envOrigins);
  std::string origin;

  while (std::getline(ss, origin, ',')) {

    origin = trim(origin);

    if (!origin.empty())
      origins.insert(origin);
  }

  return origins;
}

void addCorsHeaders(const crow::request &req, crow::response &res) {

  const std::string origin = req.get_header_value("Origin");

  const auto allowedOrigins = getAllowedOrigins();

  if (origin.empty()) {

    res.set_header("Access-Control-Allow-Origin", localFrontendOrigin);

  } else if (allowedOrigins.count(origin)) {

    res.set_header("Access-Control-Allow-Origin", origin);
  }

  res.set_header("Access-Control-Allow-Methods", allowedMethods);

  res.set_header("Access-Control-Allow-Headers", allowedHeaders);

  res.set_header("Access-Control-Max-Age", "86400");

  res.set_header("Vary", "Origin");
}

} // namespace

// ==========================================
// SessionKeyStore Implementation
// ==========================================

SessionKeyStore &SessionKeyStore::instance() {

  static SessionKeyStore store;

  return store;
}

void SessionKeyStore::storeKey(const std::string &token, SecureKey &&key) {

  std::lock_guard<std::mutex> lock(m_mutex);

  m_keyStore[token] = std::make_shared<SecureKey>(std::move(key));
}

std::shared_ptr<SecureKey> SessionKeyStore::getKey(const std::string &token) {

  std::lock_guard<std::mutex> lock(m_mutex);

  auto it = m_keyStore.find(token);

  if (it == m_keyStore.end())
    return nullptr;

  return it->second;
}

void SessionKeyStore::removeKey(const std::string &token) {

  std::lock_guard<std::mutex> lock(m_mutex);

  m_keyStore.erase(token);
}

// ==========================================
// CORS Middleware Implementation
// ==========================================

void CORSMiddleware::before_handle(crow::request &req, crow::response &res,
                                   context & /*ctx*/
) {

  if (req.method == crow::HTTPMethod::Options) {

    addCorsHeaders(req, res);

    res.code = 204;
    res.body.clear();

    res.end();
  }
}

void CORSMiddleware::after_handle(crow::request &req, crow::response &res,
                                  context & /*ctx*/
) {

  addCorsHeaders(req, res);

  if (req.method == crow::HTTPMethod::Options) {

    res.code = 204;
    res.body.clear();
  }
}

// ==========================================
// Authentication Middleware Implementation
// ==========================================

std::optional<UserSessionContext>
authenticateRequest(const crow::request &req, std::shared_ptr<Auth> auth) {

  // Check whether Auth is available.
  if (!auth)
    return std::nullopt;

  // Read Authorization header.
  const std::string authHeader = req.get_header_value("Authorization");

  // Check Bearer token format.
  if (authHeader.rfind("Bearer ", 0) != 0)
    return std::nullopt;

  // Extract token.
  const std::string token = authHeader.substr(7);

  if (token.empty())
    return std::nullopt;

  // Validate token using Auth class.
  auto session = auth->validateToken(token);

  if (!session.has_value())
    return std::nullopt;

  // Create authenticated user context.
  UserSessionContext userContext;

  userContext.user_id = session->user_id;

  userContext.email = session->email;

  // Retrieve decrypted vault key from session storage.
  userContext.vault_key = SessionKeyStore::instance().getKey(token);

  return userContext;
}
