#include "Middleware.h"
#include <cstdlib>
#include <sstream>
#include <unordered_set>

static const char* const defaultOrigins[] = {
    "http://localhost:5174",
    "http://localhost:5173"
};
static const char* const allowedMethods = "GET, POST, PUT, DELETE, OPTIONS";
static const char* const allowedHeaders = "Content-Type, Authorization, X-Requested-With, Accept, Origin";

static std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

static std::unordered_set<std::string> getAllowedOrigins() {
    std::unordered_set<std::string> origins;
    for (const auto* orig : defaultOrigins) {
        origins.insert(orig);
    }

    const char* envOrigins = std::getenv("FRONTEND_ORIGIN");
    if (!envOrigins || *envOrigins == '\0') {
        return origins;
    }

    std::stringstream configuredOrigins(envOrigins);
    std::string origin;
    while (std::getline(configuredOrigins, origin, ',')) {
        origin = trim(origin);
        if (!origin.empty()) {
            origins.insert(origin);
        }
    }
    return origins;
}

void CORSMiddleware::addCorsHeaders(const crow::request& req, crow::response& res) {
    const std::string origin = req.get_header_value("Origin");
    const auto allowedOrigins = getAllowedOrigins();

    if (origin.empty()) {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:5174");
    } else if (allowedOrigins.count(origin) != 0) {
        res.set_header("Access-Control-Allow-Origin", origin);
    }

    res.set_header("Access-Control-Allow-Methods", allowedMethods);
    res.set_header("Access-Control-Allow-Headers", allowedHeaders);
    res.set_header("Access-Control-Max-Age", "86400");
    res.set_header("Vary", "Origin");
}

// File-scope helper declared and defined before any usage
static void addCorsHeaders(const crow::request& req, crow::response& res) {
    CORSMiddleware::addCorsHeaders(req, res);
}

void CORSMiddleware::before_handle(crow::request& req, crow::response& res,
                                   context& /*ctx*/) {
    // Intercept preflight OPTIONS before route matching and authentication
    if (req.method == crow::HTTPMethod::Options) {
        addCorsHeaders(req, res);
        res.code = 204; // No Content
        res.body.clear();
        res.end();
    }
}

void CORSMiddleware::after_handle(crow::request& req, crow::response& res,
                                  context& /*ctx*/) {
    if (req.method == crow::HTTPMethod::Options) {
        return;
    }
    // Add CORS headers to all normal and error responses
    addCorsHeaders(req, res);
}

SessionKeyStore& SessionKeyStore::instance() {
    static SessionKeyStore s_instance;
    return s_instance;
}

void SessionKeyStore::storeKey(const std::string& token, SecureKey&& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_keyStore[token] = std::make_shared<SecureKey>(std::move(key));
}

std::shared_ptr<SecureKey> SessionKeyStore::getKey(const std::string& token) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_keyStore.find(token);
    if (it != m_keyStore.end()) {
        return it->second;
    }
    return nullptr;
}

void SessionKeyStore::removeKey(const std::string& token) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_keyStore.erase(token);
}

std::optional<UserSessionContext> authenticateRequest(
    const crow::request& req,
    std::shared_ptr<Auth> auth
) {
    if (!auth) {
        return std::nullopt;
    }

    std::string authHeader = req.get_header_value("Authorization");
    if (authHeader.empty()) {
        return std::nullopt;
    }

    // Expected format: "Bearer <token>"
    std::string prefix = "Bearer ";
    if (authHeader.rfind(prefix, 0) != 0) {
        return std::nullopt;
    }

    std::string token = authHeader.substr(prefix.length());
    auto sessionOpt = auth->validateToken(token);
    if (!sessionOpt.has_value()) {
        // Purge any stale key for this token
        SessionKeyStore::instance().removeKey(token);
        return std::nullopt;
    }

    auto vaultKey = SessionKeyStore::instance().getKey(token);
    if (!vaultKey || !vaultKey->isValid()) {
        return std::nullopt;
    }

    UserSessionContext ctx;
    ctx.user_id = sessionOpt->user_id;
    ctx.email = sessionOpt->email;
    ctx.vault_key = vaultKey;

    return ctx;
}
