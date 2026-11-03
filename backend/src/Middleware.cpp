#include "Middleware.h"
#include <iostream>

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
        return std::nullopt;
    }

    UserSessionContext ctx;
    ctx.user_id = sessionOpt->user_id;
    ctx.email = sessionOpt->email;
    ctx.vault_key = SessionKeyStore::instance().getKey(token);

    return ctx;
}

