#include "Auth.h"
#include "Database.h"
#include "Encryption.h"
#include "Middleware.h"
#include "Vault.h"
#include "crow.h"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main() {
  std::cout << "========================================" << std::endl;
  std::cout << "   BLOCKVAULT C++ Backend Server Starting" << std::endl;
  std::cout << "========================================" << std::endl;

  // 0. Ensure cryptographic subsystem initializes safely (Fail-Closed)
  if (!Encryption::isInitialized()) {
    std::cerr << "[Fatal] libsodium failed to initialize. Aborting startup." << std::endl;
    return 1;
  }

  // 1. Read DB_PATH from environment (default: database/blockvault.db)
  std::string dbPath = "database/blockvault.db";
  const char *envDbPath = std::getenv("DB_PATH");
  if (envDbPath && std::string(envDbPath).length() > 0) {
    dbPath = envDbPath;
  }

  // Ensure the parent directory for the database file exists
  std::filesystem::path dbFilePath(dbPath);
  if (dbFilePath.has_parent_path()) {
    std::filesystem::create_directories(dbFilePath.parent_path());
  }

  // 2. Initialize Database
  auto db = std::make_shared<Database>(dbPath);
  if (!db->init()) {
    std::cerr << "[Fatal] Failed to initialize SQLite database at: " << dbPath << std::endl;
    return 1;
  }
  std::cout << "[DB] Connected to SQLite database at: " << dbPath << std::endl;

  // 3. Initialize Services
  auto auth = std::make_shared<Auth>(db);
  auto vault = std::make_shared<Vault>(db);

  // 4. Configure Crow App with CORS Middleware
  crow::App<CORSMiddleware> app;

  // ==========================================
  // Public Health Check Endpoint
  // ==========================================
  CROW_ROUTE(app, "/api/health").methods(crow::HTTPMethod::Get)([]() {
    json res = {{"status", "online"},
                {"service", "BlockVault C++ API"},
                {"version", "1.0.0"}};
    return crow::response(200, res.dump());
  });

  // ==========================================
  // Authentication Endpoints
  // ==========================================

  // POST /api/auth/register
  CROW_ROUTE(app, "/api/auth/register")
      .methods(crow::HTTPMethod::Post)([&auth](const crow::request &req) {
        json body;
        try {
          body = json::parse(req.body);
        } catch (...) {
          return crow::response(
              400, json({{"error", "Invalid JSON payload."}}).dump());
        }

        std::string name = body.value("name", "");
        std::string email = body.value("email", "");
        std::string masterPassword = body.value("master_password", "");

        AuthResult result = auth->registerUser(name, email, masterPassword);
        if (!result.success) {
          return crow::response(400, json({{"error", result.message}}).dump());
        }

        // Derive vault key from master password and per-user unique random vault salt
        SecureKey vaultKey = Encryption::deriveVaultKey(masterPassword, result.vault_salt);
        if (!vaultKey.isValid()) {
          return crow::response(500, json({{"error", "Failed to derive vault encryption key."}}).dump());
        }
        SessionKeyStore::instance().storeKey(result.token, std::move(vaultKey));

        json resp = {{"success", true},
                     {"message", result.message},
                     {"token", result.token},
                     {"user",
                      {{"id", result.user_id},
                       {"name", result.name},
                       {"email", result.email}}}};
        return crow::response(201, resp.dump());
      });

  // POST /api/auth/login
  CROW_ROUTE(app, "/api/auth/login")
      .methods(crow::HTTPMethod::Post)([&auth](const crow::request &req) {
        json body;
        try {
          body = json::parse(req.body);
        } catch (...) {
          return crow::response(
              400, json({{"error", "Invalid JSON payload."}}).dump());
        }

        std::string email = body.value("email", "");
        std::string masterPassword = body.value("master_password", "");

        AuthResult result = auth->loginUser(email, masterPassword);
        if (!result.success) {
          return crow::response(401, json({{"error", result.message}}).dump());
        }

        // Derive vault key using the user's stored vault salt
        SecureKey vaultKey = Encryption::deriveVaultKey(masterPassword, result.vault_salt);
        if (!vaultKey.isValid()) {
          return crow::response(500, json({{"error", "Failed to derive vault encryption key."}}).dump());
        }
        SessionKeyStore::instance().storeKey(result.token, std::move(vaultKey));

        json resp = {{"success", true},
                     {"message", result.message},
                     {"token", result.token},
                     {"user",
                      {{"id", result.user_id},
                       {"name", result.name},
                       {"email", result.email}}}};
        return crow::response(200, resp.dump());
      });

  // POST /api/auth/logout
  CROW_ROUTE(app, "/api/auth/logout")
      .methods(crow::HTTPMethod::Post)([&auth](const crow::request &req) {
        std::string authHeader = req.get_header_value("Authorization");
        if (authHeader.rfind("Bearer ", 0) == 0) {
          std::string token = authHeader.substr(7);
          auth->logoutUser(token);
          SessionKeyStore::instance().removeKey(token);
        }
        return crow::response(
            200,
            json({{"success", true}, {"message", "Logged out successfully."}})
                .dump());
      });

  // GET /api/auth/me
  CROW_ROUTE(app, "/api/auth/me")
      .methods(crow::HTTPMethod::Get)([&auth, &db](const crow::request &req) {
        auto sessionOpt = authenticateRequest(req, auth);
        if (!sessionOpt.has_value()) {
          return crow::response(
              401,
              json({{"error", "Unauthorized or expired session."}}).dump());
        }

        auto userOpt = db->getUserById(sessionOpt->user_id);
        if (!userOpt.has_value()) {
          return crow::response(404,
                                json({{"error", "User not found."}}).dump());
        }

        json res = {{"id", userOpt->id},
                    {"name", userOpt->name},
                    {"email", userOpt->email},
                    {"created_at", userOpt->created_at}};
        return crow::response(200, res.dump());
      });

  // ==========================================
  // Vault Credential Endpoints (Protected)
  // ==========================================

  // POST /api/vault
  CROW_ROUTE(app, "/api/vault")
      .methods(
          crow::HTTPMethod::Post)([&auth, &vault](const crow::request &req) {
        auto sessionOpt = authenticateRequest(req, auth);
        if (!sessionOpt.has_value() || !sessionOpt->vault_key) {
          return crow::response(
              401,
              json({{"error", "Unauthorized or vault is locked."}}).dump());
        }

        json body;
        try {
          body = json::parse(req.body);
        } catch (...) {
          return crow::response(
              400, json({{"error", "Invalid JSON payload."}}).dump());
        }

        CredentialInputDTO input;
        input.website = body.value("website", "");
        input.website_url = body.value("website_url", "");
        input.username = body.value("username", "");
        input.password = body.value("password", "");
        input.category = body.value("category", "General");
        input.notes = body.value("notes", "");
        input.is_favorite = body.value("is_favorite", false);

        VaultResult res = vault->addCredential(sessionOpt->user_id, input,
                                               *sessionOpt->vault_key);
        if (!res.success) {
          return crow::response(400, json({{"error", res.message}}).dump());
        }

        return crow::response(201, json({{"success", true},
                                         {"message", res.message},
                                         {"credential_id", res.credential_id}})
                                        .dump());
      });

  // GET /api/vault
  CROW_ROUTE(app, "/api/vault")
      .methods(
          crow::HTTPMethod::Get)([&auth, &vault](const crow::request &req) {
        auto sessionOpt = authenticateRequest(req, auth);
        if (!sessionOpt.has_value() || !sessionOpt->vault_key) {
          return crow::response(
              401,
              json({{"error", "Unauthorized or vault is locked."}}).dump());
        }

        // Check query parameters: category or search
        auto categoryParam = req.url_params.get("category");
        auto searchParam = req.url_params.get("search");

        std::vector<CredentialDTO> credentials;
        if (searchParam) {
          credentials = vault->searchByWebsite(sessionOpt->user_id, searchParam,
                                               *sessionOpt->vault_key);
        } else if (categoryParam) {
          credentials = vault->filterByCategory(
              sessionOpt->user_id, categoryParam, *sessionOpt->vault_key);
        } else {
          credentials = vault->getAllCredentials(sessionOpt->user_id,
                                                 *sessionOpt->vault_key);
        }

        json items = json::array();
        for (const auto &c : credentials) {
          items.push_back({{"id", c.id},
                           {"website", c.website},
                           {"website_url", c.website_url},
                           {"username", c.username},
                           {"password", c.password},
                           {"category", c.category},
                           {"notes", c.notes},
                           {"is_favorite", c.is_favorite},
                           {"created_at", c.created_at},
                           {"updated_at", c.updated_at}});
        }

        return crow::response(200, json({{"credentials", items}}).dump());
      });

  // GET /api/vault/<int>
  CROW_ROUTE(app, "/api/vault/<int>")
      .methods(crow::HTTPMethod::Get)([&auth, &vault](const crow::request &req,
                                                      int credentialId) {
        auto sessionOpt = authenticateRequest(req, auth);
        if (!sessionOpt.has_value() || !sessionOpt->vault_key) {
          return crow::response(
              401,
              json({{"error", "Unauthorized or vault is locked."}}).dump());
        }

        auto credOpt = vault->getCredentialById(
            credentialId, sessionOpt->user_id, *sessionOpt->vault_key);
        if (!credOpt.has_value()) {
          return crow::response(
              404,
              json({{"error", "Credential not found or permission denied."}})
                  .dump());
        }

        const auto &c = credOpt.value();
        json res = {{"id", c.id},
                    {"website", c.website},
                    {"website_url", c.website_url},
                    {"username", c.username},
                    {"password", c.password},
                    {"category", c.category},
                    {"notes", c.notes},
                    {"is_favorite", c.is_favorite},
                    {"created_at", c.created_at},
                    {"updated_at", c.updated_at}};
        return crow::response(200, res.dump());
      });

  // PUT /api/vault/<int>
  CROW_ROUTE(app, "/api/vault/<int>")
      .methods(crow::HTTPMethod::Put)([&auth, &vault](const crow::request &req,
                                                      int credentialId) {
        auto sessionOpt = authenticateRequest(req, auth);
        if (!sessionOpt.has_value() || !sessionOpt->vault_key) {
          return crow::response(
              401,
              json({{"error", "Unauthorized or vault is locked."}}).dump());
        }

        json body;
        try {
          body = json::parse(req.body);
        } catch (...) {
          return crow::response(
              400, json({{"error", "Invalid JSON payload."}}).dump());
        }

        CredentialInputDTO input;
        input.website = body.value("website", "");
        input.website_url = body.value("website_url", "");
        input.username = body.value("username", "");
        input.password = body.value("password", "");
        input.category = body.value("category", "General");
        input.notes = body.value("notes", "");
        input.is_favorite = body.value("is_favorite", false);

        VaultResult res = vault->updateCredential(
            credentialId, sessionOpt->user_id, input, *sessionOpt->vault_key);
        if (!res.success) {
          int code = (res.message.find("not found") != std::string::npos ||
                      res.message.find("permission denied") != std::string::npos) ? 404 : 400;
          return crow::response(code, json({{"error", res.message}}).dump());
        }

        return crow::response(200, json({{"success", true},
                                         {"message", res.message},
                                         {"credential_id", credentialId}})
                                        .dump());
      });

  // DELETE /api/vault/<int>
  CROW_ROUTE(app, "/api/vault/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&auth, &vault](const crow::request &req, int credentialId) {
            auto sessionOpt = authenticateRequest(req, auth);
            if (!sessionOpt.has_value()) {
              return crow::response(
                  401, json({{"error", "Unauthorized session."}}).dump());
            }

            VaultResult res =
                vault->deleteCredential(credentialId, sessionOpt->user_id);
            if (!res.success) {
              return crow::response(404, json({{"error", res.message}}).dump());
            }

            return crow::response(
                200,
                json({{"success", true}, {"message", res.message}}).dump());
          });

  // POST /api/vault/<int>/favorite
  CROW_ROUTE(app, "/api/vault/<int>/favorite")
      .methods(crow::HTTPMethod::Post)([&auth, &vault](const crow::request &req,
                                                       int credentialId) {
        auto sessionOpt = authenticateRequest(req, auth);
        if (!sessionOpt.has_value()) {
          return crow::response(
              401, json({{"error", "Unauthorized session."}}).dump());
        }

        json body;
        bool isFav = true;
        try {
          body = json::parse(req.body);
          isFav = body.value("is_favorite", true);
        } catch (...) {
        }

        VaultResult res =
            vault->setFavorite(credentialId, sessionOpt->user_id, isFav);
        if (!res.success) {
          return crow::response(404, json({{"error", res.message}}).dump());
        }

        return crow::response(
            200, json({{"success", true}, {"message", res.message}}).dump());
      });

  // Read port from environment variable PORT (if set), default to 10000 (Render default)
  uint16_t port = 10000;
  const char *envPort = std::getenv("PORT");

  std::cout << "[Server] Environment PORT value: "
            << (envPort ? envPort : "(not set, using fallback 10000)")
            << std::endl;

  if (envPort && std::string(envPort).length() > 0) {
    try {
      int parsed = std::stoi(envPort);
      if (parsed > 0 && parsed <= 65535) {
        port = static_cast<uint16_t>(parsed);
      } else {
        std::cerr << "[Warning] Invalid PORT value: " << envPort
                  << ". Using fallback: " << port << std::endl;
      }
    } catch (const std::exception &e) {
      std::cerr << "[Warning] Failed to parse PORT: " << envPort
                << " (" << e.what() << "). Using fallback: " << port << std::endl;
    }
  }

  // Explicitly bind to 0.0.0.0 across all network interfaces
  // Do not allow HOST to override with 127.0.0.1 in production
  std::string bindAddr = "0.0.0.0";
  const char *envHost = std::getenv("HOST");
  if (envHost && std::string(envHost).length() > 0) {
    std::string customHost = envHost;
    // Disallow 127.0.0.1 or localhost overrides in production
    if (customHost != "127.0.0.1" && customHost != "localhost") {
      bindAddr = customHost;
    } else {
      std::cout << "[Server] Ignoring loopback HOST override (" << customHost
                << ") - enforcing 0.0.0.0 for container/Render routing."
                << std::endl;
    }
  }

  std::cout << "[Server] Final bind address: " << bindAddr << std::endl;
  std::cout << "[Server] Final listening port: " << port << std::endl;
  std::cout << "[Server] Listening on http://" << bindAddr << ":" << port
            << std::endl;
  app.bindaddr(bindAddr).port(port).multithreaded().run();

  return 0;
}
