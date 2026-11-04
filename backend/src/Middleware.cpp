#include "Middleware.h"
#include <iostream>

// All internal helper constants and functions are placed in an unnamed namespace
// to give them internal linkage.
namespace {
    // Development origin (used when FRONTEND_ORIGIN is not set)
    const char *const localFrontendOrigin = "http://localhost:5174";
    const char *const allowedMethods = "GET, POST, PUT, DELETE, OPTIONS";
    const char *const allowedHeaders = "Content-Type, Authorization";

    // Trim whitespace from both ends of a string.
    std::string trim(const std::string &value) {
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return {};
        const auto last = value.find_last_not_of(" \t\r\n");
        return value.substr(first, last - first + 1);
    }

    // Build the set of allowed origins. Starts with the local dev origin and
    // adds any comma‑separated values from the FRONTEND_ORIGIN environment
    // variable.
    std::unordered_set<std::string> getAllowedOrigins() {
        std::unordered_set<std::string> origins{localFrontendOrigin};
        const char *envOrigins = std::getenv("FRONTEND_ORIGIN");
        if (!envOrigins || *envOrigins == '\0') return origins;
        std::stringstream ss(envOrigins);
        std::string origin;
        while (std::getline(ss, origin, ',')) {
            origin = trim(origin);
            if (!origin.empty()) origins.insert(origin);
        }
        return origins;
    }

    // Helper that injects the required CORS response headers.
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

// ---------------------------------------------------------------------------
// CORSMiddleware implementation – the methods are defined exactly as declared
// in Middleware.h.
// ---------------------------------------------------------------------------
void CORSMiddleware::before_handle(crow::request &req, crow::response &res,
                                  context & /*ctx*/) {
    // OPTIONS requests are handled completely here, before any route is
    // matched, ensuring the client receives a 204 with the proper CORS headers.
    if (req.method == crow::HTTPMethod::Options) {
        addCorsHeaders(req, res);
        res.code = 204;            // No Content
        res.body.clear();
        res.end();                 // Short‑circuit the middleware chain.
    }
}

void CORSMiddleware::after_handle(crow::request &req, crow::response &res,
                                 context & /*ctx*/) {
    // For all non‑OPTIONS responses we still need the CORS headers.
    addCorsHeaders(req, res);
    // If the request *was* OPTIONS, the before_handle already set the status
    // to 204, but we make sure the body stays empty.
    if (req.method == crow::HTTPMethod::Options) {
        res.code = 204;
        res.body.clear();
    }
}
